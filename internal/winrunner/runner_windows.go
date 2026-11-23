//go:build windows

package winrunner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

const (
	envWindowsUser               = "SANDBOX_LOCAL_WINDOWS_USER"
	envWindowsPassword           = "SANDBOX_LOCAL_WINDOWS_PASSWORD"
	envWindowsDomain             = "SANDBOX_LOCAL_WINDOWS_DOMAIN"
	envWindowsRequest            = "SANDBOX_LOCAL_WINDOWS_REQUEST_ENV"
	envWindowsWriteCapabilitySID = "SANDBOX_LOCAL_WINDOWS_WRITE_CAPABILITY_SID"

	writeRestricted = 0x8
)

var procCreateRestrictedToken = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
var (
	procGetProcessWindowStation  = syswindows.NewLazySystemDLL("user32.dll").NewProc("GetProcessWindowStation")
	procGetThreadDesktop         = syswindows.NewLazySystemDLL("user32.dll").NewProc("GetThreadDesktop")
	procGetUserObjectInformation = syswindows.NewLazySystemDLL("user32.dll").NewProc("GetUserObjectInformationW")
)

type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.Code)
}

func Run(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return errors.New("command is required")
	}
	user := os.Getenv(envWindowsUser)
	password := os.Getenv(envWindowsPassword)
	domain := os.Getenv(envWindowsDomain)
	if domain == "" {
		domain = "."
	}
	if user == "" || password == "" {
		return errors.New("Windows runner credentials are missing")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	ctx, stop := taskContext(ctx, os.Getenv(TaskDirectoryEnvironment))
	defer stop()
	code, err := runProfileFree(ctx, user, domain, password, cwd, command)
	if err != nil {
		return err
	}
	if code != 0 {
		return ExitCodeError{Code: code}
	}
	return nil
}

// RunRestricted launches the actual command with a write-restricted token.
// Windows then requires write access to be granted both to the sandbox account
// and to the per-run capability SID, making WriteAllow an actual allow-list.
func RunRestricted(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return errors.New("command is required")
	}
	capabilitySID := strings.TrimSpace(os.Getenv(envWindowsWriteCapabilitySID))
	if capabilitySID == "" {
		return errors.New("Windows write capability SID is missing")
	}
	sid, err := syswindows.StringToSid(capabilitySID)
	if err != nil {
		return fmt.Errorf("parse Windows write capability SID: %w", err)
	}
	currentProcess, err := syswindows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("get current Windows process: %w", err)
	}
	var token syswindows.Token
	if err := syswindows.OpenProcessToken(currentProcess, syswindows.TOKEN_QUERY|syswindows.TOKEN_DUPLICATE|syswindows.TOKEN_ASSIGN_PRIMARY, &token); err != nil {
		return fmt.Errorf("open current Windows process token: %w", err)
	}
	defer token.Close()
	restricted, err := createWriteRestrictedToken(token, sid)
	if err != nil {
		return err
	}
	defer restricted.Close()
	desktopName, err := currentDesktopName()
	if err != nil {
		return err
	}

	cmdline, err := syswindows.UTF16FromString(syswindows.ComposeCommandLine(command))
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	cwdUTF16, err := syswindows.UTF16PtrFromString(cwd)
	if err != nil {
		return err
	}
	desktop, err := syswindows.UTF16PtrFromString(desktopName)
	if err != nil {
		return err
	}
	startup := syswindows.StartupInfo{Cb: uint32(unsafe.Sizeof(syswindows.StartupInfo{})), Flags: syswindows.STARTF_USESTDHANDLES}
	startup.Desktop = desktop
	startup.StdInput = syswindows.Handle(os.Stdin.Fd())
	startup.StdOutput = syswindows.Handle(os.Stdout.Fd())
	startup.StdErr = syswindows.Handle(os.Stderr.Fd())
	job, err := restrictedJob()
	if err != nil {
		return err
	}
	defer syswindows.CloseHandle(job)
	if err := syswindows.SetHandleInformation(startup.StdInput, syswindows.HANDLE_FLAG_INHERIT, syswindows.HANDLE_FLAG_INHERIT); err != nil {
		return err
	}
	var process syswindows.ProcessInformation
	if err := syswindows.CreateProcessAsUser(
		restricted, nil, &cmdline[0], nil, nil, true, syswindows.CREATE_SUSPENDED, nil, cwdUTF16, &startup, &process,
	); err != nil {
		return fmt.Errorf("start command with write-restricted Windows token: %w", err)
	}
	defer syswindows.CloseHandle(process.Thread)
	defer syswindows.CloseHandle(process.Process)
	if err := syswindows.AssignProcessToJobObject(job, process.Process); err != nil {
		return errors.Join(err, syswindows.TerminateProcess(process.Process, 1))
	}
	if _, err := syswindows.ResumeThread(process.Thread); err != nil {
		return err
	}
	wait := make(chan error, 1)
	go func() {
		_, err := syswindows.WaitForSingleObject(process.Process, syswindows.INFINITE)
		wait <- err
	}()
	select {
	case <-ctx.Done():
		_ = syswindows.TerminateProcess(process.Process, 1)
		<-wait
		return ctx.Err()
	case err := <-wait:
		if err != nil {
			return err
		}
	}
	var exitCode uint32
	if err := syswindows.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		return err
	}
	if exitCode != 0 {
		return ExitCodeError{Code: int(exitCode)}
	}
	return nil
}

func currentDesktopName() (string, error) {
	windowStation, _, callErr := procGetProcessWindowStation.Call()
	if windowStation == 0 {
		return "", fmt.Errorf("get current Windows station: %w", callErr)
	}
	desktop, _, callErr := procGetThreadDesktop.Call(uintptr(syswindows.GetCurrentThreadId()))
	if desktop == 0 {
		return "", fmt.Errorf("get current Windows desktop: %w", callErr)
	}
	stationName, err := currentUserObjectName(syswindows.Handle(windowStation))
	if err != nil {
		return "", fmt.Errorf("read current Windows station name: %w", err)
	}
	desktopName, err := currentUserObjectName(syswindows.Handle(desktop))
	if err != nil {
		return "", fmt.Errorf("read current Windows desktop name: %w", err)
	}
	return stationName + `\` + desktopName, nil
}

func currentUserObjectName(handle syswindows.Handle) (string, error) {
	const userObjectName = 2
	var needed uint32
	_, _, _ = procGetUserObjectInformation.Call(uintptr(handle), userObjectName, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed < 2 {
		return "", syswindows.GetLastError()
	}
	buffer := make([]uint16, (needed+1)/2)
	ok, _, callErr := procGetUserObjectInformation.Call(
		uintptr(handle), userObjectName, uintptr(unsafe.Pointer(&buffer[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)),
	)
	if ok == 0 {
		return "", callErr
	}
	return syswindows.UTF16ToString(buffer), nil
}

func createWriteRestrictedToken(base syswindows.Token, capabilitySID *syswindows.SID) (syswindows.Token, error) {
	everyoneSID, err := syswindows.StringToSid("S-1-1-0")
	if err != nil {
		return 0, fmt.Errorf("parse Windows Everyone SID: %w", err)
	}
	user, err := base.GetTokenUser()
	if err != nil {
		return 0, fmt.Errorf("read Windows token user: %w", err)
	}
	groups, err := base.GetTokenGroups()
	if err != nil {
		return 0, fmt.Errorf("read Windows token groups: %w", err)
	}
	var logonSID *syswindows.SID
	for _, group := range groups.AllGroups() {
		if group.Attributes&syswindows.SE_GROUP_LOGON_ID == syswindows.SE_GROUP_LOGON_ID {
			logonSID = group.Sid
			break
		}
	}
	if logonSID == nil {
		return 0, errors.New("Windows logon SID is missing")
	}
	// WRITE_RESTRICTED applies the restricting-SID access check only to write
	// operations. The per-run capability SID is the only filesystem grant in
	// this set. Everyone preserves access to ordinary Windows runtime objects;
	// the capability SID remains the only added grant on filesystem policy paths.
	// Do not add the built-in Users group: it owns broad writable host locations.
	restricting := []syswindows.SIDAndAttributes{{Sid: capabilitySID}, {Sid: user.User.Sid}, {Sid: logonSID}, {Sid: everyoneSID}}
	var restricted syswindows.Token
	ok, _, callErr := procCreateRestrictedToken.Call(
		uintptr(base),
		writeRestricted,
		0, 0,
		0, 0,
		uintptr(len(restricting)), uintptr(unsafe.Pointer(&restricting[0])),
		uintptr(unsafe.Pointer(&restricted)),
	)
	if ok == 0 {
		return 0, fmt.Errorf("create write-restricted Windows token: %w", callErr)
	}
	return restricted, nil
}

func runProfileFree(ctx context.Context, user, domain, password, cwd string, command []string) (int, error) {
	directory := os.Getenv(TaskDirectoryEnvironment)
	if directory == "" {
		return 0, errors.New("Windows task transport directory is missing")
	}
	config := taskConfig{Cwd: cwd, Command: command}
	var err error
	config.Env, err = requestEnvironment()
	if err != nil {
		return 0, err
	}
	if config.Env == nil {
		config.Env = map[string]string{}
	}
	config.Env[envWindowsWriteCapabilitySID] = os.Getenv(envWindowsWriteCapabilitySID)
	raw, err := json.Marshal(config)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(directory, "request.json"), raw, 0600); err != nil {
		return 0, err
	}
	input, err := os.Create(filepath.Join(directory, "stdin.bin"))
	if err != nil {
		return 0, err
	}
	_, copyErr := io.Copy(input, os.Stdin)
	if err := errors.Join(copyErr, input.Close()); err != nil {
		return 0, err
	}
	helper, err := os.Executable()
	if err != nil {
		return 0, err
	}
	stdout := taskOutputCursor{path: filepath.Join(directory, "stdout.bin"), out: os.Stdout}
	stderr := taskOutputCursor{path: filepath.Join(directory, "stderr.bin"), out: os.Stderr}
	var code int
	waitErr := withProfileFreeBroker(user, domain, password, helper, directory, func(broker syswindows.ProcessInformation) (resultErr error) {
		defer syswindows.CloseHandle(broker.Process)
		defer syswindows.CloseHandle(broker.Thread)
		job, err := restrictedJob()
		if err != nil {
			return errors.Join(err, syswindows.TerminateProcess(broker.Process, 1))
		}
		defer syswindows.CloseHandle(job)
		if err := syswindows.AssignProcessToJobObject(job, broker.Process); err != nil {
			return errors.Join(err, syswindows.TerminateProcess(broker.Process, 1))
		}
		// Reap every process before closing its private desktop or reversing
		// host policy. Closing a job alone initiates asynchronous termination.
		defer func() { resultErr = errors.Join(resultErr, terminateAndReapJob(job)) }()
		if _, err := syswindows.ResumeThread(broker.Thread); err != nil {
			return err
		}
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			state, err := syswindows.WaitForSingleObject(broker.Process, 100)
			if err != nil {
				return err
			}
			stdout.drain(1 << 20)
			stderr.drain(1 << 20)
			if state == syswindows.WAIT_OBJECT_0 {
				var brokerExit uint32
				if err := syswindows.GetExitCodeProcess(broker.Process, &brokerExit); err != nil {
					return err
				}
				code, err = readBrokerExit(directory, brokerExit)
				return err
			}
		}
	})
	stdout.drain(0)
	stderr.drain(0)
	return code, errors.Join(waitErr, stdout.err, stderr.err)
}

func readBrokerExit(directory string, brokerExit uint32) (int, error) {
	if failure, err := os.ReadFile(filepath.Join(directory, "failure.txt")); err == nil {
		return 0, fmt.Errorf("Windows broker bootstrap failed: %s", strings.TrimSpace(string(failure)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "exit.txt"))
	if err != nil {
		return 0, fmt.Errorf("Windows broker exited with status %#x without a completion report: %w", brokerExit, err)
	}
	code, ready, err := parseTaskExit(raw)
	if err == nil && !ready {
		return 0, fmt.Errorf("Windows broker exited with status %#x and an empty completion report", brokerExit)
	}
	return code, err
}

func parseTaskExit(raw []byte) (int, bool, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return 0, false, nil
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		return 0, false, fmt.Errorf("parse Windows broker exit code: %w", err)
	}
	return code, true, nil
}

func randomID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func requestEnvironment() (map[string]string, error) {
	raw := os.Getenv(envWindowsRequest)
	if raw == "" || raw == "null" {
		return map[string]string{}, nil
	}
	var env map[string]string
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("decode Windows runner request environment: %w", err)
	}
	for _, key := range []string{envWindowsUser, envWindowsPassword, envWindowsDomain, envWindowsRequest} {
		delete(env, key)
	}
	return env, nil
}
