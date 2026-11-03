//go:build windows

package winrunner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
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
	code, err := runAsScheduledTask(ctx, user, domain, password, cwd, command)
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
	if err := releaseBackgroundJob(job); err != nil {
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

func runAsScheduledTask(ctx context.Context, user, domain, password, cwd string, command []string) (int, error) {
	directory := os.Getenv(TaskDirectoryEnvironment)
	if directory == "" {
		return 0, errors.New("Windows task transport directory is missing")
	}
	transport := TaskTransport{Directory: directory}
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
	action := taskAction{Command: helper, Arguments: syswindows.ComposeCommandLine([]string{
		"__sandbox-local-helper", "__windows-task-broker", directory,
	})}
	raw, err = xml.Marshal(taskDefinition{Version: "1.2", Namespace: "http://schemas.microsoft.com/windows/2004/02/mit/task",
		Settings: taskSettings{ExecutionTimeLimit: "PT0S", AllowHardTerminate: true}, Actions: taskActions{Exec: action}})
	if err != nil {
		return 0, err
	}
	xmlPath := filepath.Join(directory, "task.xml")
	if err := os.WriteFile(xmlPath, taskXMLBytes(raw), 0600); err != nil {
		return 0, err
	}
	runAs := user
	if domain != "" && domain != "." {
		runAs = domain + `\` + user
	} else if computer := os.Getenv("COMPUTERNAME"); computer != "" {
		runAs = computer + `\` + user
	}
	if out, err := exec.CommandContext(ctx, "schtasks.exe", "/Create", "/TN", transport.name(), "/XML", xmlPath, "/RU", runAs, "/RP", password, "/F").CombinedOutput(); err != nil {
		return 0, fmt.Errorf("create scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", transport.name()).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("start scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	code, waitErr := waitForTaskExit(ctx, filepath.Join(directory, "exit.txt"), transport.name())
	outputErr := replayFile(filepath.Join(directory, "stdout.bin"), os.Stdout)
	errorOutputErr := replayFile(filepath.Join(directory, "stderr.bin"), os.Stderr)
	return code, errors.Join(waitErr, outputErr, errorOutputErr)
}

func waitForTaskExit(ctx context.Context, exitPath string, taskName string) (int, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	statusAt := time.Now().Add(time.Second)
	for {
		if raw, err := os.ReadFile(exitPath); err == nil {
			code, ready, parseErr := parseTaskExit(raw)
			if parseErr != nil {
				return 0, parseErr
			}
			if ready {
				if failure, err := os.ReadFile(filepath.Join(filepath.Dir(exitPath), "failure.txt")); err == nil {
					return 0, fmt.Errorf("scheduled-task bootstrap failed: %s", strings.TrimSpace(string(failure)))
				} else if !errors.Is(err, os.ErrNotExist) {
					return 0, fmt.Errorf("read scheduled-task failure: %w", err)
				}
				return code, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, fmt.Errorf("read scheduled-task completion: %w", err)
		}
		if time.Now().After(statusAt) {
			statusAt = time.Now().Add(time.Second)
			completed, result, err := scheduledTaskCompleted(ctx, taskName)
			if err != nil {
				return 0, err
			}
			if completed {
				// A completed task has already closed its report. Check again to
				// avoid racing the write between the first read and the query.
				if raw, err := os.ReadFile(exitPath); errors.Is(err, os.ErrNotExist) || (err == nil && strings.TrimSpace(string(raw)) == "") {
					return 0, fmt.Errorf("scheduled task ended without a completion report (result %#x)", result)
				}
			}
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func parseTaskExit(raw []byte) (int, bool, error) {
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return 0, false, nil
	}
	code, err := strconv.Atoi(value)
	if err != nil {
		return 0, false, fmt.Errorf("parse scheduled task exit code: %w", err)
	}
	return code, true, nil
}

func deleteTask(ctx context.Context, taskName string) error {
	cmd := exec.CommandContext(ctx, "schtasks.exe", "/Delete", "/TN", taskName, "/F")
	if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "cannot find") {
		return fmt.Errorf("delete scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func replayFile(path string, out *os.File) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	_, err = out.Write(data)
	return err
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

func taskXMLBytes(raw []byte) []byte {
	units := utf16.Encode([]rune(`<?xml version="1.0" encoding="UTF-16"?>` + string(raw)))
	encoded := make([]byte, 2+2*len(units))
	encoded[0], encoded[1] = 0xff, 0xfe
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2+i*2:], unit)
	}
	return encoded
}
