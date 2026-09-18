//go:build windows

package winrunner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	var process syswindows.ProcessInformation
	if err := syswindows.CreateProcessAsUser(
		restricted, nil, &cmdline[0], nil, nil, true, 0, nil, cwdUTF16, &startup, &process,
	); err != nil {
		return fmt.Errorf("start command with write-restricted Windows token: %w", err)
	}
	defer syswindows.CloseHandle(process.Thread)
	defer syswindows.CloseHandle(process.Process)
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

func runAsScheduledTask(ctx context.Context, user string, domain string, password string, cwd string, command []string) (int, error) {
	id, err := randomID()
	if err != nil {
		return 0, err
	}
	taskName := `\sandbox-local-` + id
	workDir, err := os.MkdirTemp(cwd, ".sandbox-local-win-"+id+"-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(workDir)

	stdoutPath := filepath.Join(workDir, "stdout.txt")
	stderrPath := filepath.Join(workDir, "stderr.txt")
	exitPath := filepath.Join(workDir, "exit.txt")
	scriptPath := filepath.Join(workDir, "run.ps1")
	if err := writeTaskScript(scriptPath, cwd, command, stdoutPath, stderrPath, exitPath); err != nil {
		return 0, err
	}
	defer deleteTask(context.WithoutCancel(ctx), taskName)

	runAs := user
	if domain != "" && domain != "." {
		runAs = domain + `\` + user
	} else if computer := os.Getenv("COMPUTERNAME"); computer != "" {
		runAs = computer + `\` + user
	}
	start := time.Now().Add(5 * time.Minute).Format("15:04")
	createArgs := []string{
		"/Create",
		"/TN", taskName,
		"/SC", "ONCE",
		"/ST", start,
		"/TR", syswindows.ComposeCommandLine([]string{
			"powershell.exe",
			"-NoProfile",
			"-ExecutionPolicy", "Bypass",
			"-File", scriptPath,
		}),
		"/RU", runAs,
		"/RP", password,
		"/F",
	}
	if out, err := exec.CommandContext(ctx, "schtasks.exe", createArgs...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("create scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.CommandContext(ctx, "schtasks.exe", "/Run", "/TN", taskName).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("run scheduled task: %w: %s", err, strings.TrimSpace(string(out)))
	}

	code, err := waitForTaskExit(ctx, exitPath, taskName)
	time.Sleep(1 * time.Second)
	if replayErr := replayFile(stdoutPath, os.Stdout); replayErr != nil && err == nil {
		err = replayErr
	}
	if replayErr := replayFile(stderrPath, os.Stderr); replayErr != nil && err == nil {
		err = replayErr
	}
	if err != nil {
		return 0, err
	}
	return code, nil
}

func writeTaskScript(path string, cwd string, command []string, stdoutPath string, stderrPath string, exitPath string) error {
	requestEnv, err := requestEnvironment()
	if err != nil {
		return err
	}
	capabilitySID := strings.TrimSpace(os.Getenv(envWindowsWriteCapabilitySID))
	if capabilitySID == "" {
		return errors.New("Windows write capability SID is missing")
	}
	requestEnv[envWindowsWriteCapabilitySID] = capabilitySID
	helper, err := os.Executable()
	if err != nil {
		return err
	}
	command = append([]string{helper, "__sandbox-local-helper", "__windows-restricted-runner", "--"}, command...)
	var script strings.Builder
	script.WriteString("$ErrorActionPreference = 'Continue'\r\n")
	script.WriteString("Set-Location -LiteralPath ")
	script.WriteString(powerShellString(cwd))
	script.WriteString("\r\n")
	for key, value := range requestEnv {
		if !validEnvKey(key) {
			continue
		}
		script.WriteString("$env:")
		script.WriteString(key)
		script.WriteString(" = ")
		script.WriteString(powerShellString(value))
		script.WriteString("\r\n")
	}
	script.WriteString("$out = ")
	script.WriteString(powerShellString(stdoutPath))
	script.WriteString("\r\n")
	script.WriteString("$err = ")
	script.WriteString(powerShellString(stderrPath))
	script.WriteString("\r\n")
	script.WriteString("$code = ")
	script.WriteString(powerShellString(exitPath))
	script.WriteString("\r\n")
	script.WriteString("$proc = Start-Process -FilePath ")
	script.WriteString(powerShellString(command[0]))
	script.WriteString(" -ArgumentList @(")
	for i, arg := range command[1:] {
		if i > 0 {
			script.WriteString(", ")
		}
		script.WriteString(powerShellString(arg))
	}
	script.WriteString(") -WorkingDirectory ")
	script.WriteString(powerShellString(cwd))
	script.WriteString(" -RedirectStandardOutput $out -RedirectStandardError $err -Wait -PassThru\r\n")
	script.WriteString("$exitCode = $proc.ExitCode\r\n")
	script.WriteString("Set-Content -LiteralPath $code -Value $exitCode -Encoding ascii\r\n")
	return os.WriteFile(path, []byte(script.String()), 0o600)
}

func waitForTaskExit(ctx context.Context, exitPath string, taskName string) (int, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if raw, err := os.ReadFile(exitPath); err == nil {
			code, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if parseErr != nil {
				return 0, fmt.Errorf("parse scheduled task exit code: %w", parseErr)
			}
			return code, nil
		}
		select {
		case <-ctx.Done():
			_ = deleteTask(context.WithoutCancel(ctx), taskName)
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
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
	data = decodeTaskOutput(data)
	if len(data) == 0 {
		return nil
	}
	_, err = out.Write(data)
	return err
}

func decodeTaskOutput(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	if data[0] == 0xff && data[1] == 0xfe {
		return utf16BytesToUTF8(data[2:], binary.LittleEndian)
	}
	if data[0] == 0xfe && data[1] == 0xff {
		return utf16BytesToUTF8(data[2:], binary.BigEndian)
	}
	if looksUTF16LE(data) {
		return utf16BytesToUTF8(data, binary.LittleEndian)
	}
	return data
}

func looksUTF16LE(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	zeros := 0
	pairs := len(data) / 2
	for i := 1; i < len(data); i += 2 {
		if data[i] == 0 {
			zeros++
		}
	}
	return zeros*2 >= pairs
}

func utf16BytesToUTF8(data []byte, order binary.ByteOrder) []byte {
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	words := make([]uint16, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		words = append(words, order.Uint16(data[i:i+2]))
	}
	return []byte(string(utf16.Decode(words)))
}

func randomID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func powerShellString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func validEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if !(r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
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
