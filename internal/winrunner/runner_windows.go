//go:build windows

package winrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf16"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

const (
	envWindowsUser     = "SANDBOX_LOCAL_WINDOWS_USER"
	envWindowsPassword = "SANDBOX_LOCAL_WINDOWS_PASSWORD"
	envWindowsDomain   = "SANDBOX_LOCAL_WINDOWS_DOMAIN"
	envWindowsRequest  = "SANDBOX_LOCAL_WINDOWS_REQUEST_ENV"

	createProcessWithTokenLogonFlags = 0x00000001
	logon32LogonInteractive          = 2
	logon32ProviderDefault           = 0
)

var (
	procCreateProcessWithTokenW = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithTokenW")
	procLogonUserW              = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
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
	code, err := runAsUser(ctx, user, domain, password, cwd, command)
	if err != nil {
		return err
	}
	if code != 0 {
		return ExitCodeError{Code: code}
	}
	return nil
}

func runAsUser(ctx context.Context, user string, domain string, password string, cwd string, command []string) (int, error) {
	if err := inheritStandardHandles(); err != nil {
		return 0, err
	}
	job, err := createKillOnCloseJob()
	if err != nil {
		return 0, err
	}
	defer syswindows.CloseHandle(job)

	token, err := logonUser(user, domain, password)
	if err != nil {
		return 0, err
	}
	defer token.Close()

	commandLine, err := syswindows.UTF16FromString(syswindows.ComposeCommandLine(command))
	if err != nil {
		return 0, err
	}
	envBlock, err := environmentBlock(token)
	if err != nil {
		return 0, err
	}
	cwd16, err := syswindows.UTF16PtrFromString(cwd)
	if err != nil {
		return 0, err
	}
	desktop16, err := syswindows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return 0, err
	}
	startup := syswindows.StartupInfo{
		Cb:        uint32(unsafe.Sizeof(syswindows.StartupInfo{})),
		Desktop:   desktop16,
		Flags:     syswindows.STARTF_USESTDHANDLES,
		StdInput:  syswindows.Handle(os.Stdin.Fd()),
		StdOutput: syswindows.Handle(os.Stdout.Fd()),
		StdErr:    syswindows.Handle(os.Stderr.Fd()),
	}
	var procInfo syswindows.ProcessInformation
	creationFlags := uint32(syswindows.CREATE_UNICODE_ENVIRONMENT | syswindows.CREATE_SUSPENDED)
	r1, _, callErr := procCreateProcessWithTokenW.Call(
		uintptr(token),
		uintptr(createProcessWithTokenLogonFlags),
		0,
		uintptr(unsafe.Pointer(&commandLine[0])),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(&envBlock[0])),
		uintptr(unsafe.Pointer(cwd16)),
		uintptr(unsafe.Pointer(&startup)),
		uintptr(unsafe.Pointer(&procInfo)),
	)
	if r1 == 0 {
		return 0, callErr
	}
	defer syswindows.CloseHandle(procInfo.Process)
	defer syswindows.CloseHandle(procInfo.Thread)

	if err := syswindows.AssignProcessToJobObject(job, procInfo.Process); err != nil {
		_ = syswindows.TerminateProcess(procInfo.Process, 1)
		return 0, err
	}
	if _, err := syswindows.ResumeThread(procInfo.Thread); err != nil {
		_ = syswindows.TerminateProcess(procInfo.Process, 1)
		return 0, err
	}
	done := make(chan waitResult, 1)
	go func() {
		var exitCode uint32
		_, waitErr := syswindows.WaitForSingleObject(procInfo.Process, syswindows.INFINITE)
		if waitErr == nil {
			waitErr = syswindows.GetExitCodeProcess(procInfo.Process, &exitCode)
		}
		done <- waitResult{code: exitCode, err: waitErr}
	}()
	select {
	case <-ctx.Done():
		_ = syswindows.TerminateJobObject(job, 1)
		_ = syswindows.TerminateProcess(procInfo.Process, 1)
		return 0, ctx.Err()
	case result := <-done:
		if result.err != nil {
			return 0, result.err
		}
		return int(result.code), nil
	}
}

type waitResult struct {
	code uint32
	err  error
}

func inheritStandardHandles() error {
	for _, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if err := syswindows.SetHandleInformation(syswindows.Handle(file.Fd()), syswindows.HANDLE_FLAG_INHERIT, syswindows.HANDLE_FLAG_INHERIT); err != nil {
			return err
		}
	}
	return nil
}

func createKillOnCloseJob() (syswindows.Handle, error) {
	job, err := syswindows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info syswindows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = syswindows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := syswindows.SetInformationJobObject(
		job,
		syswindows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		_ = syswindows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func logonUser(user string, domain string, password string) (syswindows.Token, error) {
	user16, err := syswindows.UTF16PtrFromString(user)
	if err != nil {
		return 0, err
	}
	domain16, err := syswindows.UTF16PtrFromString(domain)
	if err != nil {
		return 0, err
	}
	password16, err := syswindows.UTF16PtrFromString(password)
	if err != nil {
		return 0, err
	}
	var token syswindows.Token
	r1, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(user16)),
		uintptr(unsafe.Pointer(domain16)),
		uintptr(unsafe.Pointer(password16)),
		uintptr(logon32LogonInteractive),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return 0, callErr
	}
	return token, nil
}

func environmentBlock(token syswindows.Token) ([]uint16, error) {
	tokenEnv, err := token.Environ(false)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, item := range tokenEnv {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		values[key] = value
	}

	requestEnv, err := requestEnvironment()
	if err != nil {
		return nil, err
	}
	for key, value := range requestEnv {
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b string) int {
		return strings.Compare(strings.ToUpper(a), strings.ToUpper(b))
	})
	var builder strings.Builder
	for _, key := range keys {
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(values[key])
		builder.WriteByte(0)
	}
	builder.WriteByte(0)
	return utf16.Encode([]rune(builder.String())), nil
}

func requestEnvironment() (map[string]string, error) {
	raw := os.Getenv(envWindowsRequest)
	if raw == "" || raw == "null" {
		return nil, nil
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
