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

	syswindows "golang.org/x/sys/windows"
)

const (
	envWindowsUser     = "SANDBOX_LOCAL_WINDOWS_USER"
	envWindowsPassword = "SANDBOX_LOCAL_WINDOWS_PASSWORD"
	envWindowsDomain   = "SANDBOX_LOCAL_WINDOWS_DOMAIN"
	envWindowsRequest  = "SANDBOX_LOCAL_WINDOWS_REQUEST_ENV"
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
	defer deleteTask(context.Background(), taskName)

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
			_ = deleteTask(context.Background(), taskName)
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
