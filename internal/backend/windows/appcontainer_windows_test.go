//go:build windows

package windows

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/iFurySt/sandbox-local/internal/appcontainer"
	"github.com/iFurySt/sandbox-local/internal/helpercmd"
	"github.com/iFurySt/sandbox-local/internal/helperprotocol"
	"github.com/iFurySt/sandbox-local/internal/model"
	syswindows "golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--sandbox-test-pipe" {
		os.Exit(localPipeProbe())
	}
	if len(os.Args) > 1 && os.Args[1] == "--sandbox-test-sleep" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "--sandbox-test-spawn" {
		exe, err := os.Executable()
		if err != nil {
			os.Exit(1)
		}
		cmd := exec.Command(exe, "--sandbox-test-sleep")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syswindows.CREATE_NO_WINDOW}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "start descendant:", err)
			os.Exit(1)
		}
		fmt.Printf("DESCENDANT_PID=%d\n", cmd.Process.Pid)
		time.Sleep(time.Minute)
		os.Exit(0)
	}

	if len(os.Args) > 1 && os.Args[1] == "--sandbox-test-read" {
		data, err := os.ReadFile(os.Args[2])
		if err != nil {
			os.Exit(1)
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "--sandbox-test-nested" {
		os.Exit(nestedTokenProbe(os.Args[2]))
	}

	if len(os.Args) > 1 && os.Args[1] == helperprotocol.DispatchCommand {
		os.Exit(helpercmd.Run(context.Background(), os.Args[2:], os.Stderr))
	}
	if os.Getenv("SANDBOX_TEST_REQUIRE_STANDARD_USER") == "1" && hasAdministratorGroup() {
		fmt.Fprintln(os.Stderr, "Windows standard-user tests must not run with administrator membership")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestAppContainerFilesystemEnforcement(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workspace, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"secret.txt", "readonly.txt"} {
		if err := os.WriteFile(filepath.Join(workspace, file), []byte("protected-content"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	policy := model.Policy{Filesystem: model.FilesystemPolicy{
		WriteAllow: []string{workspace}, WriteDeny: []string{filepath.Join(workspace, ".git"), filepath.Join(workspace, "readonly.txt")},
		ReadDeny: []string{filepath.Join(workspace, "secret.txt")},
	}}
	for _, test := range []struct {
		name, command string
		allowed       bool
	}{
		{"allowed write", `echo allowed>allowed.txt`, true},
		{"allowed child", `cmd.exe /d /c echo child`, true},
		{"protected read", `type secret.txt`, false},
		{"protected write", `echo bad>.git\blocked.txt`, false},
		{"protected delete", `del readonly.txt`, false},
		{"protected rename", `ren .git stolen`, false},
		{"outside write", `echo bad>..\outside.txt`, false},
		{"ACL bypass", `icacls . /grant *S-1-15-2-1:(OI)(CI)F`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := appContainerCommand(t, workspace, policy, []string{"cmd.exe", "/d", "/c", test.command})
			if (err == nil) != test.allowed {
				t.Fatalf("command error = %v, allowed = %v; output: %s", err, test.allowed, output)
			}
			if strings.Contains(output, "protected-content") {
				t.Fatal("protected file content escaped")
			}
		})
	}
	for _, file := range []string{".git/blocked.txt", "stolen", "../outside.txt"} {
		if _, err := os.Stat(filepath.Join(workspace, file)); !os.IsNotExist(err) {
			t.Fatalf("forbidden path %s exists: %v", file, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(workspace, "readonly.txt")); err != nil || string(data) != "protected-content" {
		t.Fatalf("read-only file changed: %q, %v", data, err)
	}
}

func TestAppContainerOfflineAndUnsupportedAllowlist(t *testing.T) {
	workspace := t.TempDir()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil || line == "\r\n" {
					break
				}
			}
			_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			_ = conn.Close()
		}
	}()
	url := "http://" + listener.Addr().String()
	command := []string{"curl.exe", "--silent", "--show-error", "--noproxy", "*", "--max-time", "2", url}
	if out, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("network positive control failed: %v, %s", err, out)
	}
	if out, err := appContainerCommand(t, workspace, model.Policy{}, command); err == nil || !strings.Contains(out, "curl:") {
		t.Fatalf("offline request did not fail at the network boundary: %v, %s", err, out)
	}
	_, cleanup, err := prepareAppContainer(context.Background(), model.Request{
		Command: []string{"cmd.exe", "/c", "echo unsafe"}, Cwd: workspace,
		Policy: model.Policy{Network: model.NetworkPolicy{Mode: model.NetworkAllowlist, Allow: []string{"example.com"}}},
	})
	if err == nil || cleanup != nil || !strings.Contains(err.Error(), "cannot enforce") {
		t.Fatalf("unsupported allowlist = %v, cleanup present = %v", err, cleanup != nil)
	}
}

func appContainerCommand(t *testing.T, workspace string, policy model.Policy, command []string) (string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	timeout := 10 * time.Second
	if policy.Process.Timeout > 0 {
		timeout = policy.Process.Timeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	prepared, cleanup, err := prepareAppContainer(ctx, model.Request{Command: command, Cwd: workspace, Policy: policy, HelperPath: exe})
	if err != nil {
		t.Fatal(err)
	}
	var config appcontainer.Config
	_ = json.Unmarshal([]byte(prepared.Env[appcontainer.Environment]), &config)
	cmd := exec.CommandContext(ctx, prepared.Command[0], prepared.Command[1:]...)
	cmd.Dir = prepared.Cwd
	cmd.Env = os.Environ()
	for key, value := range prepared.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	output, commandErr := cmd.CombinedOutput()
	if err := cleanup(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("AppContainer cleanup failed: %v", err)
	}
	for _, path := range []string{workspace, filepath.Join(workspace, "secret.txt"), filepath.Join(workspace, ".git")} {
		sd, err := syswindows.GetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
		if err != nil {
			continue
		}
		if strings.Contains(sd.String(), config.SID) || strings.Contains(sd.String(), config.DenySID) {
			t.Fatalf("invocation ACL leaked on %s: %s", path, sd.String())
		}
	}
	return string(output), commandErr
}

func nestedTokenProbe(path string) int {
	var base syswindows.Token
	if err := syswindows.OpenProcessToken(syswindows.CurrentProcess(), syswindows.TOKEN_DUPLICATE|syswindows.TOKEN_ASSIGN_PRIMARY|syswindows.TOKEN_QUERY, &base); err != nil {
		return 1
	}
	defer base.Close()
	user, err := base.GetTokenUser()
	if err != nil {
		return 1
	}
	restricting := syswindows.SIDAndAttributes{Sid: user.User.Sid}
	var token syswindows.Token
	ok, _, _ := syswindows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(base), 1, 0, 0, 0, 0, 1, uintptr(unsafe.Pointer(&restricting)), uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return 1
	}
	defer token.Close()
	exe, err := os.Executable()
	if err != nil {
		return 1
	}
	cmd := exec.Command(exe, "--sandbox-test-read", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token)}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if cmd.Run() != nil {
		return 1
	}
	return 0
}

func TestAppContainerNestedTokenCannotRemoveDenials(t *testing.T) {
	workspace := t.TempDir()
	secret := filepath.Join(workspace, "secret.txt")
	if err := os.WriteFile(secret, []byte("protected-content"), 0600); err != nil {
		t.Fatal(err)
	}
	exe := ownedTestExecutable(t, workspace)
	policy := model.Policy{Filesystem: model.FilesystemPolicy{ReadAllow: []string{workspace}, ReadDeny: []string{secret}}}
	out, err := appContainerCommand(t, workspace, policy, []string{exe, "--sandbox-test-nested", secret})
	if err == nil || strings.Contains(out, "protected-content") {
		t.Fatalf("nested token removed a denial: %v, %s", err, out)
	}
}

func TestAppContainerCancellationKillsDescendants(t *testing.T) {
	workspace := t.TempDir()
	exe := ownedTestExecutable(t, workspace)
	policy := model.Policy{Process: model.ProcessPolicy{Timeout: 3 * time.Second}}
	out, err := appContainerCommand(t, workspace, policy, []string{exe, "--sandbox-test-spawn"})
	if err == nil {
		t.Fatal("sleeping process did not time out")
	}
	match := regexp.MustCompile(`DESCENDANT_PID=(\d+)`).FindStringSubmatch(out)
	if len(match) != 2 {
		t.Fatalf("descendant did not start: %v, %s", err, out)
	}
	pid, err := strconv.ParseUint(match[1], 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		process, err := syswindows.OpenProcess(syswindows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err == syswindows.ERROR_INVALID_PARAMETER {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var exit uint32
		err = syswindows.GetExitCodeProcess(process, &exit)
		closeErr := syswindows.CloseHandle(process)
		if err != nil || closeErr != nil {
			t.Fatalf("query descendant: %v, %v", err, closeErr)
		}
		if exit != 259 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d survived cancellation", pid)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func ownedTestExecutable(t *testing.T, workspace string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, "child.exe")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAppContainerOverlappingCleanupPreservesOtherInvocation(t *testing.T) {
	workspace := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	request := model.Request{Command: []string{"cmd.exe", "/c", "echo ok"}, Cwd: workspace, HelperPath: exe, Env: map[string]string{"FAKE_CREDENTIAL": "synthetic-value"}, Policy: model.Policy{Filesystem: model.FilesystemPolicy{WriteAllow: []string{workspace}}}}
	first, cleanupFirst, err := prepareAppContainer(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, cleanupSecond, err := prepareAppContainer(context.Background(), request)
	if err != nil {
		_ = cleanupFirst(context.Background())
		t.Fatal(err)
	}
	if first.Env["FAKE_CREDENTIAL"] != "synthetic-value" || second.Env["FAKE_CREDENTIAL"] != "synthetic-value" || len(request.Env) != 1 {
		t.Fatal("execution environment was lost or caller data was changed")
	}
	var one, two appcontainer.Config
	if err := json.Unmarshal([]byte(first.Env[appcontainer.Environment]), &one); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(second.Env[appcontainer.Environment]), &two); err != nil {
		t.Fatal(err)
	}
	if err := cleanupFirst(context.Background()); err != nil {
		t.Fatal(err)
	}
	sd, err := syswindows.GetNamedSecurityInfo(workspace, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sd.String(), one.SID) || strings.Contains(sd.String(), one.DenySID) || !strings.Contains(sd.String(), two.SID) || !strings.Contains(sd.String(), two.DenySID) {
		t.Fatalf("overlapping invocation ACL changed: %s", sd.String())
	}
	if err := cleanupSecond(context.Background()); err != nil {
		t.Fatal(err)
	}
	sd, err = syswindows.GetNamedSecurityInfo(workspace, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sd.String(), two.SID) || strings.Contains(sd.String(), two.DenySID) {
		t.Fatalf("cleanup leaked invocation identities: %s", sd.String())
	}
}
