//go:build integration

package e2e

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
)

func TestSDKUpperAppFilesystemIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	workdir := prepareWorkspace(t)
	helperPath := buildHelper(t, workdir)
	manager := newReadyManager(t, ctx, helperPath)

	policy := basePolicy(workdir)
	var out bytes.Buffer
	result, err := manager.Run(ctx, sandbox.Request{
		Command: writeAllowedCommand(),
		Cwd:     workdir,
		Policy:  policy,
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("allowed write returned error: %v\n%s", err, out.String())
	}
	if result.ExitCode != 0 {
		t.Fatalf("allowed write exit code = %d\n%s", result.ExitCode, out.String())
	}
	if data, err := os.ReadFile(filepath.Join(workdir, "allowed.txt")); err != nil || strings.TrimSpace(string(data)) != "ok" {
		t.Fatalf("allowed write file = %q, %v", string(data), err)
	}

	out.Reset()
	result, err = manager.Run(ctx, sandbox.Request{
		Command: writeDeniedCommand(),
		Cwd:     workdir,
		Policy:  policy,
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("denied write returned runner error instead of process denial: %v\n%s", err, out.String())
	}
	if result.ExitCode == 0 {
		t.Fatalf("denied write unexpectedly succeeded\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(workdir, ".git", "blocked.txt")); !os.IsNotExist(err) {
		t.Fatalf("denied write created blocked file: %v", err)
	}

	out.Reset()
	result, err = manager.Run(ctx, sandbox.Request{
		Command: readDeniedCommand(),
		Cwd:     workdir,
		Policy:  policy,
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("denied read returned runner error instead of process denial: %v\n%s", err, out.String())
	}
	if result.ExitCode == 0 {
		t.Fatalf("denied read unexpectedly succeeded\n%s", out.String())
	}
}

func TestSDKUpperAppNetworkIsolation(t *testing.T) {
	if _, err := exec.LookPath(curlCommand()); err != nil {
		t.Skipf("curl is required for network E2E: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	workdir := prepareWorkspace(t)
	helperPath := buildHelper(t, workdir)
	manager := newReadyManager(t, ctx, helperPath)

	var out bytes.Buffer
	result, err := manager.Run(ctx, sandbox.Request{
		Command: curlHeadCommand("https://example.com", false),
		Cwd:     workdir,
		Policy:  withNetwork(basePolicy(workdir), sandbox.NetworkOffline, nil),
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("offline network returned runner error instead of process denial: %v\n%s", err, out.String())
	}
	if result.ExitCode == 0 {
		t.Fatalf("offline network unexpectedly succeeded\n%s", out.String())
	}

	report, err := manager.Check(ctx)
	if err != nil {
		t.Fatalf("check backend: %v", err)
	}
	if !slices.Contains(report.NetworkModes, string(sandbox.NetworkAllowlist)) {
		t.Skipf("backend %s does not support network allowlist", report.Backend)
	}

	out.Reset()
	result, err = manager.Run(ctx, sandbox.Request{
		Command: curlHeadCommand("https://example.com", false),
		Cwd:     workdir,
		Policy:  withNetwork(basePolicy(workdir), sandbox.NetworkAllowlist, []string{"example.com"}),
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("allowlisted network returned error: %v\n%s", err, out.String())
	}
	if result.ExitCode != 0 {
		t.Fatalf("allowlisted network exit code = %d\n%s", result.ExitCode, out.String())
	}

	out.Reset()
	result, err = manager.Run(ctx, sandbox.Request{
		Command: curlHeadCommand("https://openai.com", false),
		Cwd:     workdir,
		Policy:  withNetwork(basePolicy(workdir), sandbox.NetworkAllowlist, []string{"example.com"}),
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("non-allowlisted network returned runner error instead of process denial: %v\n%s", err, out.String())
	}
	if result.ExitCode == 0 {
		t.Fatalf("non-allowlisted network unexpectedly succeeded\n%s", out.String())
	}

	out.Reset()
	result, err = manager.Run(ctx, sandbox.Request{
		Command: curlHeadCommand("https://example.com", true),
		Cwd:     workdir,
		Policy:  withNetwork(basePolicy(workdir), sandbox.NetworkAllowlist, []string{"example.com"}),
		Stdio:   sandbox.Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatalf("direct network bypass returned runner error instead of process denial: %v\n%s", err, out.String())
	}
	if result.ExitCode == 0 {
		t.Fatalf("direct network bypass unexpectedly succeeded\n%s", out.String())
	}
}

func newReadyManager(t *testing.T, ctx context.Context, helperPath string) *sandbox.Manager {
	t.Helper()
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helperPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = manager.Close()
	})
	report, err := manager.Check(ctx)
	if err != nil {
		t.Fatalf("check backend: %v", err)
	}
	if !report.Available || !report.Sandboxed {
		t.Skipf("sandbox backend unavailable: %+v", report)
	}
	setup, err := manager.Setup(ctx, sandbox.SetupRequest{TargetPlatform: runtime.GOOS})
	if err != nil {
		t.Fatalf("setup backend: %v; report=%+v", err, setup)
	}
	if !setup.Ready {
		t.Skipf("sandbox setup is not ready: %+v", setup)
	}
	return manager
}

func buildHelper(t *testing.T, workdir string) string {
	t.Helper()
	name := "sandbox-local"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helperPath := filepath.Join(workdir, name)
	cmd := exec.Command("go", "build", "-o", helperPath, "./cmd/sandbox-local")
	cmd.Dir = repoRoot(t)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out.String())
	}
	return helperPath
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func prepareWorkspace(t *testing.T) string {
	t.Helper()
	workdir := t.TempDir()
	if err := os.Mkdir(filepath.Join(workdir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return workdir
}

func basePolicy(workdir string) sandbox.Policy {
	return sandbox.Policy{
		Filesystem: sandbox.FilesystemPolicy{
			ReadAllow:  []string{workdir},
			ReadDeny:   []string{filepath.Join(workdir, "secret.txt")},
			WriteAllow: []string{workdir},
			WriteDeny:  []string{filepath.Join(workdir, ".git")},
		},
		Network: sandbox.NetworkPolicy{Mode: sandbox.NetworkOffline},
		Process: sandbox.ProcessPolicy{Timeout: 20 * time.Second},
	}
}

func withNetwork(policy sandbox.Policy, mode sandbox.NetworkMode, allow []string) sandbox.Policy {
	policy.Network.Mode = mode
	policy.Network.Allow = allow
	return policy
}

func writeAllowedCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/c", "echo ok>allowed.txt"}
	}
	return []string{"/bin/sh", "-c", "printf ok > allowed.txt"}
}

func writeDeniedCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/c", "echo|set /p=bad>.git\\blocked.txt"}
	}
	return []string{"/bin/sh", "-c", "printf bad > .git/blocked.txt"}
}

func readDeniedCommand() []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd.exe", "/c", "type secret.txt >NUL"}
	}
	return []string{"/bin/sh", "-c", "cat secret.txt >/dev/null"}
}

func curlCommand() string {
	if runtime.GOOS == "windows" {
		return "curl.exe"
	}
	return "curl"
}

func curlHeadCommand(url string, bypassProxy bool) []string {
	args := []string{curlCommand(), "--fail", "-I", "--max-time", "8"}
	if bypassProxy {
		if runtime.GOOS == "windows" {
			args = append(args, "--noproxy", "*")
		} else {
			args = append(args, "--noproxy", "*")
		}
	}
	args = append(args, url)
	return args
}
