//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
)

func TestWindowsReadOnlyTaskTransport(t *testing.T) {
	root := t.TempDir()
	workdir := filepath.Join(root, "readonly workspace with spaces")
	if err := os.Mkdir(workdir, 0755); err != nil {
		t.Fatal(err)
	}
	helper := buildHelper(t, workdir)
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	policy := sandbox.Policy{
		Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{workdir}, WriteDeny: []string{workdir}},
		Network:    sandbox.NetworkPolicy{Mode: sandbox.NetworkOpen},
		Process:    sandbox.ProcessPolicy{Timeout: 30 * time.Second},
	}
	for _, test := range []struct {
		name, script, stdout, stderr string
		exit                         int
	}{
		{name: "empty", script: "exit 0"},
		{name: "stdout", script: "echo readonly-ok", stdout: "readonly-ok"},
		{name: "stderr", script: "echo readonly-error 1>&2", stderr: "readonly-error"},
		{name: "nonzero", script: "exit 23", exit: 23},
		{name: "write denied", script: "echo forbidden>blocked.txt", exit: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			var stdout, stderr bytes.Buffer
			result, err := manager.Run(ctx, sandbox.Request{
				Command: []string{"cmd.exe", "/d", "/c", test.script}, Cwd: workdir, Policy: policy,
				Stdio: sandbox.Stdio{Stdout: &stdout, Stderr: &stderr},
			})
			if err != nil || result.ExitCode != test.exit {
				t.Fatalf("result=%+v error=%v stdout=%q stderr=%q", result, err, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "bootstrap failed") || strings.Contains(stderr.String(), "create scheduled task") {
				t.Fatalf("runner failed instead of exercising command: %s", stderr.String())
			}
			if strings.TrimSpace(stdout.String()) != test.stdout ||
				(test.stderr != "" && !strings.Contains(stderr.String(), test.stderr)) {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if _, err := os.Stat(filepath.Join(workdir, "blocked.txt")); !os.IsNotExist(err) {
				t.Fatalf("readonly command created a file: %v", err)
			}
		})
	}
}

func TestWindowsTaskBootstrapFailure(t *testing.T) {
	cwd := t.TempDir()
	helper := buildHelper(t, cwd)
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	started := time.Now()
	var output bytes.Buffer
	result, err := manager.Run(context.Background(), sandbox.Request{Command: []string{filepath.Join(cwd, "does-not-exist.exe")}, Cwd: cwd,
		Policy: sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{cwd}, WriteDeny: []string{cwd}}, Network: sandbox.NetworkPolicy{Mode: sandbox.NetworkOpen}, Process: sandbox.ProcessPolicy{Timeout: 20 * time.Second}}, Stdio: sandbox.Stdio{Stderr: &output}})
	if err != nil || result.ExitCode == 0 || !strings.Contains(output.String(), "bootstrap failed") {
		t.Fatalf("result=%+v err=%v stderr=%q", result, err, output.String())
	}
	if elapsed := time.Since(started); elapsed > 8*time.Second {
		t.Fatalf("bootstrap failure waited %s", elapsed)
	}
}
