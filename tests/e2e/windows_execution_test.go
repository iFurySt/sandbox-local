//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
)

func windowsCommandFixture(t *testing.T, directory string) string {
	t.Helper()
	destination := filepath.Join(directory, "command fixture.exe")
	if source := os.Getenv("SANDBOX_LOCAL_TEST_COMMAND"); source != "" {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, data, 0755); err != nil {
			t.Fatal(err)
		}
		return destination
	}
	command := exec.Command("go", "build", "-o", destination, "./tests/e2e/testdata/command")
	command.Dir = repoRoot(t)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build command fixture: %v %s", err, out)
	}
	return destination
}

func TestWindowsExecutionTransportMatrix(t *testing.T) {
	root := t.TempDir()
	workdir := filepath.Join(root, "workspace 中文 ' quote & percent%")
	if err := os.Mkdir(workdir, 0755); err != nil {
		t.Fatal(err)
	}
	helper := buildHelper(t, workdir)
	fixture := windowsCommandFixture(t, workdir)
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	policy := sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{workdir}, WriteAllow: []string{workdir}}, Network: sandbox.NetworkPolicy{Mode: sandbox.NetworkOpen}, Process: sandbox.ProcessPolicy{Timeout: 30 * time.Second}}
	argv := []string{"space arg", "double\"quote", "single'quote", "符号&|<>%TEMP%", "", "trailing\\", "tab\tvalue"}
	for _, tc := range []struct {
		name                  string
		args                  []string
		stdin, stdout, stderr string
		exit                  int
	}{
		{name: "argv", args: append([]string{"argv"}, argv...)},
		{name: "stdin", args: []string{"stdin"}, stdin: "first\nsecond\x00third", stdout: "first\nsecond\x00third"},
		{name: "both streams", args: []string{"streams", "100000"}, stdout: strings.Repeat("O", 100000), stderr: strings.Repeat("E", 100000)},
		{name: "nonzero", args: []string{"exit", "23"}, exit: 23},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			var out, errOut bytes.Buffer
			result, err := manager.Run(ctx, sandbox.Request{Command: append([]string{fixture}, tc.args...), Cwd: workdir, Policy: policy, Stdio: sandbox.Stdio{Stdin: strings.NewReader(tc.stdin), Stdout: &out, Stderr: &errOut}})
			if err != nil || result.ExitCode != tc.exit {
				t.Fatalf("result=%+v err=%v stderr=%q", result, err, errOut.String())
			}
			if tc.name == "argv" {
				var got []string
				if json.Unmarshal(out.Bytes(), &got) != nil || strings.Join(got, "\x00") != strings.Join(argv, "\x00") {
					t.Fatalf("argv=%q", out.String())
				}
				return
			}
			if out.String() != tc.stdout || errOut.String() != tc.stderr {
				t.Fatalf("stream mismatch stdout=%d/%d stderr=%d/%d", out.Len(), len(tc.stdout), errOut.Len(), len(tc.stderr))
			}
		})
	}
}
