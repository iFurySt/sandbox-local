package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSeatbeltInlineProfileEnforcesSpecialCharacterPath(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var allowed string
	for i := 0; i < 128; i++ {
		directory := filepath.Join(workspace, fmt.Sprintf("entry-%03d", i))
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if i == 127 {
			allowed = filepath.Join(directory, "allowed")
		}
	}
	denied := filepath.Join(workspace, `protected "quoted" \\ path`)
	policy := Policy{Filesystem: FilesystemPolicy{WriteAllow: []string{workspace}, WriteDeny: []string{denied}}}
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	var output bytes.Buffer
	result, err := manager.Run(context.Background(), Request{
		Command: []string{"/bin/sh", "-c", "printf hello > \"$1\"; printf blocked > \"$2\"; cat \"$1\"", "sh", allowed, denied},
		Cwd:     workspace, Policy: policy, Stdio: Stdio{Stdout: &output, Stderr: &output},
	})
	if err != nil || result == nil || result.ExitCode != 0 || !strings.HasSuffix(output.String(), "hello") {
		t.Fatalf("inline profile failed: result=%+v error=%v output=%s", result, err, output.String())
	}
	if _, err := os.Stat(denied); !os.IsNotExist(err) {
		t.Fatalf("inline profile lost its write deny: %v", err)
	}
}

func TestSeatbeltInlineProfileLifecycle(t *testing.T) {
	workspace := t.TempDir()
	manager, err := NewManager(Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, test := range []struct {
		name        string
		command     []string
		cancel      bool
		timeout     time.Duration
		wantError   bool
		wantNonzero bool
	}{
		{name: "success", command: []string{"/usr/bin/true"}},
		{name: "exit failure", command: []string{"/usr/bin/false"}, wantNonzero: true},
		{name: "executable missing", command: []string{filepath.Join(workspace, "missing")}, wantNonzero: true},
		{name: "cancelled", command: []string{"/usr/bin/true"}, cancel: true, wantError: true},
		{name: "timeout", command: []string{"/bin/sleep", "10"}, timeout: 50 * time.Millisecond, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.cancel {
				cancel()
			}
			result, err := manager.Run(ctx, Request{Command: test.command, Cwd: workspace,
				Policy: Policy{Process: ProcessPolicy{Timeout: test.timeout}}})
			if (err != nil) != test.wantError {
				t.Fatalf("Run() error=%v, wantError=%v", err, test.wantError)
			}
			if !test.wantError && (result == nil || (result.ExitCode != 0) != test.wantNonzero) {
				t.Fatalf("Run() result=%+v, wantNonzero=%v", result, test.wantNonzero)
			}
		})
	}
}
