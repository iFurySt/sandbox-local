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

	"golang.org/x/sys/unix"
)

func TestSeatbeltLargeProfile(t *testing.T) {
	workspace, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	argmax, err := unix.SysctlUint32("kern.argmax")
	if err != nil {
		t.Fatal(err)
	}
	// Long, distinct paths keep the profile large without excessive rule counts.
	prefix := filepath.Join(workspace, strings.Repeat("a", 180), strings.Repeat("b", 180),
		strings.Repeat("c", 180), strings.Repeat("d", 180))
	denied := []string{filepath.Join(workspace, "protected")}
	for i := 0; i < int(argmax)/(4*len(prefix))+100; i++ {
		denied = append(denied, filepath.Join(prefix, fmt.Sprint(i)))
	}
	policy := Policy{Filesystem: FilesystemPolicy{WriteAllow: []string{workspace}, WriteDeny: denied}}
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
		Command: []string{"/bin/sh", "-c", "printf hello > allowed; printf blocked > protected; cat allowed"},
		Cwd:     workspace, Policy: policy, Stdio: Stdio{Stdout: &output, Stderr: &output},
	})
	if err != nil || result == nil || result.ExitCode != 0 || !strings.HasSuffix(output.String(), "hello") {
		t.Fatalf("large profile failed: result=%+v error=%v output=%s", result, err, output.String())
	}
	if _, err := os.Stat(filepath.Join(workspace, "protected")); !os.IsNotExist(err) {
		t.Fatalf("large profile lost its write deny: %v", err)
	}
}

func TestSeatbeltProfileCleanup(t *testing.T) {
	workspace := t.TempDir()
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
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
			assertNoProfileFiles(t, temporary)
		})
	}
	if _, err := manager.Prepare(context.Background(), Request{Command: []string{"/usr/bin/true"}, Cwd: workspace}); err != nil {
		t.Fatal(err)
	}
	assertNoProfileFiles(t, temporary)
}

func assertNoProfileFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary profile files survived: entries=%v error=%v", entries, err)
	}
}
