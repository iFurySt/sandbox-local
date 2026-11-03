//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	"golang.org/x/sys/windows"
)

func TestWindowsExecutionLifecycle(t *testing.T) {
	before := windowsTaskResources(t)
	t.Cleanup(func() {
		for resource := range windowsTaskResources(t) {
			if !before[resource] {
				t.Errorf("execution leaked owned resource: %s", resource)
			}
		}
	})
	cwd := t.TempDir()
	helper, fixture := buildHelper(t, cwd), windowsCommandFixture(t, cwd)
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	policy := sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{cwd}, WriteAllow: []string{cwd}}, Network: sandbox.NetworkPolicy{Mode: sandbox.NetworkOpen}, Process: sandbox.ProcessPolicy{Timeout: 20 * time.Second}}
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			marker := filepath.Join(cwd, mode+".pid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			current := policy
			if mode == "timeout" {
				current.Process.Timeout = 5 * time.Second
			}
			var partial bytes.Buffer
			finished := make(chan error, 1)
			go func() {
				_, err := manager.Run(ctx, sandbox.Request{Command: []string{fixture, "descendant", marker}, Cwd: cwd, Policy: current, Stdio: sandbox.Stdio{Stdout: &partial}})
				finished <- err
			}()
			var pid uint64
			until := time.Now().Add(12 * time.Second)
			for time.Now().Before(until) {
				if data, err := os.ReadFile(marker); err == nil {
					if parsed, err := strconv.ParseUint(string(data), 10, 32); err == nil && parsed != 0 {
						pid = parsed
						break
					}
				}
				select {
				case err := <-finished:
					t.Fatalf("command ended before marker: %v", err)
				default:
				}
				time.Sleep(50 * time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("descendant did not start")
			}
			process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(process)
			started := time.Now()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-finished:
				expected := context.Canceled
				if mode == "timeout" {
					expected = context.DeadlineExceeded
				}
				if !errors.Is(err, expected) {
					t.Fatalf("expected %v, got %v", expected, err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("cancelled execution did not return")
			}
			if partial.String() != "started" {
				t.Fatalf("lost partial stdout: %q", partial.String())
			}
			state, err := windows.WaitForSingleObject(process, 3000)
			if err != nil || state != windows.WAIT_OBJECT_0 {
				t.Fatalf("descendant survived cleanup: state=%d err=%v", state, err)
			}
			t.Logf("returned and reaped descendant in %s", time.Since(started))
		})
	}
	t.Run("background handles", func(t *testing.T) {
		var out, errOut bytes.Buffer
		started := time.Now()
		result, err := manager.Run(context.Background(), sandbox.Request{Command: []string{fixture, "background", "15000"}, Cwd: cwd, Policy: policy, Stdio: sandbox.Stdio{Stdout: &out, Stderr: &errOut}})
		if err != nil || result.ExitCode != 0 || out.String() != "foreground" || errOut.Len() != 0 {
			t.Fatalf("result=%+v err=%v stdout=%q stderr=%q", result, err, out.String(), errOut.String())
		}
		if elapsed := time.Since(started); elapsed > 8*time.Second {
			t.Fatalf("background handles delayed completion: %s", elapsed)
		}
	})
	t.Run("concurrent and repeated", func(t *testing.T) {
		var wg sync.WaitGroup
		failures := make(chan error, 6)
		for i := 0; i < 6; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				var out bytes.Buffer
				p := policy
				p.Process.Timeout = time.Minute
				result, err := manager.Run(context.Background(), sandbox.Request{Command: []string{fixture, "argv", fmt.Sprint(i)}, Cwd: cwd, Policy: p, Stdio: sandbox.Stdio{Stdout: &out}})
				if err != nil || result.ExitCode != 0 || strings.TrimSpace(out.String()) != fmt.Sprintf(`["%d"]`, i) {
					failures <- fmt.Errorf("run %d result=%+v err=%v out=%q", i, result, err, out.String())
				}
			}(i)
		}
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Error(err)
		}
	})
}

// Compare only new resources: a shared developer host may contain residue from
// older builds, which this test must neither delete nor mistake for its own.
func windowsTaskResources(t *testing.T) map[string]bool {
	t.Helper()
	result := map[string]bool{}
	for _, pattern := range []string{
		filepath.Join(os.TempDir(), ".sandbox-local-win-*"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", "sandbox-local-*"),
	} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			result[path] = true
		}
	}
	return result
}
