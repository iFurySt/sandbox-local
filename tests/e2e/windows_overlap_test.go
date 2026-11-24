//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	"golang.org/x/sys/windows"
)

type observedStream struct {
	mu sync.Mutex
	bytes.Buffer
}

func (s *observedStream) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Buffer.Write(data)
}

func (s *observedStream) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Buffer.String()
}

func TestWindowsOverlappingCommandsRetainIndependentPolicies(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("local-account overlap requires an elevated host")
	}
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
	secret := filepath.Join(cwd, "secret")
	if err := os.WriteFile(secret, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []sandbox.NetworkMode{sandbox.NetworkOpen, sandbox.NetworkOffline} {
		t.Run(string(mode), func(t *testing.T) {
			ready := filepath.Join(cwd, string(mode)+"-ready")
			release := filepath.Join(cwd, string(mode)+"-release")
			allowed := filepath.Join(cwd, string(mode)+"-allowed")
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			var stdout, stderr observedStream
			type outcome struct {
				result *sandbox.Result
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := manager.Run(ctx, sandbox.Request{
					Command: []string{fixture, "gated-policy", ready, release, allowed, secret}, Cwd: cwd,
					Policy: sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{
						ReadAllow: []string{cwd}, WriteAllow: []string{cwd}, ReadDeny: []string{secret}, WriteDeny: []string{secret}},
						Network: sandbox.NetworkPolicy{Mode: mode}, Process: sandbox.ProcessPolicy{Timeout: 75 * time.Second}},
					Stdio: sandbox.Stdio{Stdout: &stdout, Stderr: &stderr}})
				done <- outcome{result, err}
			}()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case result := <-done:
						t.Logf("cancelled held command: result=%+v err=%v", result.result, result.err)
					case <-time.After(20 * time.Second):
						t.Error("held command did not return during cleanup")
					}
				}
			})
			deadline := time.Now().Add(25 * time.Second)
			for {
				if _, err := os.Stat(ready); err == nil && stdout.text() == "before-release" && stderr.text() == "before-release-error" {
					break
				}
				select {
				case result := <-done:
					joined = true
					t.Fatalf("held command ended before readiness: result=%+v err=%v stdout=%q stderr=%q", result.result, result.err, stdout.text(), stderr.text())
				default:
				}
				if !time.Now().Before(deadline) {
					t.Fatalf("missing live output/readiness: stdout=%q stderr=%q", stdout.text(), stderr.text())
				}
				time.Sleep(25 * time.Millisecond)
			}
			shortMode := sandbox.NetworkOffline
			if mode == sandbox.NetworkOffline {
				shortMode = sandbox.NetworkOpen
			}
			shortPolicy := sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{cwd}, WriteDeny: []string{cwd}},
				Network: sandbox.NetworkPolicy{Mode: shortMode}, Process: sandbox.ProcessPolicy{Timeout: 20 * time.Second}}
			for _, test := range []struct {
				args []string
				code int
				out  string
			}{
				{[]string{fixture, "write", allowed}, 9, ""},
				{[]string{fixture, "read", secret}, 0, "original"},
			} {
				var out, errOut bytes.Buffer
				result, err := manager.Run(ctx, sandbox.Request{Command: test.args, Cwd: cwd, Policy: shortPolicy,
					Stdio: sandbox.Stdio{Stdout: &out, Stderr: &errOut}})
				if err != nil || result.ExitCode != test.code || out.String() != test.out {
					t.Fatalf("short command result=%+v err=%v stdout=%q stderr=%q", result, err, out.String(), errOut.String())
				}
			}
			select {
			case result := <-done:
				joined = true
				t.Fatalf("held command ended before release: %+v", result)
			default:
			}
			if data, err := os.ReadFile(allowed); err != nil || string(data) != "allowed" {
				t.Fatalf("rejected write changed state: data=%q err=%v", data, err)
			}
			if err := os.WriteFile(release, nil, 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				joined = true
				if result.err != nil || result.result.ExitCode != 0 {
					t.Fatalf("held command lost its policy after short cleanup: result=%+v err=%v stderr=%q", result.result, result.err, stderr.text())
				}
			case <-time.After(20 * time.Second):
				t.Fatal("released command did not finish")
			}
			if stdout.text() != "before-releaseafter-release" || stderr.text() != "before-release-error" {
				t.Fatalf("lost or duplicated output: stdout=%q stderr=%q", stdout.text(), stderr.text())
			}
			if data, err := os.ReadFile(secret); err != nil || string(data) != "original" {
				t.Fatalf("deny policy did not preserve secret: data=%q err=%v", data, err)
			}
		})
	}
}
