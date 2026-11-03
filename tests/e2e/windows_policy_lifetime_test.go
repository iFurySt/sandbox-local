//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWindowsChildrenCannotOutlivePolicyCleanup(t *testing.T) {
	cwd := t.TempDir()
	helper, fixture := buildHelper(t, cwd), windowsCommandFixture(t, cwd)
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, network := range []sandbox.NetworkMode{sandbox.NetworkOpen, sandbox.NetworkOffline} {
		t.Run(string(network), func(t *testing.T) {
			marker := filepath.Join(cwd, fmt.Sprintf("child-%s", network))
			var out bytes.Buffer
			policy := sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{cwd}, WriteAllow: []string{cwd}}, Network: sandbox.NetworkPolicy{Mode: network}, Process: sandbox.ProcessPolicy{Timeout: 30 * time.Second}}
			result, err := manager.Run(context.Background(), sandbox.Request{Command: []string{fixture, "background", "10000", marker}, Cwd: cwd, Policy: policy, Stdio: sandbox.Stdio{Stdout: &out}})
			if err != nil || result.ExitCode != 0 || out.String() != "foreground" {
				t.Fatalf("result=%+v err=%v stdout=%q", result, err, out.String())
			}
			raw, err := os.ReadFile(marker + ".pid")
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
			if err != nil {
				t.Fatal(err)
			}
			process, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err == windows.ERROR_INVALID_PARAMETER {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(process)
			defer windows.TerminateProcess(process, 0)
			state, err := windows.WaitForSingleObject(process, 3000)
			if err != nil || state != windows.WAIT_OBJECT_0 {
				t.Fatalf("background PID %d is still running after %s policy cleanup: state=%d err=%v", pid, network, state, err)
			}
		})
	}
}
