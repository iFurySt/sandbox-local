package macos

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/internal/model"
)

func runProfile(t *testing.T, policy model.Policy, argv ...string) error {
	t.Helper()
	profile, err := buildProfile(policy, t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, sandboxExecPath, append([]string{"-p", profile}, argv...)...).CombinedOutput()
	if err != nil {
		t.Logf("sandbox command: %v: %s", err, output)
	}
	return err
}

func TestProcessControl(t *testing.T) {
	t.Parallel()
	for _, action := range []model.SeatbeltDefaultAction{"", model.SeatbeltDefaultDeny, model.SeatbeltDefaultAllow} {
		t.Run(string(action), func(t *testing.T) {
			t.Parallel()
			child := exec.Command("/bin/sleep", "60")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
			pid := fmt.Sprint(child.Process.Pid)
			policy := model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: action}}
			for _, signal := range []string{"-0", "-9"} {
				err := runProfile(t, policy, "/bin/kill", signal, pid)
				if (err == nil) != (action == model.SeatbeltDefaultAllow) {
					t.Fatalf("action=%q signal=%s error=%v", action, signal, err)
				}
			}
		})
	}
}

func TestResourceFences(t *testing.T) {
	t.Parallel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: model.SeatbeltDefaultAllow}, Filesystem: model.FilesystemPolicy{
		WriteAllow: []string{root}, WriteDeny: []string{secret}, ReadDeny: []string{secret},
	}}
	for _, tc := range []struct {
		name    string
		argv    []string
		allowed bool
	}{
		{"allowed-write", []string{"/usr/bin/touch", filepath.Join(root, "allowed")}, true},
		{"denied-write", []string{"/usr/bin/touch", secret}, false},
		{"denied-read", []string{"/bin/cat", secret}, false},
		{"outside-write", []string{"/usr/bin/touch", filepath.Join(root, "..", "outside-dsh-test")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runProfile(t, policy, tc.argv...); (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
		})
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
	argv := []string{"/usr/bin/nc", "-z", "-w", "1", "127.0.0.1", port}
	if err := runProfile(t, policy, argv...); err == nil {
		t.Fatal("offline connection succeeded")
	}
	policy.Network.Mode = model.NetworkOpen
	if err := runProfile(t, policy, argv...); err != nil {
		t.Fatalf("open connection failed: %v", err)
	}
}

func TestAllowBaselineNetworkAllowlist(t *testing.T) {
	t.Parallel()
	allowed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()
	denied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	policy := model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: model.SeatbeltDefaultAllow}, Network: model.NetworkPolicy{Mode: model.NetworkAllowlist}}
	allowedPort := allowed.Addr().(*net.TCPAddr).Port
	profile, err := buildProfile(policy, t.TempDir(), allowedPort)
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{allowedPort, denied.Addr().(*net.TCPAddr).Port} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := exec.CommandContext(ctx, sandboxExecPath, "-p", profile, "/usr/bin/nc", "-z", "-w", "1", "127.0.0.1", fmt.Sprint(port)).Run()
		cancel()
		if (err == nil) != (port == allowedPort) {
			t.Fatalf("port=%d error=%v", port, err)
		}
	}
}
