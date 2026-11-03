//go:build windows && integration

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	syswindows "golang.org/x/sys/windows"
)

func TestWindowsPrivateAncestorMetadata(t *testing.T) {
	root := t.TempDir()
	user, err := syswindows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := syswindows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", user.User.Sid.String()))
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := syswindows.SetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION|syswindows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	workdir := filepath.Join(root, "workspace 中文 ' & %")
	if err := os.Mkdir(workdir, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "sibling-secret.txt")
	allowed := filepath.Join(workdir, "allowed.txt")
	for _, path := range []string{secret, allowed} {
		if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	helper, fixture := buildHelper(t, workdir), windowsCommandFixture(t, workdir)
	before, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := sandbox.NewManager(sandbox.Options{HelperPath: helper, Enforcement: sandbox.EnforcementRequire})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, mode := range []sandbox.NetworkMode{sandbox.NetworkOpen, sandbox.NetworkOffline} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			var out, stderr bytes.Buffer
			result, err := manager.Run(ctx, sandbox.Request{Command: []string{fixture, "ancestor-metadata", root, allowed, secret}, Cwd: workdir,
				Policy: sandbox.Policy{Filesystem: sandbox.FilesystemPolicy{ReadAllow: []string{workdir}, WriteDeny: []string{workdir}}, Network: sandbox.NetworkPolicy{Mode: mode}, Process: sandbox.ProcessPolicy{Timeout: 30 * time.Second}},
				Stdio:  sandbox.Stdio{Stdout: &out, Stderr: &stderr}})
			if err != nil || result.ExitCode != 0 || out.String() != "metadata-only" {
				t.Fatalf("result=%+v err=%v stdout=%q stderr=%q", result, err, out.String(), stderr.String())
			}
			after, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			if before.String() != after.String() {
				t.Fatalf("parent ACL not restored: %s -> %s", before.String(), after.String())
			}
		})
	}
}
