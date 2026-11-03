//go:build windows

package winrunner

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

func TestTaskDirectoryRejectsRestrictedMutation(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	const capability = "S-1-5-21-101-202-303-404"
	directory, err := newTaskDirectory(account.Username, ".", capability, "acl-regression")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	script := filepath.Join(directory, "request.json")
	if err := os.WriteFile(script, []byte("trusted bootstrap"), 0600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syswindows.GetNamedSecurityInfo(directory, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil || control&syswindows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("IPC DACL inherits caller policy: control=%#x, error=%v", control, err)
	}
	var base syswindows.Token
	if err := syswindows.OpenProcessToken(syswindows.CurrentProcess(), syswindows.TOKEN_QUERY|syswindows.TOKEN_DUPLICATE|syswindows.TOKEN_ASSIGN_PRIMARY, &base); err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	sid, err := syswindows.StringToSid(capability)
	if err != nil {
		t.Fatal(err)
	}
	// The real bootstrap account is not an administrator. Remove the test
	// caller's administrator grant and privileges before modelling its token;
	// host administrators intentionally retain IPC recovery access.
	admins, err := syswindows.CreateWellKnownSid(syswindows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disabled := syswindows.SIDAndAttributes{Sid: admins}
	var standard syswindows.Token
	ok, _, callErr := procCreateRestrictedToken.Call(uintptr(base), 1,
		1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&standard)))
	if ok == 0 {
		t.Fatalf("model unprivileged bootstrap account: %v", callErr)
	}
	defer standard.Close()
	restricted, err := createWriteRestrictedToken(standard, sid)
	if err != nil {
		t.Fatal(err)
	}
	defer restricted.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	impersonate := syswindows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	ok, _, callErr = impersonate.Call(uintptr(restricted))
	if ok == 0 {
		t.Fatalf("impersonate restricted command: %v", callErr)
	}
	defer func() {
		if err := syswindows.RevertToSelf(); err != nil {
			t.Fatal(err)
		}
	}()
	for name, action := range map[string]func() error{
		"overwrite script": func() error { return os.WriteFile(script, []byte("forged"), 0600) },
		"forge completion": func() error { return os.WriteFile(filepath.Join(directory, "exit.txt"), []byte("0"), 0600) },
		"remove script":    func() error { return os.Remove(script) },
		"rename script":    func() error { return os.Rename(script, filepath.Join(directory, "moved.ps1")) },
	} {
		if err := action(); err == nil {
			t.Errorf("restricted command could %s", name)
		}
	}
}
