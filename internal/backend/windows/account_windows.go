//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

var (
	procLsaOpenPolicy         = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("LsaOpenPolicy")
	procLsaClose              = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("LsaClose")
	procLsaAddAccountRights   = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("LsaAddAccountRights")
	procLsaNtStatusToWinError = syswindows.NewLazySystemDLL("advapi32.dll").NewProc("LsaNtStatusToWinError")
)

func createLocalUser(ctx context.Context, username, password string) error {
	if username == sandboxUsername && exec.CommandContext(ctx, "net", "user", username).Run() == nil {
		cmd := exec.CommandContext(ctx, "net", "user", username, password, "/active:yes", "/expires:never", "/passwordchg:no")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("update sandbox Windows user: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, "net", "user", username, password, "/add", "/expires:never", "/passwordchg:no")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create sandbox Windows user: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

type localUserInfo struct {
	name, password         *uint16
	passwordAge, privilege uint32
	homeDir, comment       *uint16
	flags                  uint32
	scriptPath             *uint16
}

var netUserAdd = syswindows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserAdd")

func createInvocationLocalUser(username, password string) error {
	name, err := syswindows.UTF16PtrFromString(username)
	if err != nil {
		return err
	}
	secret, err := syswindows.UTF16FromString(password)
	if err != nil {
		return err
	}
	// The API accepts strong passwords without the legacy net.exe confirmation
	// prompt and does not expose the password through a command line.
	const userPrivilege, normalAccount, passwordDoesNotExpire = 1, 0x200, 0x10000
	defer clear(secret)
	info := localUserInfo{name: name, password: &secret[0], privilege: userPrivilege, flags: normalAccount | passwordDoesNotExpire}
	var parameter uint32
	status, _, _ := netUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(info)
	if status != 0 {
		return fmt.Errorf("create invocation Windows user (parameter %d): %w", parameter, syscall.Errno(status))
	}
	return nil
}

var deleteUserProfile = syswindows.NewLazySystemDLL("userenv.dll").NewProc("DeleteProfileW")

func deleteInvocationProfile(sid string) error {
	value, err := syswindows.UTF16PtrFromString(sid)
	if err != nil {
		return err
	}
	ok, _, callErr := deleteUserProfile.Call(uintptr(unsafe.Pointer(value)), 0, 0)
	runtime.KeepAlive(value)
	if ok != 0 || callErr == syswindows.ERROR_FILE_NOT_FOUND || callErr == syswindows.ERROR_PATH_NOT_FOUND {
		return nil
	}
	return fmt.Errorf("remove invocation Windows user profile: %w", callErr)
}

func deleteInvocationLocalUser(ctx context.Context, username string) error {
	cmd := exec.CommandContext(ctx, "net", "user", username, "/delete")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete invocation Windows user: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func localUserExists(ctx context.Context, username string) bool {
	return exec.CommandContext(ctx, "net", "user", username).Run() == nil
}

func disableLocalUser(ctx context.Context, username string) error {
	cmd := exec.CommandContext(ctx, "net", "user", username, "/active:no")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("disable sandbox Windows user: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func windowsServiceStatus(ctx context.Context, name string) (string, error) {
	script := fmt.Sprintf("(Get-Service -Name '%s' -ErrorAction Stop).Status.ToString()", escapePowerShellSingleQuoted(name))
	out, err := powerShellOutput(ctx, script)
	if err != nil {
		return "", fmt.Errorf("check Windows service %q: %w", name, err)
	}
	return strings.TrimSpace(out), nil
}

func powerShellOutput(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func lookupSID(username string) (*syswindows.SID, string, error) {
	sid, _, typ, err := syswindows.LookupSID("", username)
	if err != nil {
		return nil, "", err
	}
	if typ != syswindows.SidTypeUser {
		return nil, "", fmt.Errorf("temporary account %q resolved to SID type %d", username, typ)
	}
	return sid, sid.String(), nil
}

func addOfflineFirewallRule(ctx context.Context, ruleName, sid string) error {
	localUserSDDL := "D:(A;;CC;;;" + sid + ")"
	script := fmt.Sprintf(
		"New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -LocalUser '%s' | Out-Null",
		escapePowerShellSingleQuoted(ruleName), escapePowerShellSingleQuoted(localUserSDDL),
	)
	if out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput(); err != nil {
		return fmt.Errorf("create offline firewall rule: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeFirewallRule(ctx context.Context, ruleName string) error {
	script := fmt.Sprintf("Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue", escapePowerShellSingleQuoted(ruleName))
	if out, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script).CombinedOutput(); err != nil {
		return fmt.Errorf("remove offline firewall rule: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func newLocalCredential() (string, string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	return sandboxUsername, "Sbx!" + hex.EncodeToString(randomBytes[:4]) + "9", nil
}

func newInvocationLocalCredential() (string, string, error) {
	var randomBytes [24]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", "", err
	}
	// SAM local account names are limited to 20 characters.
	return "sbx-" + hex.EncodeToString(randomBytes[:8]), "Sbx!" + hex.EncodeToString(randomBytes[8:]) + "9", nil
}

func newCapabilitySID() (*syswindows.SID, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, err
	}
	return syswindows.StringToSid(fmt.Sprintf("S-1-5-21-%d-%d-%d-%d",
		binary.LittleEndian.Uint32(randomBytes[0:4]), binary.LittleEndian.Uint32(randomBytes[4:8]),
		binary.LittleEndian.Uint32(randomBytes[8:12]), binary.LittleEndian.Uint32(randomBytes[12:16])))
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func grantAccountRight(sid *syswindows.SID, right string) error {
	policy, err := openLsaPolicy(policyCreateAccount | policyLookupNames)
	if err != nil {
		return err
	}
	defer closeLsaPolicy(policy)
	right16, lsaRight, err := lsaRightString(right)
	if err != nil {
		return err
	}
	status, _, _ := procLsaAddAccountRights.Call(uintptr(policy), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&lsaRight)), 1)
	runtime.KeepAlive(right16)
	if status != 0 {
		return lsaStatusError(status)
	}
	return nil
}

func openLsaPolicy(access uint32) (syswindows.Handle, error) {
	attrs := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var policy syswindows.Handle
	status, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs)), uintptr(access), uintptr(unsafe.Pointer(&policy)))
	if status != 0 {
		return 0, lsaStatusError(status)
	}
	return policy, nil
}

func closeLsaPolicy(policy syswindows.Handle) {
	if policy != 0 {
		_, _, _ = procLsaClose.Call(uintptr(policy))
	}
}

func lsaRightString(right string) ([]uint16, lsaUnicodeString, error) {
	right16, err := syswindows.UTF16FromString(right)
	if err != nil {
		return nil, lsaUnicodeString{}, err
	}
	return right16, lsaUnicodeString{Length: uint16((len(right16) - 1) * 2), MaximumLength: uint16(len(right16) * 2), Buffer: &right16[0]}, nil
}

func lsaStatusError(status uintptr) error {
	winErr, _, _ := procLsaNtStatusToWinError.Call(status)
	if winErr != 0 {
		return syscall.Errno(winErr)
	}
	return syscall.Errno(status)
}
