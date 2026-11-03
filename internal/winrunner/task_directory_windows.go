//go:build windows

package winrunner

import (
	"errors"
	"fmt"
	"os"

	syswindows "golang.org/x/sys/windows"
)

// The scheduled-task bootstrap writes IPC before applying the restricted token.
// Its directory must neither inherit the command CWD's deny-write ACL nor allow
// the restricted command to forge the script or completion report.
func newTaskDirectory(user, domain, capability, id string) (_ string, retErr error) {
	account := user
	if domain != "" && domain != "." {
		account = domain + `\` + user
	}
	userSID, _, _, err := syswindows.LookupSID("", account)
	if err != nil {
		return "", fmt.Errorf("resolve scheduled-task account: %w", err)
	}
	capabilitySID, err := syswindows.StringToSid(capability)
	if err != nil {
		return "", fmt.Errorf("resolve scheduled-task write capability: %w", err)
	}
	directory, err := os.MkdirTemp("", ".sandbox-local-win-"+id+"-")
	if err != nil {
		return "", err
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, os.RemoveAll(directory))
		}
	}()
	const mutationRights = syswindows.FILE_WRITE_DATA | syswindows.FILE_APPEND_DATA |
		syswindows.FILE_WRITE_EA | syswindows.FILE_WRITE_ATTRIBUTES | syswindows.DELETE |
		0x40 | syswindows.WRITE_DAC | syswindows.WRITE_OWNER
	sddl := fmt.Sprintf("D:P(D;OICI;0x%x;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x%x;;;%s)",
		mutationRights, capabilitySID.String(),
		syswindows.FILE_GENERIC_READ|syswindows.FILE_GENERIC_WRITE|syswindows.FILE_GENERIC_EXECUTE, userSID.String())
	descriptor, err := syswindows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return "", fmt.Errorf("build scheduled-task IPC ACL: %w", err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return "", err
	}
	if err := syswindows.SetNamedSecurityInfo(directory, syswindows.SE_FILE_OBJECT,
		syswindows.DACL_SECURITY_INFORMATION|syswindows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return "", fmt.Errorf("protect scheduled-task IPC directory: %w", err)
	}
	return directory, nil
}
