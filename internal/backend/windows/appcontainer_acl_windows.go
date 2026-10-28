//go:build windows

package windows

import (
	"errors"
	"fmt"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

// SetEntriesInAcl(REVOKE_ACCESS) only removes allow ACEs. Cleanup must also
// remove the ordinary deny SID, preserving opaque ACEs owned by other actors.
func removeInvocationACE(old *syswindows.ACL, sid *syswindows.SID) (*syswindows.ACL, error) {
	if old == nil {
		return nil, errors.New("AppContainer resource has no DACL")
	}
	header := (*struct {
		Revision  uint8
		Reserved  uint8
		Size      uint16
		Count     uint16
		Reserved2 uint16
	})(unsafe.Pointer(old))
	data := make([]byte, int(header.Size))
	acl := (*syswindows.ACL)(unsafe.Pointer(&data[0]))
	advapi := syswindows.NewLazySystemDLL("advapi32.dll")
	ok, _, callErr := advapi.NewProc("InitializeAcl").Call(uintptr(unsafe.Pointer(acl)), uintptr(len(data)), uintptr(header.Revision))
	if ok == 0 {
		return nil, fmt.Errorf("initialize AppContainer cleanup ACL: %w", callErr)
	}
	for i := uint16(0); i < old.AceCount; i++ {
		var ace *syswindows.ACCESS_ALLOWED_ACE
		ok, _, callErr = advapi.NewProc("GetAce").Call(uintptr(unsafe.Pointer(old)), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 {
			return nil, fmt.Errorf("read AppContainer cleanup ACE: %w", callErr)
		}
		if ace.Header.AceType == syswindows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceType == syswindows.ACCESS_DENIED_ACE_TYPE {
			entrySID := (*syswindows.SID)(unsafe.Pointer(&ace.SidStart))
			if entrySID.Equals(sid) {
				continue
			}
		}
		ok, _, callErr = advapi.NewProc("AddAce").Call(uintptr(unsafe.Pointer(acl)), uintptr(header.Revision),
			0xffffffff, uintptr(unsafe.Pointer(ace)), uintptr(ace.Header.AceSize))
		if ok == 0 {
			return nil, fmt.Errorf("preserve unrelated ACL entry: %w", callErr)
		}
	}
	return acl, nil
}
