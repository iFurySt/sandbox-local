//go:build windows

package windows

import (
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	syswindows "golang.org/x/sys/windows"
)

// metadataAncestors excludes explicit policy roots: those keep their own
// inheritable allow/deny rules. Ancestors need only directory metadata for
// runtimes such as Node to resolve an allowed script's real path.
func metadataAncestors(plans []aclPlan) []string {
	explicit := make(map[string]bool, len(plans))
	for _, plan := range plans {
		explicit[strings.ToLower(plan.path)] = true
	}
	seen := make(map[string]bool)
	var paths []string
	for _, plan := range plans {
		if plan.mode != syswindows.GRANT_ACCESS {
			continue
		}
		for path := filepath.Dir(plan.path); filepath.Dir(path) != path; path = filepath.Dir(path) {
			key := strings.ToLower(path)
			if !explicit[key] && !seen[key] {
				seen[key] = true
				paths = append(paths, path)
			}
		}
	}
	slices.Sort(paths)
	return paths
}

func setPathDACL(path string, acl *syswindows.ACL, localOnly bool) (resultErr error) {
	if !localOnly {
		return syswindows.SetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	name, err := syswindows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Use the native single-object setter: the high-level Win32 setters can
	// reprocess every descendant's inherited ACL even for a local-only ACE.
	// Security-only access also avoids data/delete sharing conflicts on an
	// active profile directory. Preserve the original DACL control flags.
	handle, err := syswindows.CreateFile(name, syswindows.READ_CONTROL|syswindows.WRITE_DAC,
		syswindows.FILE_SHARE_READ|syswindows.FILE_SHARE_WRITE|syswindows.FILE_SHARE_DELETE,
		nil, syswindows.OPEN_EXISTING, syswindows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, syswindows.CloseHandle(handle)) }()
	sd, err := syswindows.GetSecurityInfo(handle, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	absolute, err := sd.ToAbsolute()
	if err != nil {
		return err
	}
	if err := absolute.SetDACL(acl, true, false); err != nil {
		return err
	}
	control, _, err := absolute.Control()
	if err != nil {
		return err
	}
	if control&syswindows.SE_DACL_AUTO_INHERITED != 0 {
		// The native setter requires the set-only request bit to retain AI.
		if err := absolute.SetControl(syswindows.SE_DACL_AUTO_INHERIT_REQ, syswindows.SE_DACL_AUTO_INHERIT_REQ); err != nil {
			return err
		}
	}
	status, _, _ := ntSetSecurityObject.Call(uintptr(handle), uintptr(syswindows.DACL_SECURITY_INFORMATION), uintptr(unsafe.Pointer(absolute)))
	runtime.KeepAlive(absolute)
	runtime.KeepAlive(acl)
	if status != 0 {
		return syswindows.NTStatus(status).Errno()
	}
	return nil
}

var ntSetSecurityObject = syswindows.NewLazySystemDLL("ntdll.dll").NewProc("NtSetSecurityObject")
