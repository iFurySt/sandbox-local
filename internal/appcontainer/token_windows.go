//go:build windows

package appcontainer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// AppContainer's package-SID access check ignores deny ACEs. Retain the
// caller's ordinary DAC checks in a restricted base token and attach a normal
// per-invocation SID for explicit read/write denials.
func denyToken(denySID, packageSID string) (windows.Token, error) {
	var base windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|
		windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &base); err != nil {
		return 0, err
	}
	defer base.Close()
	user, err := base.GetTokenUser()
	if err != nil {
		return 0, err
	}
	groups, err := base.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	sid, err := windows.StringToSid(denySID)
	if err != nil {
		return 0, err
	}
	restricting := []windows.SIDAndAttributes{{Sid: user.User.Sid}, {Sid: sid}}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			restricting = append(restricting, windows.SIDAndAttributes{Sid: group.Sid})
		}
	}
	var token windows.Token
	create := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ok, _, callErr := create.Call(uintptr(base), 1, 0, 0, 0, 0, uintptr(len(restricting)),
		uintptr(unsafe.Pointer(&restricting[0])), uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return 0, fmt.Errorf("create AppContainer deny token: %w", callErr)
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + user.User.Sid.String() + ")(A;;GA;;;SY)(A;;GA;;;" + packageSID + ")")
	if err != nil {
		token.Close()
		return 0, err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		token.Close()
		return 0, err
	}
	defaultACL := struct{ ACL *windows.ACL }{acl}
	if err := windows.SetTokenInformation(token, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&defaultACL)),
		uint32(unsafe.Sizeof(defaultACL))); err != nil {
		token.Close()
		return 0, err
	}
	return token, nil
}

func objectSecurity(sid *windows.SID) (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + user.User.Sid.String() +
		")(A;;GA;;;SY)(A;;GA;;;" + sid.String() + ")S:(ML;;NW;;;LW)")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}
