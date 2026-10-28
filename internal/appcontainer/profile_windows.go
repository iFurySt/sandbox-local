//go:build windows

package appcontainer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var userenv = windows.NewLazySystemDLL("userenv.dll")

type Profile struct {
	Name string
	SID  *windows.SID
}

func NewProfile() (*Profile, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	name := "sandbox-local." + hex.EncodeToString(id[:])
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := userenv.NewProc("CreateAppContainerProfile").Call(
		uintptr(unsafe.Pointer(wide)), uintptr(unsafe.Pointer(wide)), uintptr(unsafe.Pointer(wide)),
		0, 0, uintptr(unsafe.Pointer(&sid)),
	)
	if hr != 0 {
		return nil, fmt.Errorf("create per-user AppContainer profile: HRESULT 0x%08x", uint32(hr))
	}
	return &Profile{Name: name, SID: sid}, nil
}

func (p *Profile) Close() error {
	wide, err := windows.UTF16PtrFromString(p.Name)
	if err != nil {
		return err
	}
	hr, _, _ := userenv.NewProc("DeleteAppContainerProfile").Call(uintptr(unsafe.Pointer(wide)))
	var deleteErr error
	if hr != 0 {
		deleteErr = fmt.Errorf("delete per-user AppContainer profile: HRESULT 0x%08x", uint32(hr))
	}
	return errors.Join(deleteErr, windows.FreeSid(p.SID))
}

func Available() error {
	return userenv.NewProc("CreateAppContainerProfile").Find()
}
