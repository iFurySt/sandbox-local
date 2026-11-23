package winrunner

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	profileFreeLogon = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateProcessWithLogonW")
	stationDLL       = windows.NewLazySystemDLL("user32.dll")
	stationCreate    = stationDLL.NewProc("CreateWindowStationW")
	stationSet       = stationDLL.NewProc("SetProcessWindowStation")
	stationClose     = stationDLL.NewProc("CloseWindowStation")
	desktopCreate    = stationDLL.NewProc("CreateDesktopW")
	desktopSet       = stationDLL.NewProc("SetThreadDesktop")
	desktopClose     = stationDLL.NewProc("CloseDesktop")
)

// withProfileFreeBroker is called only in the single-invocation controller
// process. Switching its window station never changes the host's shared station.
func withProfileFreeBroker(user, domain, password, helper, directory string, run func(windows.ProcessInformation) error) (resultErr error) {
	var child windows.ProcessInformation
	account := domain + `\` + user
	if domain == "." {
		account = user
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("look up Windows broker account: %w", err)
	}
	user16, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	domain16, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return err
	}
	password16, err := windows.UTF16FromString(password)
	if err != nil {
		return err
	}
	defer clear(password16)
	helper16, err := windows.UTF16PtrFromString(helper)
	if err != nil {
		return err
	}
	dir16, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return err
	}
	argv, err := windows.UTF16FromString(windows.ComposeCommandLine([]string{helper,
		"__sandbox-local-helper", "__windows-task-broker", directory}))
	if err != nil {
		return err
	}
	// A broker must not inherit controller credentials or host-only variables.
	// With no token and inheritExisting=false Windows builds only the system
	// environment. Request variables are applied from the protected IPC file.
	var environment *uint16
	if err := windows.CreateEnvironmentBlock(&environment, 0, false); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, windows.DestroyEnvironmentBlock(environment)) }()
	err = withPrivateBrokerDesktop(sid, func(desktop *uint16) error {
		startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
		// Zero logon flags are intentional: the child must not load a user profile.
		ok, _, callErr := profileFreeLogon.Call(uintptr(unsafe.Pointer(user16)), uintptr(unsafe.Pointer(domain16)),
			uintptr(unsafe.Pointer(&password16[0])), 0, uintptr(unsafe.Pointer(helper16)), uintptr(unsafe.Pointer(&argv[0])),
			windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT, uintptr(unsafe.Pointer(environment)), uintptr(unsafe.Pointer(dir16)),
			uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&child)))
		runtime.KeepAlive(startup)
		if ok == 0 {
			return fmt.Errorf("launch Windows broker without loading a profile: %w", callErr)
		}
		return run(child)
	})
	return err
}

func withPrivateBrokerDesktop(sid *windows.SID, run func(*uint16) error) (resultErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	caller, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + caller.User.Sid.String() + ")(A;;GA;;;" + sid.String() + ")")
	if err != nil {
		return err
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	id, err := randomID()
	if err != nil {
		return err
	}
	name := "sandbox-local-" + id
	wide, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	previous, _, callErr := procGetProcessWindowStation.Call()
	if previous == 0 {
		return fmt.Errorf("get previous Windows station: %w", callErr)
	}
	previousDesktop, _, callErr := procGetThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	if previousDesktop == 0 {
		return fmt.Errorf("get previous Windows desktop: %w", callErr)
	}
	station, _, callErr := stationCreate.Call(uintptr(unsafe.Pointer(wide)), 0, 0x000f037f, uintptr(unsafe.Pointer(&security)))
	if station == 0 {
		return fmt.Errorf("create private Windows station: %w", callErr)
	}
	defer func() { resultErr = errors.Join(resultErr, closeUserObject(stationClose, station)) }()
	if ok, _, callErr := stationSet.Call(station); ok == 0 {
		return fmt.Errorf("select private Windows station: %w", callErr)
	}
	defer func() { resultErr = errors.Join(resultErr, closeUserObject(stationSet, previous)) }()
	const deskName = "Job"
	wideDesk, err := windows.UTF16PtrFromString(deskName)
	if err != nil {
		return err
	}
	desk, _, callErr := desktopCreate.Call(uintptr(unsafe.Pointer(wideDesk)), 0, 0, 0, 0x000f01ff, uintptr(unsafe.Pointer(&security)))
	runtime.KeepAlive(security)
	if desk == 0 {
		return fmt.Errorf("create private Windows desktop: %w", callErr)
	}
	defer func() {
		resultErr = errors.Join(resultErr, closeUserObject(desktopSet, previousDesktop), closeUserObject(desktopClose, desk))
	}()
	path, err := windows.UTF16PtrFromString(name + `\` + deskName)
	if err != nil {
		return err
	}
	return run(path)
}

func closeUserObject(proc *windows.LazyProc, handle uintptr) error {
	if ok, _, err := proc.Call(handle); ok == 0 {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}
	return nil
}
