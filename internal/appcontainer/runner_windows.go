//go:build windows

package appcontainer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type securityCapabilities struct {
	SID          *windows.SID
	Capabilities *windows.SIDAndAttributes
	Count        uint32
	Reserved     uint32
}

func Run(ctx context.Context, command []string) error {
	if len(command) == 0 {
		return errors.New("AppContainer command is required")
	}
	var config Config
	if err := json.Unmarshal([]byte(os.Getenv(Environment)), &config); err != nil {
		return fmt.Errorf("decode AppContainer configuration: %w", err)
	}
	// The contained process cannot reuse the controller's configuration.
	if err := os.Unsetenv(Environment); err != nil {
		return err
	}
	sid, err := windows.StringToSid(config.SID)
	if err != nil || !sid.IsValid() {
		return errors.New("AppContainer SID is invalid")
	}
	app, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	appWide, err := windows.UTF16PtrFromString(app)
	if err != nil {
		return err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(command))
	if err != nil {
		return err
	}
	desktop, closeDesktop, err := privateDesktop(sid)
	if err != nil {
		return err
	}
	defer closeDesktop()

	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return err
	}
	defer attributes.Delete()
	capabilities := securityCapabilities{SID: sid}
	var network []windows.SIDAndAttributes
	if config.NetworkOpen {
		for _, value := range []string{"S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"} {
			capability, err := windows.StringToSid(value)
			if err != nil {
				return err
			}
			network = append(network, windows.SIDAndAttributes{Sid: capability, Attributes: windows.SE_GROUP_ENABLED})
		}
		capabilities.Capabilities, capabilities.Count = &network[0], uint32(len(network))
	}
	const securityCapabilitiesAttribute = 0x00020009
	if err := attributes.Update(securityCapabilitiesAttribute, unsafe.Pointer(&capabilities), unsafe.Sizeof(capabilities)); err != nil {
		return err
	}
	stdio, err := newPipeStdio(sid)
	if err != nil {
		return err
	}
	defer stdio.close()
	handles := make([]windows.Handle, len(stdio.child))
	for i, file := range stdio.child {
		handles[i] = windows.Handle(file.Fd())
		if err := windows.SetHandleInformation(handles[i], windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
			return err
		}
	}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	// The controller owns the only job handle. Its termination also kills
	// descendants when the host cancels by killing this helper process.
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_READCLIPBOARD |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_DESKTOP}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		return err
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Desktop: desktop,
			Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var process windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)
	token, err := denyToken(config.DenySID, config.SID)
	if err != nil {
		return err
	}
	defer token.Close()
	security, err := objectSecurity(sid)
	if err != nil {
		return err
	}
	if err := windows.CreateProcessAsUser(token, appWide, line, security, security, true, flags, nil, nil, &startup.StartupInfo, &process); err != nil {
		return fmt.Errorf("start AppContainer process: %w", err)
	}
	stdio.closeChild()
	defer windows.CloseHandle(process.Thread)
	defer windows.CloseHandle(process.Process)
	if err := windows.AssignProcessToJobObject(job, process.Process); err != nil {
		return errors.Join(err, windows.TerminateProcess(process.Process, 1))
	}
	if _, err := windows.ResumeThread(process.Thread); err != nil {
		return err
	}
	runtime.KeepAlive(network)
	for {
		state, err := windows.WaitForSingleObject(process.Process, 50)
		if err != nil {
			return err
		}
		if state == windows.WAIT_OBJECT_0 {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	var code uint32
	if err := windows.GetExitCodeProcess(process.Process, &code); err != nil {
		return err
	}
	if err := windows.TerminateJobObject(job, 1); err != nil {
		return err
	}
	if err := stdio.wait(); err != nil {
		return err
	}
	if code == 0xc0000142 {
		return errors.New("AppContainer command could not initialize Windows DLLs; PowerShell and other USER32 workloads require an interactive user session")
	}
	if code != 0 {
		return ExitCodeError{Code: int(code)}
	}
	return nil
}

var user32 = windows.NewLazySystemDLL("user32.dll")

func privateDesktop(sid *windows.SID) (*uint16, func(), error) {
	if err := user32.Load(); err != nil {
		return nil, nil, fmt.Errorf("initialize Windows desktop APIs; use an interactive user session: %w", err)
	}
	station, _, err := user32.NewProc("GetProcessWindowStation").Call()
	if station == 0 {
		return nil, nil, fmt.Errorf("get Windows window station: %w", err)
	}
	var needed uint32
	name := make([]uint16, 512)
	ok, _, err := user32.NewProc("GetUserObjectInformationW").Call(station, 2, uintptr(unsafe.Pointer(&name[0])),
		uintptr(len(name)*2), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return nil, nil, fmt.Errorf("get Windows window station name: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;" + user.User.Sid.String() +
		")(A;;GA;;;" + sid.String() + ")S:(ML;;NW;;;LW)")
	if err != nil {
		return nil, nil, err
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	desktopName := fmt.Sprintf("sandbox-local-%d-%d", os.Getpid(), time.Now().UnixNano())
	wide, err := windows.UTF16PtrFromString(desktopName)
	if err != nil {
		return nil, nil, err
	}
	desktop, _, err := user32.NewProc("CreateDesktopW").Call(uintptr(unsafe.Pointer(wide)), 0, 0, 0,
		0x000f01ff, uintptr(unsafe.Pointer(&security)))
	if desktop == 0 {
		return nil, nil, fmt.Errorf("create private AppContainer desktop: %w", err)
	}
	path, err := windows.UTF16PtrFromString(windows.UTF16ToString(name) + `\` + desktopName)
	if err != nil {
		user32.NewProc("CloseDesktop").Call(desktop)
		return nil, nil, err
	}
	return path, func() { user32.NewProc("CloseDesktop").Call(desktop) }, nil
}
