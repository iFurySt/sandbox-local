//go:build windows

package winrunner

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

func restrictedJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, errors.Join(err, windows.CloseHandle(job))
	}
	return job, nil
}

// Normal foreground completion must not terminate detached background work.
// Cancellation keeps KILL_ON_JOB_CLOSE armed until the broker is terminated.
func releaseBackgroundJob(job windows.Handle) error {
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	_, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	return err
}
