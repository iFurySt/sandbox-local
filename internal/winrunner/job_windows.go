//go:build windows

package winrunner

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"time"
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

// terminateAndReapJob preserves policy until all owned processes have stopped.
func terminateAndReapJob(job windows.Handle) error {
	if err := windows.TerminateJobObject(job, 1); err != nil {
		return err
	}
	// JOBOBJECT_BASIC_ACCOUNTING_INFORMATION has four LARGE_INTEGER times
	// followed by four DWORD counters, including ActiveProcesses.
	var info struct {
		totalUser, totalKernel, periodUser, periodKernel             int64
		faults, totalProcesses, activeProcesses, terminatedProcesses uint32
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return err
		}
		if info.activeProcesses == 0 {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("Windows broker job still has %d active processes after termination", info.activeProcesses)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
