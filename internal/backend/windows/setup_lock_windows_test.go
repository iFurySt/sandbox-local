//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	syswindows "golang.org/x/sys/windows"
)

func TestSetupLockCleanupAcrossThreads(t *testing.T) {
	// Keep the acquiring thread occupied so cleanup must run on another one.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	lock, err := acquireSetupLock()
	if err != nil {
		t.Fatal(err)
	}

	name, err := syswindows.UTF16PtrFromString(`Local\sandbox-local-windows-backend`)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := syswindows.OpenMutex(syswindows.SYNCHRONIZE|syswindows.MUTEX_MODIFY_STATE, false, name)
	if err != nil {
		t.Fatal(err)
	}
	defer syswindows.CloseHandle(recovery)

	state := &sandboxState{lock: lock}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		done <- state.Cleanup(context.Background())
	}()
	select {
	case err := <-done:
		if err != nil {
			// Recover the old implementation's ownership before reporting failure.
			_ = syswindows.ReleaseMutex(recovery)
			t.Fatalf("cleanup on another OS thread: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = syswindows.ReleaseMutex(recovery)
		t.Fatal("cleanup on another OS thread did not return")
	}
}

func TestSetupLockWaitsForExistingOwner(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	name := fmt.Sprintf(`Local\sandbox-local-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	wideName, err := syswindows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syswindows.CreateMutex(nil, true, wideName)
	if err != nil {
		t.Fatal(err)
	}
	defer syswindows.CloseHandle(handle)
	owned := true
	defer func() {
		if owned {
			_ = syswindows.ReleaseMutex(handle)
		}
	}()

	acquired := make(chan *setupLock)
	failed := make(chan error, 1)
	go func() {
		lock, err := acquireNamedSetupLock(name)
		if err != nil {
			failed <- err
			return
		}
		acquired <- lock
	}()
	select {
	case lock := <-acquired:
		_ = lock.Close()
		t.Fatal("acquired mutex while its existing owner still held it")
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := syswindows.ReleaseMutex(handle); err != nil {
		t.Fatal(err)
	}
	owned = false
	select {
	case lock := <-acquired:
		if err := lock.Close(); err != nil {
			t.Fatal(err)
		}
	case err := <-failed:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("mutex did not become available after the existing owner released it")
	}
}

func TestSetupLockConcurrentClose(t *testing.T) {
	name := fmt.Sprintf(`Local\sandbox-local-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	lock, err := acquireNamedSetupLock(name)
	if err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for range 16 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := lock.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		}()
	}
	callers.Wait()
	if err := lock.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
}

func TestSetupLockRejectsConflictingObject(t *testing.T) {
	name := fmt.Sprintf(`Local\sandbox-local-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	wideName, err := syswindows.UTF16PtrFromString(name)
	if err != nil {
		t.Fatal(err)
	}
	event, err := syswindows.CreateEvent(nil, 0, 0, wideName)
	if err != nil {
		t.Fatal(err)
	}
	defer syswindows.CloseHandle(event)
	lock, err := acquireNamedSetupLock(name)
	if err == nil {
		_ = lock.Close()
		t.Fatal("accepted an event object as a mutex")
	}
}
