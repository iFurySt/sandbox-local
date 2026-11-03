//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	syswindows "golang.org/x/sys/windows"
)

const setupMutexName = `Local\sandbox-local-windows-backend`

type setupLock struct {
	release chan struct{}
	done    chan struct{}
	once    sync.Once
	err     error
}

func acquireSetupLock(ctx context.Context) (*setupLock, error) {
	return acquireNamedSetupLock(ctx, setupMutexName)
}

func acquireNamedSetupLock(ctx context.Context, name string) (*setupLock, error) {
	wideName, err := syswindows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	lock := &setupLock{release: make(chan struct{}), done: make(chan struct{})}
	ready := make(chan error)
	go func() {
		defer close(lock.done)
		// Windows mutex ownership belongs to an OS thread, not a goroutine.
		// Keep both acquisition and release here even if callers move threads.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		handle, err := syswindows.CreateMutex(nil, false, wideName)
		if err != nil && !(errors.Is(err, syswindows.ERROR_ALREADY_EXISTS) && handle != 0) {
			ready <- err
			return
		}
		for {
			if err := ctx.Err(); err != nil {
				ready <- errors.Join(err, syswindows.CloseHandle(handle))
				return
			}
			state, err := syswindows.WaitForSingleObject(handle, 50)
			if err != nil {
				ready <- errors.Join(err, syswindows.CloseHandle(handle))
				return
			}
			if state == uint32(syswindows.WAIT_TIMEOUT) {
				continue
			}
			if state != syswindows.WAIT_OBJECT_0 && state != syswindows.WAIT_ABANDONED {
				ready <- errors.Join(fmt.Errorf("unexpected setup mutex wait result %#x", state), syswindows.CloseHandle(handle))
				return
			}
			break
		}
		if err := ctx.Err(); err != nil {
			ready <- errors.Join(err, syswindows.ReleaseMutex(handle), syswindows.CloseHandle(handle))
			return
		}
		ready <- nil
		<-lock.release
		lock.err = errors.Join(syswindows.ReleaseMutex(handle), syswindows.CloseHandle(handle))
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return lock, nil
}

func (l *setupLock) Close() error {
	l.once.Do(func() { close(l.release) })
	<-l.done
	return l.err
}
