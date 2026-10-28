//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	syswindows "golang.org/x/sys/windows"
)

// ACL inheritance can update descendants, so all ACL edits for the same
// desktop user share a cross-process lock, including across Windows sessions.
// File locks are handle-owned and do not pin a Go goroutine to an OS thread.
func lockAppContainerACL(ctx context.Context) (func() error, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(cache, "sandbox-local")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, "appcontainer-acl.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	handle := syswindows.Handle(file.Fd())
	overlapped := &syswindows.Overlapped{}
	for {
		err := syswindows.LockFileEx(handle, syswindows.LOCKFILE_EXCLUSIVE_LOCK|syswindows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, overlapped)
		if err == nil {
			return func() error {
				return errors.Join(syswindows.UnlockFileEx(handle, 0, 1, 0, overlapped), file.Close())
			}, nil
		}
		if !errors.Is(err, syswindows.ERROR_LOCK_VIOLATION) {
			return nil, errors.Join(fmt.Errorf("lock AppContainer ACL updates: %w", err), file.Close())
		}
		select {
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), file.Close())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
