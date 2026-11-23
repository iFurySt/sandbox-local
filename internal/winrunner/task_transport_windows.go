//go:build windows

package winrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

const TaskDirectoryEnvironment = "SANDBOX_LOCAL_WINDOWS_TASK_DIRECTORY"

// TaskTransport is owned by the host backend, so cancellation of its helper
// cannot skip IPC cleanup.
type TaskTransport struct{ Directory string }

func NewTaskTransport(user, domain, capability string) (*TaskTransport, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	directory, err := newTaskDirectory(user, domain, capability, id)
	if err != nil {
		return nil, err
	}
	return &TaskTransport{Directory: directory}, nil
}

func (t *TaskTransport) Cleanup(ctx context.Context) error {
	return removeTaskDirectory(ctx, t.Directory)
}

// Cancel asks the controller helper to stop the broker and its owned processes before
// host cleanup. The protected directory prevents command-originated signals.
func (t *TaskTransport) Cancel() error {
	return os.WriteFile(filepath.Join(t.Directory, "cancel"), nil, 0600)
}

func taskContext(parent context.Context, directory string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := os.Stat(filepath.Join(directory, "cancel")); err == nil {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// Task termination is asynchronous. Completion/stdin handles can briefly deny
// deletion even after the controller ends the job. Retry only these
// transient filesystem failures; never hide a persistent cleanup failure.
func removeTaskDirectory(ctx context.Context, directory string) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := os.RemoveAll(directory)
		if err == nil {
			return nil
		}
		transient := errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_DIR_NOT_EMPTY)
		if !transient || !time.Now().Before(deadline) {
			return err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
}
