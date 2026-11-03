//go:build windows

package winrunner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const TaskDirectoryEnvironment = "SANDBOX_LOCAL_WINDOWS_TASK_DIRECTORY"

// TaskTransport is owned by the host backend, so cancellation of its helper
// cannot skip scheduler and IPC cleanup.
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

func (t *TaskTransport) name() string { return `\sandbox-local-` + filepath.Base(t.Directory) }

func (t *TaskTransport) Cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var errs []error
	taskFile := filepath.Join(os.Getenv("SystemRoot"), "System32", "Tasks", strings.TrimPrefix(t.name(), `\`))
	if _, err := os.Stat(taskFile); err == nil {
		// A completion report commits normal foreground exit. Task Scheduler may
		// still be retiring its action; stopping it here would kill background work.
		completedReport := false
		if raw, err := os.ReadFile(filepath.Join(t.Directory, "exit.txt")); err == nil {
			_, ready, parseErr := parseTaskExit(raw)
			completedReport = ready && parseErr == nil
			if parseErr != nil {
				errs = append(errs, parseErr)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
		_, cancelErr := os.Stat(filepath.Join(t.Directory, "cancel"))
		if !completedReport || cancelErr == nil {
			completed, _, err := scheduledTaskCompleted(ctx, t.name())
			if err != nil {
				errs = append(errs, err)
			} else if !completed {
				if out, err := exec.CommandContext(ctx, "schtasks.exe", "/End", "/TN", t.name()).CombinedOutput(); err != nil {
					errs = append(errs, fmt.Errorf("end scheduled task: %w: %s", err, strings.TrimSpace(string(out))))
				}
			}
		}
		if err := deleteTask(ctx, t.name()); err != nil {
			errs = append(errs, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	errs = append(errs, os.RemoveAll(t.Directory))
	return errors.Join(errs...)
}

// Cancel asks the controller helper to stop its scheduler operations before
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
