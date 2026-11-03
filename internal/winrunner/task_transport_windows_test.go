//go:build windows

package winrunner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestTaskCleanupWaitsForClosingIPCHandle(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "exit.txt")
	if err := os.WriteFile(path, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// Broker completion/stdin files are opened without delete sharing. Task
	// termination can return before Windows finishes closing those handles.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { time.Sleep(200 * time.Millisecond); closed <- windows.CloseHandle(handle) }()
	err = (&TaskTransport{Directory: directory}).Cleanup(t.Context())
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatalf("cleanup raced a closing broker handle: %v", err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("IPC directory remains: %v", err)
	}
}

func TestTaskCleanupWaitHonorsCancellation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "stdin.bin")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = (&TaskTransport{Directory: directory}).Cleanup(ctx)
	if closeErr := windows.CloseHandle(handle); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("cleanup error lost its causes: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("cleanup ignored its caller's deadline")
	}
}
