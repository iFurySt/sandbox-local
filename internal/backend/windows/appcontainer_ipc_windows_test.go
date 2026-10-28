//go:build windows

package windows

import (
	"fmt"
	"os"
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
	w "golang.org/x/sys/windows"
)

func localPipeProbe() int {
	name := fmt.Sprintf(`\\.\pipe\LOCAL\sandbox-local-test-%d`, os.Getpid())
	wide, err := w.UTF16PtrFromString(name)
	if err != nil {
		return 1
	}
	server, err := w.CreateNamedPipe(wide, w.PIPE_ACCESS_DUPLEX|w.FILE_FLAG_OVERLAPPED, w.PIPE_TYPE_BYTE, 1, 4096, 4096, 1000, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer w.CloseHandle(server)
	client, err := w.CreateFile(wide, w.GENERIC_READ|w.GENERIC_WRITE, 0, nil, w.OPEN_EXISTING, 0, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer w.CloseHandle(client)
	fmt.Println("LOCAL_PIPE_CONNECTED")
	return 0
}

func TestAppContainerLocalNamedPipe(t *testing.T) {
	workspace := t.TempDir()
	exe := ownedTestExecutable(t, workspace)
	output, err := appContainerCommand(t, workspace, model.Policy{}, []string{exe, "--sandbox-test-pipe"})
	if err != nil || output != "LOCAL_PIPE_CONNECTED\n" {
		t.Fatalf("local named pipe failed: %v, %s", err, output)
	}
}
