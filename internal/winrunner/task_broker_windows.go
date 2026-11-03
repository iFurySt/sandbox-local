//go:build windows

package winrunner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/windows"
)

type taskConfig struct {
	Cwd     string
	Command []string
	Env     map[string]string
}

type taskDefinition struct {
	XMLName   xml.Name `xml:"Task"`
	Version   string   `xml:"version,attr"`
	Namespace string   `xml:"xmlns,attr"`
	Settings  taskSettings
	Actions   taskActions
}
type taskSettings struct {
	ExecutionTimeLimit         string
	AllowHardTerminate         bool
	DisallowStartIfOnBatteries bool
	StopIfGoingOnBatteries     bool
}
type taskActions struct{ Exec taskAction }
type taskAction struct{ Command, Arguments string }

// RunTaskBroker executes inside the scheduled task, before token restriction.
// Only this trusted process can open the IPC files for writing; the command
// inherits stdio handles without receiving write access to the control files.
func RunTaskBroker(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return errors.New("Windows task broker requires its private directory")
	}
	directory := args[0]
	code, err := runTaskCommand(ctx, directory)
	if err != nil {
		if writeErr := os.WriteFile(filepath.Join(directory, "failure.txt"), []byte(err.Error()), 0600); writeErr != nil {
			return errors.Join(err, writeErr)
		}
	}
	return os.WriteFile(filepath.Join(directory, "exit.txt"), []byte(strconv.Itoa(code)), 0600)
}

func runTaskCommand(ctx context.Context, directory string) (int, error) {
	raw, err := os.ReadFile(filepath.Join(directory, "request.json"))
	if err != nil {
		return -1, err
	}
	var config taskConfig
	if err := json.Unmarshal(raw, &config); err != nil {
		return -1, err
	}
	if err := os.Chdir(config.Cwd); err != nil {
		return -1, err
	}
	for key, value := range config.Env {
		if err := os.Setenv(key, value); err != nil {
			return -1, err
		}
	}
	input, err := os.Open(filepath.Join(directory, "stdin.bin"))
	if err != nil {
		return -1, err
	}
	defer input.Close()
	output, err := taskOutput(filepath.Join(directory, "stdout.bin"))
	if err != nil {
		return -1, err
	}
	defer output.Close()
	errOutput, err := taskOutput(filepath.Join(directory, "stderr.bin"))
	if err != nil {
		return -1, err
	}
	defer errOutput.Close()
	os.Stdin, os.Stdout, os.Stderr = input, output, errOutput
	err = RunRestricted(ctx, config.Command)
	var exitErr ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Code, nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

func taskOutput(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.CREATE_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("open task output: %w", err)
	}
	// The restricted child inherits only these already-authorized stdio handles.
	if err := windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		return nil, errors.Join(err, windows.CloseHandle(handle))
	}
	return os.NewFile(uintptr(handle), path), nil
}
