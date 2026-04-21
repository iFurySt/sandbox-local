//go:build !windows

package winrunner

import (
	"context"
	"fmt"
	"runtime"
)

type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.Code)
}

func Run(context.Context, []string) error {
	return fmt.Errorf("Windows runner is only available on Windows, not %s", runtime.GOOS)
}
