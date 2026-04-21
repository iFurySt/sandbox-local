//go:build !linux

package linuxbridge

import (
	"context"
	"errors"
)

func Run(context.Context, string, string, []string) error {
	return errors.New("linux proxy bridge is only available on Linux")
}

func ExecWithSeccomp([]string) error {
	return errors.New("seccomp exec wrapper is only available on Linux")
}
