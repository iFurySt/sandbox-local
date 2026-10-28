//go:build !windows

package appcontainer

import (
	"context"
	"errors"
)

func Run(context.Context, []string) error {
	return errors.New("AppContainer requires Windows")
}
