//go:build !windows

package windows

import (
	"context"
	"fmt"
	"runtime"

	"github.com/iFurySt/sandbox-local/internal/model"
)

type Backend struct{}

func New() Backend {
	return Backend{}
}

func (Backend) Name() string {
	return "windows-local-user"
}

func (Backend) Platform() string {
	return runtime.GOOS
}

func (b Backend) Check(context.Context) model.CapabilityReport {
	return model.CapabilityReport{
		Backend:   b.Name(),
		Platform:  b.Platform(),
		Available: false,
		Sandboxed: false,
		Missing:   []string{"windows platform"},
	}
}

func (b Backend) Prepare(context.Context, model.Request) (model.PreparedCommand, model.Cleanup, error) {
	return model.PreparedCommand{}, nil, fmt.Errorf("%s is only available on Windows", b.Name())
}
