package backend

import (
	"context"
	"runtime"

	"github.com/iFurySt/sandbox-local/internal/model"
)

type noopBackend struct{}

func NewNoopBackend() Backend {
	return noopBackend{}
}

func (noopBackend) Name() string {
	return "noop"
}

func (noopBackend) Platform() string {
	return runtime.GOOS
}

func (b noopBackend) Check(context.Context) model.CapabilityReport {
	return model.CapabilityReport{
		Backend:      b.Name(),
		Platform:     b.Platform(),
		Available:    true,
		Sandboxed:    false,
		NetworkModes: []string{string(model.NetworkOpen), string(model.NetworkOffline), string(model.NetworkAllowlist)},
		Warnings:     []string{"noop backend does not enforce sandbox policy"},
	}
}

func (b noopBackend) Prepare(_ context.Context, req model.Request) (model.PreparedCommand, model.Cleanup, error) {
	return model.PreparedCommand{
		Backend:  b.Name(),
		Platform: b.Platform(),
		Command:  append([]string(nil), req.Command...),
		Cwd:      req.Cwd,
		Env:      cloneMap(req.Env),
		Warnings: []string{"noop backend selected; command will run without OS sandboxing"},
	}, nil, nil
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
