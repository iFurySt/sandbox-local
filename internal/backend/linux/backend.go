package linux

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/iFurySt/sandbox-local/internal/fsx"
	"github.com/iFurySt/sandbox-local/internal/helper"
	"github.com/iFurySt/sandbox-local/internal/model"
)

type Backend struct{}

func New() Backend {
	return Backend{}
}

func (Backend) Name() string {
	return "linux-bwrap"
}

func (Backend) Platform() string {
	return "linux"
}

func (b Backend) Check(context.Context) model.CapabilityReport {
	report := model.CapabilityReport{
		Backend:      b.Name(),
		Platform:     b.Platform(),
		Available:    true,
		Sandboxed:    true,
		NetworkModes: []string{string(model.NetworkOffline), string(model.NetworkAllowlist), string(model.NetworkOpen)},
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		report.Available = false
		report.Sandboxed = false
		report.Missing = append(report.Missing, "bwrap")
	}
	return report
}

func (b Backend) Prepare(_ context.Context, req model.Request) (model.PreparedCommand, model.Cleanup, error) {
	if len(req.Command) == 0 {
		return model.PreparedCommand{}, nil, fmt.Errorf("command is required")
	}
	cwd := req.Cwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return model.PreparedCommand{}, nil, err
		}
	}
	absCwd, err := fsx.Abs(cwd, "")
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	args, warnings, err := buildArgs(req.Policy, absCwd, req.Command, req.ManagedProxyPort, req.ManagedProxySocket, req.HelperPath)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	return model.PreparedCommand{
		Backend:  b.Name(),
		Platform: b.Platform(),
		Command:  append([]string{"bwrap"}, args...),
		Cwd:      absCwd,
		Env:      cloneMap(req.Env),
		Warnings: warnings,
	}, nil, nil
}

func buildArgs(policy model.Policy, cwd string, command []string, managedProxyPort int, managedProxySocket string, helperPath string) ([]string, []string, error) {
	writeAllow, err := fsx.AbsList(policy.Filesystem.WriteAllow, cwd)
	if err != nil {
		return nil, nil, err
	}
	writeDeny, err := fsx.AbsList(policy.Filesystem.WriteDeny, cwd)
	if err != nil {
		return nil, nil, err
	}
	readDeny, err := fsx.AbsList(policy.Filesystem.ReadDeny, cwd)
	if err != nil {
		return nil, nil, err
	}

	args := []string{
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
	}
	if policy.Network.Mode == "" || policy.Network.Mode == model.NetworkOffline || policy.Network.Mode == model.NetworkAllowlist {
		args = append(args, "--unshare-net")
	}
	for _, path := range writeAllow {
		if _, err := os.Stat(path); err != nil {
			return nil, nil, fmt.Errorf("write allow path %q is not available: %w", path, err)
		}
		args = append(args, "--bind", path, path)
	}
	var warnings []string
	for _, path := range writeDeny {
		if _, err := os.Stat(path); err != nil {
			warnings = append(warnings, fmt.Sprintf("write deny path %q does not exist and was not mounted read-only", path))
			continue
		}
		args = append(args, "--ro-bind", path, path)
	}
	for _, path := range readDeny {
		if info, err := os.Stat(path); err == nil {
			if info.IsDir() {
				args = append(args, "--tmpfs", path)
			} else {
				args = append(args, "--bind", "/dev/null", path)
			}
		} else {
			warnings = append(warnings, fmt.Sprintf("read deny path %q does not exist and was not masked", path))
		}
	}
	if policy.Network.Mode == model.NetworkAllowlist {
		if managedProxyPort <= 0 || managedProxySocket == "" {
			return nil, nil, fmt.Errorf("network allowlist requires managed proxy metadata")
		}
		resolvedHelper, err := helper.Resolve(helperPath)
		if err != nil {
			return nil, nil, err
		}
		command = append([]string{
			resolvedHelper,
			"__proxy-bridge",
			"--listen", fmt.Sprintf("127.0.0.1:%d", managedProxyPort),
			"--unix", managedProxySocket,
			"--",
		}, command...)
	}
	args = append(args, "--chdir", cwd, "--")
	args = append(args, command...)
	return args, warnings, nil
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
