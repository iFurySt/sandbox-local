package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	"github.com/iFurySt/sandbox-local/internal/backend"
	"github.com/iFurySt/sandbox-local/internal/model"
	netproxy "github.com/iFurySt/sandbox-local/internal/network"
)

type Manager struct {
	opts model.Options
}

func NewManager(opts model.Options) *Manager {
	if opts.BackendPreference == "" {
		opts.BackendPreference = model.BackendAuto
	}
	if opts.Enforcement == "" {
		opts.Enforcement = model.EnforcementRequire
	}
	return &Manager{opts: opts}
}

func (m *Manager) Check(ctx context.Context) (model.CapabilityReport, error) {
	_, report, err := backend.Select(ctx, m.opts.BackendPreference, m.opts.Enforcement)
	if err != nil {
		return report, nil
	}
	return report, nil
}

func (m *Manager) Prepare(ctx context.Context, req model.Request) (model.Plan, error) {
	req, err := normalizeRequest(req)
	if err != nil {
		return model.Plan{}, err
	}
	selected, report, err := backend.Select(ctx, m.opts.BackendPreference, m.opts.Enforcement)
	if err != nil {
		return model.Plan{
			Backend:           report.Backend,
			Platform:          report.Platform,
			Cwd:               req.Cwd,
			CapabilityReport:  report,
			EffectivePolicy:   summarizePolicy(req.Policy),
			Enforcement:       m.opts.Enforcement,
			BackendPreference: m.opts.BackendPreference,
		}, err
	}
	networkCleanup, err := m.prepareManagedNetwork(ctx, &req, report)
	if err != nil {
		return model.Plan{
			Backend:           selected.Name(),
			Platform:          selected.Platform(),
			Cwd:               req.Cwd,
			CapabilityReport:  report,
			EffectivePolicy:   summarizePolicy(req.Policy),
			Enforcement:       m.opts.Enforcement,
			BackendPreference: m.opts.BackendPreference,
		}, err
	}
	if networkCleanup != nil {
		defer networkCleanup(ctx)
	}
	prepared, backendCleanup, err := selected.Prepare(ctx, req)
	if backendCleanup != nil {
		_ = backendCleanup(ctx)
	}
	if err != nil {
		return model.Plan{
			Backend:           selected.Name(),
			Platform:          selected.Platform(),
			Cwd:               req.Cwd,
			CapabilityReport:  report,
			EffectivePolicy:   summarizePolicy(req.Policy),
			Enforcement:       m.opts.Enforcement,
			BackendPreference: m.opts.BackendPreference,
		}, err
	}
	return model.Plan{
		Backend:           prepared.Backend,
		Platform:          prepared.Platform,
		Command:           prepared.Command,
		Cwd:               prepared.Cwd,
		Env:               prepared.Env,
		Warnings:          prepared.Warnings,
		CapabilityReport:  report,
		EffectivePolicy:   summarizePolicy(req.Policy),
		Enforcement:       m.opts.Enforcement,
		BackendPreference: m.opts.BackendPreference,
	}, nil
}

func (m *Manager) Run(ctx context.Context, req model.Request) (model.Result, error) {
	req, err := normalizeRequest(req)
	if err != nil {
		return model.Result{}, err
	}
	runCtx := ctx
	cancel := func() {}
	if req.Policy.Process.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, req.Policy.Process.Timeout)
	}
	defer cancel()

	selected, report, err := backend.Select(runCtx, m.opts.BackendPreference, m.opts.Enforcement)
	if err != nil {
		return model.Result{}, err
	}
	networkCleanup, err := m.prepareManagedNetwork(runCtx, &req, report)
	if err != nil {
		return model.Result{}, err
	}
	if networkCleanup != nil {
		defer networkCleanup(context.Background())
	}
	prepared, backendCleanup, err := selected.Prepare(runCtx, req)
	if backendCleanup != nil {
		defer backendCleanup(context.Background())
	}
	if err != nil {
		return model.Result{}, err
	}
	if len(prepared.Command) == 0 {
		return model.Result{}, errors.New("prepared command is empty")
	}
	m.emit(runCtx, model.Event{Type: "backend_selected", Backend: prepared.Backend})
	cmd := exec.CommandContext(runCtx, prepared.Command[0], prepared.Command[1:]...)
	cmd.Dir = prepared.Cwd
	cmd.Env = mergeEnv(os.Environ(), prepared.Env)
	cmd.Stdin = req.Stdio.Stdin
	cmd.Stdout = req.Stdio.Stdout
	cmd.Stderr = req.Stdio.Stderr
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return model.Result{ExitCode: -1, Backend: prepared.Backend}, err
		}
	}
	if runCtx.Err() != nil {
		return model.Result{ExitCode: exitCode, Backend: prepared.Backend}, runCtx.Err()
	}
	m.emit(ctx, model.Event{Type: "process_exited", Backend: prepared.Backend, Message: fmt.Sprintf("exit_code=%d", exitCode)})
	return model.Result{ExitCode: exitCode, Backend: prepared.Backend}, nil
}

func (m *Manager) Close() error {
	return nil
}

func (m *Manager) prepareManagedNetwork(ctx context.Context, req *model.Request, report model.CapabilityReport) (model.Cleanup, error) {
	if req.Policy.Network.Mode != model.NetworkAllowlist {
		return nil, nil
	}
	if !slices.Contains(report.NetworkModes, string(model.NetworkAllowlist)) {
		return nil, fmt.Errorf("backend %q does not support network allowlist enforcement", report.Backend)
	}
	if len(req.Policy.Network.Allow) == 0 {
		return nil, errors.New("network allowlist mode requires at least one allowed host pattern")
	}
	if report.Platform == "linux" {
		proxy, err := netproxy.StartUnixProxy(req.Policy.Network)
		if err != nil {
			return nil, err
		}
		req.ManagedProxyPort = 18080
		req.ManagedProxySocket = proxy.SocketPath()
		m.applyProxyEnv(req, fmt.Sprintf("http://127.0.0.1:%d", req.ManagedProxyPort))
		m.emit(ctx, model.Event{Type: "network_proxy_started", Message: req.ManagedProxySocket, Backend: report.Backend})
		return proxy.Close, nil
	}
	proxy, err := netproxy.StartProxy(req.Policy.Network)
	if err != nil {
		return nil, err
	}
	req.ManagedProxyPort = proxy.Port()
	m.applyProxyEnv(req, proxy.URL())
	m.emit(ctx, model.Event{Type: "network_proxy_started", Message: proxy.URL(), Backend: report.Backend})
	return proxy.Close, nil
}

func (m *Manager) applyProxyEnv(req *model.Request, proxyURL string) {
	if req.Env == nil {
		req.Env = map[string]string{}
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		req.Env[key] = proxyURL
	}
	req.Env["NO_PROXY"] = ""
	req.Env["no_proxy"] = ""
}

func (m *Manager) emit(ctx context.Context, event model.Event) {
	if m.opts.EventSink != nil {
		m.opts.EventSink.OnSandboxEvent(ctx, event)
	}
}

func normalizeRequest(req model.Request) (model.Request, error) {
	if len(req.Command) == 0 {
		return req, errors.New("command is required")
	}
	if req.Cwd == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return req, err
		}
		req.Cwd = cwd
	}
	if req.Policy.Network.Mode == "" {
		req.Policy.Network.Mode = model.NetworkOffline
	}
	return req, nil
}

func mergeEnv(base []string, overlay map[string]string) []string {
	if len(overlay) == 0 {
		return base
	}
	env := append([]string(nil), base...)
	for k, v := range overlay {
		env = append(env, k+"="+v)
	}
	return env
}

func summarizePolicy(policy model.Policy) model.PolicySummary {
	return model.PolicySummary{
		Filesystem: policy.Filesystem,
		Network:    policy.Network,
	}
}
