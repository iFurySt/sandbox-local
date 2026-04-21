package sandbox

import (
	"context"
	"io"
	"time"

	"github.com/iFurySt/sandbox-local/internal/engine"
	"github.com/iFurySt/sandbox-local/internal/model"
)

type BackendPreference string

const (
	BackendAuto BackendPreference = "auto"
	BackendNoop BackendPreference = "noop"
)

type EnforcementMode string

const (
	EnforcementRequire    EnforcementMode = "require"
	EnforcementBestEffort EnforcementMode = "best-effort"
)

type NetworkMode string

const (
	NetworkOffline   NetworkMode = "offline"
	NetworkAllowlist NetworkMode = "allowlist"
	NetworkOpen      NetworkMode = "open"
)

type Options struct {
	BackendPreference BackendPreference
	Enforcement       EnforcementMode
	EventSink         EventSink
}

type Request struct {
	Command []string
	Cwd     string
	Env     map[string]string
	Policy  Policy
	Stdio   Stdio
}

type Policy struct {
	Filesystem FilesystemPolicy
	Network    NetworkPolicy
	Process    ProcessPolicy
}

type FilesystemPolicy struct {
	ReadDeny   []string
	ReadAllow  []string
	WriteAllow []string
	WriteDeny  []string
}

type NetworkPolicy struct {
	Mode  NetworkMode
	Allow []string
	Deny  []string
}

type ProcessPolicy struct {
	Timeout time.Duration
}

type Stdio struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type EventSink interface {
	OnSandboxEvent(context.Context, Event)
}

type Event struct {
	Type    string
	Message string
	Backend string
}

type Result struct {
	ExitCode int
	Backend  string
}

type Plan = model.Plan
type CapabilityReport = model.CapabilityReport

type Manager struct {
	inner *engine.Manager
}

func NewManager(opts Options) (*Manager, error) {
	return &Manager{inner: engine.NewManager(toModelOptions(opts))}, nil
}

func (m *Manager) Run(ctx context.Context, req Request) (*Result, error) {
	result, err := m.inner.Run(ctx, toModelRequest(req))
	if err != nil {
		return nil, err
	}
	return &Result{ExitCode: result.ExitCode, Backend: result.Backend}, nil
}

func (m *Manager) Prepare(ctx context.Context, req Request) (*Plan, error) {
	plan, err := m.inner.Prepare(ctx, toModelRequest(req))
	if err != nil {
		return &plan, err
	}
	return &plan, nil
}

func (m *Manager) Check(ctx context.Context) (*CapabilityReport, error) {
	report, err := m.inner.Check(ctx)
	if err != nil {
		return nil, err
	}
	return &report, nil
}

func (m *Manager) Close() error {
	return m.inner.Close()
}

func toModelOptions(opts Options) model.Options {
	return model.Options{
		BackendPreference: model.BackendPreference(opts.BackendPreference),
		Enforcement:       model.EnforcementMode(opts.Enforcement),
		EventSink:         eventSinkAdapter{sink: opts.EventSink},
	}
}

func toModelRequest(req Request) model.Request {
	return model.Request{
		Command: req.Command,
		Cwd:     req.Cwd,
		Env:     req.Env,
		Policy: model.Policy{
			Filesystem: model.FilesystemPolicy(req.Policy.Filesystem),
			Network: model.NetworkPolicy{
				Mode:  model.NetworkMode(req.Policy.Network.Mode),
				Allow: req.Policy.Network.Allow,
				Deny:  req.Policy.Network.Deny,
			},
			Process: model.ProcessPolicy(req.Policy.Process),
		},
		Stdio: model.Stdio(req.Stdio),
	}
}

type eventSinkAdapter struct {
	sink EventSink
}

func (a eventSinkAdapter) OnSandboxEvent(ctx context.Context, event model.Event) {
	if a.sink == nil {
		return
	}
	a.sink.OnSandboxEvent(ctx, Event{
		Type:    event.Type,
		Message: event.Message,
		Backend: event.Backend,
	})
}
