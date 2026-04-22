package model

import (
	"context"
	"io"
	"time"
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
	HelperPath        string
}

type Request struct {
	Command            []string
	Cwd                string
	Env                map[string]string
	Policy             Policy
	Stdio              Stdio
	ManagedProxyPort   int
	ManagedProxySocket string
	HelperPath         string
}

type SetupRequest struct {
	TargetPlatform string
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
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
	Backend string `json:"backend,omitempty"`
}

type Result struct {
	ExitCode int
	Backend  string
}

type Plan struct {
	Backend           string            `json:"backend"`
	Platform          string            `json:"platform"`
	Command           []string          `json:"command"`
	Cwd               string            `json:"cwd"`
	Env               map[string]string `json:"env,omitempty"`
	Warnings          []string          `json:"warnings,omitempty"`
	CapabilityReport  CapabilityReport  `json:"capability_report"`
	EffectivePolicy   PolicySummary     `json:"effective_policy"`
	Enforcement       EnforcementMode   `json:"enforcement"`
	BackendPreference BackendPreference `json:"backend_preference"`
}

type PolicySummary struct {
	Filesystem FilesystemPolicy `json:"filesystem"`
	Network    NetworkPolicy    `json:"network"`
}

type PreparedCommand struct {
	Backend  string
	Platform string
	Command  []string
	Cwd      string
	Env      map[string]string
	Warnings []string
}

type CapabilityReport struct {
	Backend      string   `json:"backend"`
	Platform     string   `json:"platform"`
	Available    bool     `json:"available"`
	Sandboxed    bool     `json:"sandboxed"`
	NetworkModes []string `json:"network_modes"`
	Missing      []string `json:"missing,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

type SetupReport struct {
	Backend  string   `json:"backend"`
	Platform string   `json:"platform"`
	Ready    bool     `json:"ready"`
	Changed  bool     `json:"changed"`
	Actions  []string `json:"actions,omitempty"`
	Missing  []string `json:"missing,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

type Cleanup func(context.Context) error
