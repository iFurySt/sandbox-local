package config

import (
	"fmt"
	"os"
	"time"

	"github.com/iFurySt/sandbox-local/internal/model"
	"gopkg.in/yaml.v3"
)

type File struct {
	Version  int                `yaml:"version"`
	Profiles map[string]Profile `yaml:"profiles"`
}

type Profile struct {
	Filesystem Filesystem `yaml:"filesystem"`
	Network    Network    `yaml:"network"`
	Process    Process    `yaml:"process"`
}

type Filesystem struct {
	Read  ReadPolicy  `yaml:"read"`
	Write WritePolicy `yaml:"write"`
}

type ReadPolicy struct {
	Deny  []string `yaml:"deny"`
	Allow []string `yaml:"allow"`
}

type WritePolicy struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type Network struct {
	Mode  string   `yaml:"mode"`
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

type Process struct {
	Timeout string `yaml:"timeout"`
}

func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file File
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version == 0 {
		file.Version = 1
	}
	if file.Profiles == nil {
		file.Profiles = map[string]Profile{}
	}
	return &file, nil
}

func (f *File) Policy(profile string) (model.Policy, error) {
	if profile == "" {
		profile = "default"
	}
	item, ok := f.Profiles[profile]
	if !ok {
		return model.Policy{}, fmt.Errorf("profile %q not found", profile)
	}
	return item.Policy()
}

func (p Profile) Policy() (model.Policy, error) {
	mode := model.NetworkMode(p.Network.Mode)
	if mode == "" {
		mode = model.NetworkOffline
	}
	switch mode {
	case model.NetworkOffline, model.NetworkOpen, model.NetworkAllowlist:
	default:
		return model.Policy{}, fmt.Errorf("unsupported network mode %q", mode)
	}
	var timeout time.Duration
	if p.Process.Timeout != "" {
		parsed, err := time.ParseDuration(p.Process.Timeout)
		if err != nil {
			return model.Policy{}, fmt.Errorf("invalid process timeout: %w", err)
		}
		timeout = parsed
	}
	return model.Policy{
		Filesystem: model.FilesystemPolicy{
			ReadDeny:   append([]string(nil), p.Filesystem.Read.Deny...),
			ReadAllow:  append([]string(nil), p.Filesystem.Read.Allow...),
			WriteAllow: append([]string(nil), p.Filesystem.Write.Allow...),
			WriteDeny:  append([]string(nil), p.Filesystem.Write.Deny...),
		},
		Network: model.NetworkPolicy{
			Mode:  mode,
			Allow: append([]string(nil), p.Network.Allow...),
			Deny:  append([]string(nil), p.Network.Deny...),
		},
		Process: model.ProcessPolicy{Timeout: timeout},
	}, nil
}

func DefaultPolicy() model.Policy {
	return model.Policy{
		Filesystem: model.FilesystemPolicy{
			ReadDeny:   []string{"~/.ssh", "~/.aws", "~/.config/gh"},
			ReadAllow:  []string{"."},
			WriteAllow: []string{".", os.TempDir()},
			WriteDeny:  []string{".git", ".codex", ".agents"},
		},
		Network: model.NetworkPolicy{Mode: model.NetworkOffline},
	}
}

const Example = `version: 1
profiles:
  default:
    filesystem:
      read:
        deny:
          - "~/.ssh"
          - "~/.aws"
        allow:
          - "."
      write:
        allow:
          - "."
          - "${TMPDIR}"
        deny:
          - ".git"
          - ".codex"
          - ".agents"
    network:
      mode: offline
      allow: []
      deny: []
    process:
      timeout: 30s
`
