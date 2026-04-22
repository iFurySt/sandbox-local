package macos

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/iFurySt/sandbox-local/internal/fsx"
	"github.com/iFurySt/sandbox-local/internal/model"
)

const sandboxExecPath = "/usr/bin/sandbox-exec"

type Backend struct{}

func New() Backend {
	return Backend{}
}

func (Backend) Name() string {
	return "macos-seatbelt"
}

func (Backend) Platform() string {
	return "darwin"
}

func (b Backend) Check(context.Context) model.CapabilityReport {
	report := model.CapabilityReport{
		Backend:      b.Name(),
		Platform:     b.Platform(),
		Available:    true,
		Sandboxed:    true,
		NetworkModes: []string{string(model.NetworkOffline), string(model.NetworkAllowlist), string(model.NetworkOpen)},
	}
	if _, err := os.Stat(sandboxExecPath); err != nil {
		report.Available = false
		report.Sandboxed = false
		report.Missing = append(report.Missing, sandboxExecPath)
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
	policy, err := buildProfile(req.Policy, absCwd, req.ManagedProxyPort)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	command := []string{sandboxExecPath, "-p", policy}
	command = append(command, req.Command...)
	return model.PreparedCommand{
		Backend:  b.Name(),
		Platform: b.Platform(),
		Command:  command,
		Cwd:      absCwd,
		Env:      cloneMap(req.Env),
	}, nil, nil
}

func buildProfile(policy model.Policy, cwd string, managedProxyPort int) (string, error) {
	writeAllow, err := fsx.AbsList(policy.Filesystem.WriteAllow, cwd)
	if err != nil {
		return "", err
	}
	writeDeny, err := fsx.AbsList(policy.Filesystem.WriteDeny, cwd)
	if err != nil {
		return "", err
	}
	readDeny, err := fsx.AbsList(policy.Filesystem.ReadDeny, cwd)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("(allow process*)\n")
	sb.WriteString("(allow sysctl-read)\n")
	writeReadAllowRule(&sb, readDeny)
	sb.WriteString("(allow file-write-data (literal \"/dev/null\"))\n")
	for _, path := range writeAllow {
		writePathAllowRule(&sb, "file-write*", path, writeDeny)
	}
	switch policy.Network.Mode {
	case "", model.NetworkOffline:
	case model.NetworkAllowlist:
		if managedProxyPort <= 0 {
			return "", fmt.Errorf("network allowlist requires a managed proxy port")
		}
		sb.WriteString(networkProxyPolicy(managedProxyPort))
	case model.NetworkOpen:
		sb.WriteString(networkOpenPolicy())
	default:
		return "", fmt.Errorf("unsupported network mode %q", policy.Network.Mode)
	}
	return sb.String(), nil
}

func writeReadAllowRule(sb *strings.Builder, readDeny []string) {
	sb.WriteString("(allow file-read*")
	if len(readDeny) > 0 {
		sb.WriteString(" (require-all")
		writePathExclusions(sb, readDeny)
		sb.WriteString(")")
	}
	sb.WriteString(")\n")
}

func writePathAllowRule(sb *strings.Builder, operation string, path string, exclusions []string) {
	writePathAllowMatcher(sb, operation, "literal", path, exclusions)
	writePathAllowMatcher(sb, operation, "subpath", path, exclusions)
}

func writePathAllowMatcher(sb *strings.Builder, operation string, matcher string, path string, exclusions []string) {
	sb.WriteString("(allow ")
	sb.WriteString(operation)
	sb.WriteString(" (require-all (")
	sb.WriteString(matcher)
	sb.WriteString(" ")
	sb.WriteString(sbplString(path))
	sb.WriteString(")")
	writePathExclusions(sb, exclusions)
	sb.WriteString("))\n")
}

func writePathExclusions(sb *strings.Builder, paths []string) {
	for _, path := range paths {
		sb.WriteString(" (require-not (literal ")
		sb.WriteString(sbplString(path))
		sb.WriteString("))")
		sb.WriteString(" (require-not (subpath ")
		sb.WriteString(sbplString(path))
		sb.WriteString("))")
	}
}

func networkProxyPolicy(port int) string {
	var sb strings.Builder
	sb.WriteString("(allow network-outbound (remote ip \"localhost:")
	sb.WriteString(fmt.Sprintf("%d", port))
	sb.WriteString("\"))\n")
	sb.WriteString(networkPlatformPolicy())
	return sb.String()
}

func networkOpenPolicy() string {
	var sb strings.Builder
	sb.WriteString("(allow network*)\n")
	sb.WriteString(networkPlatformPolicy())
	return sb.String()
}

func networkPlatformPolicy() string {
	var sb strings.Builder
	sb.WriteString("(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))\n")
	sb.WriteString("(allow mach-lookup\n")
	for _, service := range []string{
		"com.apple.bsd.dirhelper",
		"com.apple.SecurityServer",
		"com.apple.networkd",
		"com.apple.ocspd",
		"com.apple.trustd.agent",
		"com.apple.SystemConfiguration.DNSConfiguration",
		"com.apple.SystemConfiguration.configd",
		"com.apple.system.opendirectoryd.membership",
	} {
		sb.WriteString("  (global-name ")
		sb.WriteString(sbplString(service))
		sb.WriteString(")\n")
	}
	sb.WriteString(")\n")
	sb.WriteString("(allow sysctl-read (sysctl-name-regex #\"^net\\\\.routetable\"))\n")
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		sb.WriteString("(allow file-write* (subpath ")
		sb.WriteString(sbplString(cacheDir))
		sb.WriteString("))\n")
	}
	return sb.String()
}

func sbplString(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
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
