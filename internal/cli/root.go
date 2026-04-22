package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/iFurySt/sandbox-local/internal/config"
	"github.com/iFurySt/sandbox-local/internal/linuxbridge"
	"github.com/iFurySt/sandbox-local/internal/model"
	"github.com/iFurySt/sandbox-local/internal/winrunner"
	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	"github.com/spf13/cobra"
)

var version = "0.1.0-dev"

type ExitCodeError struct {
	Code int
}

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("command exited with code %d", e.Code)
}

type rootOptions struct {
	json        bool
	backend     string
	enforcement string
	out         io.Writer
	errOut      io.Writer
}

func Execute(ctx context.Context) int {
	root := NewRootCommand(os.Stdout, os.Stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		var exitErr ExitCodeError
		if errors.As(err, &exitErr) {
			return exitErr.Code
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func NewRootCommand(out io.Writer, errOut io.Writer) *cobra.Command {
	opts := &rootOptions{out: out, errOut: errOut}
	cmd := &cobra.Command{
		Use:          "sandbox-local",
		Short:        "Run commands inside an OS-native sandbox",
		SilenceUsage: true,
	}
	cmd.PersistentFlags().BoolVar(&opts.json, "json", false, "write machine-readable JSON")
	cmd.PersistentFlags().StringVar(&opts.backend, "backend", "auto", "backend preference: auto or noop")
	cmd.PersistentFlags().StringVar(&opts.enforcement, "enforcement", "require", "enforcement mode: require or best-effort")
	cmd.AddCommand(newRunCommand(opts))
	cmd.AddCommand(newDoctorCommand(opts))
	cmd.AddCommand(newSetupCommand(opts))
	cmd.AddCommand(newDebugCommand(opts))
	cmd.AddCommand(newPolicyCommand(opts))
	cmd.AddCommand(newProxyBridgeCommand())
	cmd.AddCommand(newExecSeccompCommand())
	cmd.AddCommand(newWindowsRunnerCommand())
	cmd.AddCommand(newVersionCommand(opts))
	return cmd
}

func newRunCommand(root *rootOptions) *cobra.Command {
	var opts runOptions
	cmd := &cobra.Command{
		Use:   "run [flags] -- <command...>",
		Short: "Run a command with sandbox policy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, cwd, err := buildPolicy(opts)
			if err != nil {
				return err
			}
			manager, err := sandbox.NewManager(sandbox.Options{
				BackendPreference: sandbox.BackendPreference(root.backend),
				Enforcement:       sandbox.EnforcementMode(root.enforcement),
			})
			if err != nil {
				return err
			}
			defer manager.Close()
			result, err := manager.Run(cmd.Context(), sandbox.Request{
				Command: args,
				Cwd:     cwd,
				Policy:  toPublicPolicy(policy),
				Stdio: sandbox.Stdio{
					Stdin:  os.Stdin,
					Stdout: root.out,
					Stderr: root.errOut,
				},
			})
			if err != nil {
				return err
			}
			if result.ExitCode != 0 {
				return ExitCodeError{Code: result.ExitCode}
			}
			return nil
		},
	}
	addRunPolicyFlags(cmd, &opts)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newDoctorCommand(root *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Report sandbox backend capabilities",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := sandbox.NewManager(sandbox.Options{
				BackendPreference: sandbox.BackendPreference(root.backend),
				Enforcement:       sandbox.EnforcementMode(root.enforcement),
			})
			if err != nil {
				return err
			}
			defer manager.Close()
			report, err := manager.Check(cmd.Context())
			if err != nil {
				return err
			}
			if root.json {
				return writeJSON(root.out, report)
			}
			fmt.Fprintf(root.out, "backend: %s\nplatform: %s\navailable: %t\nsandboxed: %t\n", report.Backend, report.Platform, report.Available, report.Sandboxed)
			if len(report.NetworkModes) > 0 {
				fmt.Fprintf(root.out, "network_modes: %s\n", strings.Join(report.NetworkModes, ", "))
			}
			for _, missing := range report.Missing {
				fmt.Fprintf(root.out, "missing: %s\n", missing)
			}
			for _, warning := range report.Warnings {
				fmt.Fprintf(root.out, "warning: %s\n", warning)
			}
			for _, note := range report.Notes {
				fmt.Fprintf(root.out, "note: %s\n", note)
			}
			return nil
		},
	}
}

func newSetupCommand(root *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "setup [platform]",
		Short: "Prepare host prerequisites for the sandbox backend",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "current"
			if len(args) > 0 {
				target = args[0]
			}
			manager, err := sandbox.NewManager(sandbox.Options{
				BackendPreference: sandbox.BackendPreference(root.backend),
				Enforcement:       sandbox.EnforcementMode(root.enforcement),
			})
			if err != nil {
				return err
			}
			defer manager.Close()
			report, err := manager.Setup(cmd.Context(), sandbox.SetupRequest{TargetPlatform: target})
			if root.json {
				if jsonErr := writeJSON(root.out, report); jsonErr != nil {
					return jsonErr
				}
				return err
			}
			fmt.Fprintf(root.out, "backend: %s\nplatform: %s\nready: %t\nchanged: %t\n", report.Backend, report.Platform, report.Ready, report.Changed)
			for _, action := range report.Actions {
				fmt.Fprintf(root.out, "action: %s\n", action)
			}
			for _, missing := range report.Missing {
				fmt.Fprintf(root.out, "missing: %s\n", missing)
			}
			for _, warning := range report.Warnings {
				fmt.Fprintf(root.out, "warning: %s\n", warning)
			}
			for _, note := range report.Notes {
				fmt.Fprintf(root.out, "note: %s\n", note)
			}
			return err
		},
	}
}

func newDebugCommand(root *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "debug",
		Short: "Debug sandbox decisions",
	}
	cmd.AddCommand(newDebugPlanCommand(root))
	return cmd
}

func newDebugPlanCommand(root *rootOptions) *cobra.Command {
	var opts runOptions
	cmd := &cobra.Command{
		Use:   "plan [flags] -- <command...>",
		Short: "Print the prepared sandbox command",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, cwd, err := buildPolicy(opts)
			if err != nil {
				return err
			}
			manager, err := sandbox.NewManager(sandbox.Options{
				BackendPreference: sandbox.BackendPreference(root.backend),
				Enforcement:       sandbox.EnforcementMode(root.enforcement),
			})
			if err != nil {
				return err
			}
			defer manager.Close()
			plan, planErr := manager.Prepare(cmd.Context(), sandbox.Request{
				Command: args,
				Cwd:     cwd,
				Policy:  toPublicPolicy(policy),
			})
			if root.json {
				if err := writeJSON(root.out, plan); err != nil {
					return err
				}
				return planErr
			}
			fmt.Fprintf(root.out, "backend: %s\ncwd: %s\ncommand: %s\n", plan.Backend, plan.Cwd, strings.Join(plan.Command, " "))
			for _, warning := range plan.Warnings {
				fmt.Fprintf(root.out, "warning: %s\n", warning)
			}
			return planErr
		},
	}
	addRunPolicyFlags(cmd, &opts)
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newPolicyCommand(root *rootOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage sandbox policy files",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "init [file]",
		Short: "Write an example policy",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "-" {
				fmt.Fprint(root.out, config.Example)
				return nil
			}
			return os.WriteFile(args[0], []byte(config.Example), 0o644)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a policy file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := config.Load(args[0])
			if err != nil {
				return err
			}
			if _, err := file.Policy("default"); err != nil {
				return err
			}
			if root.json {
				return writeJSON(root.out, map[string]any{"ok": true, "file": args[0]})
			}
			fmt.Fprintf(root.out, "policy valid: %s\n", args[0])
			return nil
		},
	})
	return cmd
}

func newVersionCommand(root *rootOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(cmd *cobra.Command, args []string) error {
			if root.json {
				return writeJSON(root.out, map[string]string{"version": version})
			}
			fmt.Fprintln(root.out, version)
			return nil
		},
	}
}

func newProxyBridgeCommand() *cobra.Command {
	var listen string
	var socket string
	cmd := &cobra.Command{
		Use:    "__proxy-bridge --listen <addr> --unix <socket> -- <command...>",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return linuxbridge.Run(cmd.Context(), listen, socket, args)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "loopback listen address")
	cmd.Flags().StringVar(&socket, "unix", "", "upstream Unix socket")
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newExecSeccompCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "__exec-seccomp -- <command...>",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return linuxbridge.ExecWithSeccomp(args)
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

func newWindowsRunnerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "__windows-runner -- <command...>",
		Hidden: true,
		Args:   cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := winrunner.Run(cmd.Context(), args)
			var exitErr winrunner.ExitCodeError
			if errors.As(err, &exitErr) {
				return ExitCodeError{Code: exitErr.Code}
			}
			return err
		},
	}
	cmd.Flags().SetInterspersed(false)
	return cmd
}

type runOptions struct {
	policyFile string
	profile    string
	cwd        string
	network    string
	allowWrite []string
	denyWrite  []string
	denyRead   []string
	allowNet   []string
	denyNet    []string
}

func addRunPolicyFlags(cmd *cobra.Command, opts *runOptions) {
	cmd.Flags().StringVar(&opts.policyFile, "policy", "", "policy file path")
	cmd.Flags().StringVar(&opts.profile, "profile", "default", "policy profile name")
	cmd.Flags().StringVar(&opts.cwd, "cwd", "", "working directory")
	cmd.Flags().StringVar(&opts.network, "network", "", "override network mode: offline, open, allowlist")
	cmd.Flags().StringSliceVar(&opts.allowWrite, "allow-write", nil, "additional writable path")
	cmd.Flags().StringSliceVar(&opts.denyWrite, "deny-write", nil, "additional write-denied path")
	cmd.Flags().StringSliceVar(&opts.denyRead, "deny-read", nil, "additional read-denied path")
	cmd.Flags().StringSliceVar(&opts.allowNet, "allow-net", nil, "additional allowed network host pattern")
	cmd.Flags().StringSliceVar(&opts.denyNet, "deny-net", nil, "additional denied network host pattern")
}

func buildPolicy(opts runOptions) (model.Policy, string, error) {
	policy := config.DefaultPolicy()
	if opts.policyFile != "" {
		file, err := config.Load(opts.policyFile)
		if err != nil {
			return model.Policy{}, "", err
		}
		loaded, err := file.Policy(opts.profile)
		if err != nil {
			return model.Policy{}, "", err
		}
		policy = loaded
	}
	if opts.network != "" {
		policy.Network.Mode = model.NetworkMode(opts.network)
	}
	policy.Filesystem.WriteAllow = append(policy.Filesystem.WriteAllow, opts.allowWrite...)
	policy.Filesystem.WriteDeny = append(policy.Filesystem.WriteDeny, opts.denyWrite...)
	policy.Filesystem.ReadDeny = append(policy.Filesystem.ReadDeny, opts.denyRead...)
	policy.Network.Allow = append(policy.Network.Allow, opts.allowNet...)
	policy.Network.Deny = append(policy.Network.Deny, opts.denyNet...)
	cwd := opts.cwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return model.Policy{}, "", err
		}
	}
	return policy, cwd, nil
}

func toPublicPolicy(policy model.Policy) sandbox.Policy {
	return sandbox.Policy{
		Filesystem: sandbox.FilesystemPolicy(policy.Filesystem),
		Network: sandbox.NetworkPolicy{
			Mode:  sandbox.NetworkMode(policy.Network.Mode),
			Allow: policy.Network.Allow,
			Deny:  policy.Network.Deny,
		},
		Process: sandbox.ProcessPolicy(policy.Process),
	}
}

func writeJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
