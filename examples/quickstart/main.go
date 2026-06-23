package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/iFurySt/sandbox-local/pkg/sandbox"
)

func main() {
	if sandbox.MaybeRunHelper() {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	workdir, err := os.MkdirTemp("", "sandbox-local-quickstart-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workdir)

	if err := os.Mkdir(filepath.Join(workdir, ".git"), 0o755); err != nil {
		return err
	}
	secretPath := filepath.Join(workdir, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0o600); err != nil {
		return err
	}

	manager, err := sandbox.NewManager(sandbox.Options{
		HelperPath: os.Args[0],
	})
	if err != nil {
		return err
	}
	defer manager.Close()

	setup, err := manager.Setup(ctx, sandbox.SetupRequest{TargetPlatform: runtime.GOOS})
	if err != nil {
		return fmt.Errorf("setup sandbox backend %q: %w", setup.Backend, err)
	}

	result, err := manager.Run(ctx, sandbox.Request{
		Command: shellCommand("write-allowed"),
		Cwd:     workdir,
		Policy: sandbox.Policy{
			Filesystem: sandbox.FilesystemPolicy{
				ReadAllow:  []string{workdir},
				ReadDeny:   []string{secretPath},
				WriteAllow: []string{workdir},
				WriteDeny:  []string{filepath.Join(workdir, ".git")},
			},
			Network: sandbox.NetworkPolicy{
				Mode: sandbox.NetworkOffline,
			},
			Process: sandbox.ProcessPolicy{
				Timeout: 30 * time.Second,
			},
		},
		Stdio: sandbox.Stdio{
			Stdout: os.Stdout,
			Stderr: os.Stderr,
		},
	})
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("sandboxed command exited with code %d", result.ExitCode)
	}

	allowed, err := os.ReadFile(filepath.Join(workdir, "allowed.txt"))
	if err != nil {
		return err
	}
	fmt.Printf("backend=%s allowed.txt=%q\n", result.Backend, string(allowed))
	return nil
}

func shellCommand(action string) []string {
	switch runtime.GOOS {
	case "windows":
		switch action {
		case "write-allowed":
			return []string{"powershell.exe", "-NoProfile", "-Command", "Set-Content -LiteralPath allowed.txt -Value ok"}
		}
	default:
		switch action {
		case "write-allowed":
			return []string{"/bin/sh", "-c", "printf ok > allowed.txt"}
		}
	}
	panic("unknown quickstart action")
}
