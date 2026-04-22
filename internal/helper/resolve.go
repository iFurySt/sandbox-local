package helper

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const envHelperPath = "SANDBOX_LOCAL_HELPER"

func Resolve(configured string) (string, error) {
	for _, candidate := range []string{configured, os.Getenv(envHelperPath)} {
		if candidate == "" {
			continue
		}
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("sandbox-local helper %q is not available: %w", abs, err)
		}
		return abs, nil
	}
	if exe, err := os.Executable(); err == nil && looksLikeHelper(exe) {
		return exe, nil
	}
	name := "sandbox-local"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("sandbox-local helper not found; set HelperPath or %s", envHelperPath)
}

func looksLikeHelper(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "sandbox-local" || base == "sandbox-local.exe"
}
