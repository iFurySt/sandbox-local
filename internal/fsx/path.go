package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func Abs(path string, cwd string) (string, error) {
	if path == "" {
		return "", nil
	}
	expanded := Expand(path)
	if !filepath.IsAbs(expanded) {
		if cwd == "" {
			cwd = "."
		}
		expanded = filepath.Join(cwd, expanded)
	}
	return filepath.Abs(expanded)
}

func AbsList(paths []string, cwd string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		abs, err := Abs(path, cwd)
		if err != nil {
			return nil, err
		}
		if abs != "" {
			out = append(out, abs)
		}
	}
	return Dedup(out), nil
}

func Expand(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return os.ExpandEnv(path)
}

func Dedup(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, path)
	}
	return out
}
