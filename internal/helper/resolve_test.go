package helper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandbox-local")
	if err := os.WriteFile(path, []byte("helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("Resolve returned %q, want %q", got, path)
	}
}

func TestResolveMissingConfiguredPath(t *testing.T) {
	_, err := Resolve(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		t.Fatal("expected missing helper error")
	}
}
