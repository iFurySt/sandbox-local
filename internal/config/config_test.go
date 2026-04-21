package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
)

func TestLoadExamplePolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sandbox-local.yaml")
	if err := os.WriteFile(path, []byte(Example), 0o644); err != nil {
		t.Fatal(err)
	}

	file, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := file.Policy("default")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Network.Mode != model.NetworkOffline {
		t.Fatalf("network mode = %q, want %q", policy.Network.Mode, model.NetworkOffline)
	}
	if len(policy.Filesystem.WriteAllow) == 0 {
		t.Fatal("expected write allow entries")
	}
}

func TestDefaultPolicyIsOffline(t *testing.T) {
	policy := DefaultPolicy()
	if policy.Network.Mode != model.NetworkOffline {
		t.Fatalf("network mode = %q, want %q", policy.Network.Mode, model.NetworkOffline)
	}
	if len(policy.Filesystem.WriteDeny) == 0 {
		t.Fatal("expected protected write deny defaults")
	}
}
