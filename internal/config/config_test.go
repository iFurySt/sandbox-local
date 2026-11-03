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

func TestSeatbeltProfileConfig(t *testing.T) {
	t.Parallel()
	for _, action := range []string{"", "deny", "allow", "unknown"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "policy.yaml")
			content := "version: 1\nprofiles:\n  default:\n    seatbelt:\n      default_action: " + action + "\n"
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			file, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := file.Policy("default")
			if action == "unknown" {
				if err == nil {
					t.Fatal("invalid action accepted")
				}
				return
			}
			if err != nil || string(policy.Seatbelt.DefaultAction) != action {
				t.Fatalf("policy=%+v error=%v", policy, err)
			}
		})
	}
}
