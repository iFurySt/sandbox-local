package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(&out, &bytes.Buffer{})
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != version {
		t.Fatalf("version output = %q, want %q", got, version)
	}
}

func TestNoopDebugPlan(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(&out, &bytes.Buffer{})
	cmd.SetArgs([]string{"--backend", "noop", "debug", "plan", "--", "echo", "hi"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "backend: noop") {
		t.Fatalf("expected noop plan, got %q", out.String())
	}
}

func TestPolicyInitStdout(t *testing.T) {
	var out bytes.Buffer
	cmd := NewRootCommand(&out, &bytes.Buffer{})
	cmd.SetArgs([]string{"policy", "init", "-"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "version: 1") {
		t.Fatalf("unexpected policy output: %q", out.String())
	}
}
