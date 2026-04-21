package sandbox

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestNoopManagerRun(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	manager, err := NewManager(Options{BackendPreference: BackendNoop})
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Run(context.Background(), Request{
		Command: []string{exe, "-test.run=TestHelperProcess", "--"},
		Env:     map[string]string{"SANDBOX_LOCAL_HELPER_PROCESS": "1"},
		Policy:  Policy{Network: NetworkPolicy{Mode: NetworkOpen}},
		Stdio:   Stdio{Stdout: &out, Stderr: &out},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d", result.ExitCode)
	}
	if out.String() != "helper ok\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestNoopManagerPrepare(t *testing.T) {
	manager, err := NewManager(Options{BackendPreference: BackendNoop})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := manager.Prepare(context.Background(), Request{
		Command: []string{"echo", "hi"},
		Policy:  Policy{Network: NetworkPolicy{Mode: NetworkOpen}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Backend != "noop" {
		t.Fatalf("backend = %q", plan.Backend)
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SANDBOX_LOCAL_HELPER_PROCESS") != "1" {
		return
	}
	t.Log("helper process")
	os.Stdout.WriteString("helper ok\n")
	os.Exit(0)
}
