//go:build integration

package e2e

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func buildHelper(t *testing.T, workdir string) string {
	t.Helper()
	name := "sandbox-local"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helperPath := filepath.Join(workdir, name)
	if source := os.Getenv("SANDBOX_LOCAL_TEST_HELPER"); source != "" {
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(helperPath, data, 0755); err != nil {
			t.Fatal(err)
		}
		return helperPath
	}
	cmd := exec.Command("go", "build", "-o", helperPath, "./cmd/sandbox-local")
	cmd.Dir = repoRoot(t)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out.String())
	}
	return helperPath
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
