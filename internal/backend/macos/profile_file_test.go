package macos

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
)

func TestPrepareProfileFile(t *testing.T) {
	request := model.Request{Command: []string{"echo", "hello"}, Cwd: t.TempDir()}
	prepared, cleanup, err := New().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil {
		t.Fatal("profile file has no cleanup")
	}
	t.Cleanup(func() {
		if err := cleanup(context.Background()); err != nil {
			t.Error(err)
		}
	})
	if len(prepared.Command) != 5 || prepared.Command[0] != sandboxExecPath || prepared.Command[1] != "-f" ||
		!reflect.DeepEqual(prepared.Command[3:], request.Command) {
		t.Fatalf("unexpected prepared command: %v", prepared.Command)
	}
	filename := prepared.Command[2]
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	want, err := buildProfile(request.Policy, prepared.Cwd, 0)
	if err != nil || string(content) != want {
		t.Fatalf("profile content changed: %v", err)
	}
	for name, mode := range map[string]os.FileMode{filename: 0600, filepath.Dir(filename): 0700} {
		info, err := os.Stat(name)
		if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != mode) {
			t.Fatalf("permissions for %s: info=%v error=%v", name, info, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(filename)); !os.IsNotExist(err) {
		t.Fatalf("profile directory survived cleanup: %v", err)
	}
}

func TestPrepareProfileFileFailure(t *testing.T) {
	request := model.Request{Command: []string{"echo", "hello"}, Cwd: t.TempDir()}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, missing)
	}
	prepared, cleanup, err := New().Prepare(context.Background(), request)
	if err == nil || len(prepared.Command) != 0 || cleanup != nil {
		t.Fatalf("temporary-file failure must reject execution: command=%v cleanup=%v error=%v", prepared.Command, cleanup != nil, err)
	}
}
