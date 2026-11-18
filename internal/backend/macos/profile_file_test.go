package macos

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
)

func TestPrepareInlineProfile(t *testing.T) {
	cwd := t.TempDir()
	quotedName := `profile "quoted" \\ path`
	quotedPath := filepath.Join(cwd, quotedName)
	request := model.Request{
		Command: []string{"echo", "hello"},
		Cwd:     cwd,
		Policy: model.Policy{Filesystem: model.FilesystemPolicy{
			WriteAllow: []string{quotedPath},
		}},
	}
	prepared, cleanup, err := New().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup != nil {
		t.Fatal("inline profile unexpectedly has cleanup")
	}
	if len(prepared.Command) != 5 || prepared.Command[0] != sandboxExecPath || prepared.Command[1] != "-p" ||
		!reflect.DeepEqual(prepared.Command[3:], request.Command) {
		t.Fatalf("unexpected prepared command: %v", prepared.Command)
	}
	want, err := buildProfile(request.Policy, prepared.Cwd, 0)
	if err != nil || prepared.Command[2] != want {
		t.Fatalf("inline profile changed: %v", err)
	}
	encodedPath := sbplString(filepath.Join(prepared.Cwd, quotedName))
	if !strings.Contains(prepared.Command[2], "(literal "+encodedPath+")") ||
		!strings.Contains(prepared.Command[2], "(subpath "+encodedPath+")") {
		t.Fatalf("special-character path was not encoded in inline profile: %q", prepared.Command[2])
	}
}

func TestPrepareDoesNotRequireTemporaryProfileFile(t *testing.T) {
	request := model.Request{Command: []string{"echo", "hello"}, Cwd: t.TempDir()}
	missing := filepath.Join(t.TempDir(), "missing")
	for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(name, missing)
	}
	prepared, cleanup, err := New().Prepare(context.Background(), request)
	if err != nil || len(prepared.Command) != 5 || cleanup != nil {
		t.Fatalf("inline profile unexpectedly depends on temporary files: command=%v cleanup=%v error=%v", prepared.Command, cleanup != nil, err)
	}
}
