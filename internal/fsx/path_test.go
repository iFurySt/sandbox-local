package fsx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAbsListExpandsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	paths, err := AbsList([]string{".", "subdir"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "subdir")
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if paths[0] != canonicalDir {
		t.Fatalf("first path = %q, want %q", paths[0], canonicalDir)
	}
	canonicalWant, err := Abs(want, "")
	if err != nil {
		t.Fatal(err)
	}
	if paths[1] != canonicalWant {
		t.Fatalf("second path = %q, want %q", paths[1], canonicalWant)
	}
}

func TestAbsCanonicalizesExistingSymlinkPrefix(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	got, err := Abs(filepath.Join(link, "future", "file.txt"), "")
	if err != nil {
		t.Fatal(err)
	}
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(canonicalTarget, "future", "file.txt")
	if got != want {
		t.Fatalf("Abs returned %q, want %q", got, want)
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got := Expand("~/example"); got != filepath.Join(home, "example") {
		t.Fatalf("Expand returned %q", got)
	}
}
