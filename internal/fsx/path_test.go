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
	if paths[0] != dir {
		t.Fatalf("first path = %q, want %q", paths[0], dir)
	}
	if paths[1] != want {
		t.Fatalf("second path = %q, want %q", paths[1], want)
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
