package winrunner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTaskOutputCursorForwardsAppendedBytesOnce(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "stdout.bin")
	var out bytes.Buffer
	cursor := taskOutputCursor{path: path, out: &out}
	cursor.drain(4)
	if cursor.err != nil || out.Len() != 0 {
		t.Fatalf("absent file: out=%x err=%v", out.Bytes(), cursor.err)
	}
	data := []byte("start\x00中文\n")
	if err := os.WriteFile(path, data[:7], 0600); err != nil {
		t.Fatal(err)
	}
	cursor.drain(4)
	if cursor.err != nil || !bytes.Equal(out.Bytes(), data[:4]) {
		t.Fatalf("first poll: out=%x err=%v", out.Bytes(), cursor.err)
	}
	cursor.drain(4)
	cursor.drain(4)
	if cursor.err != nil || !bytes.Equal(out.Bytes(), data[:7]) {
		t.Fatalf("quiet poll: out=%x err=%v", out.Bytes(), cursor.err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(data[7:])
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append: write=%v close=%v", writeErr, closeErr)
	}
	cursor.drain(0)
	cursor.drain(0)
	if cursor.err != nil || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("final drain: out=%x err=%v", out.Bytes(), cursor.err)
	}
}
