//go:build windows

package winrunner

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTaskExitWaitsForContent(t *testing.T) {
	t.Parallel()

	for _, raw := range [][]byte{nil, {}, []byte(" \r\n")} {
		code, ready, err := parseTaskExit(raw)
		if err != nil || ready || code != 0 {
			t.Fatalf("parseTaskExit(%q) = (%d, %t, %v), want (0, false, nil)", raw, code, ready, err)
		}
	}
}

func TestParseTaskExitReturnsCode(t *testing.T) {
	t.Parallel()

	code, ready, err := parseTaskExit([]byte("23\r\n"))
	if err != nil || !ready || code != 23 {
		t.Fatalf("parseTaskExit() = (%d, %t, %v), want (23, true, nil)", code, ready, err)
	}
}

func TestScheduledTaskResultUsesNumericState(t *testing.T) {
	for _, test := range []struct {
		code      string
		completed bool
	}{
		{"267009", false}, {"267011", false}, {"267045", false},
		{"0", true}, {"23", true}, {"-2147024894", true},
	} {
		t.Run(test.code, func(t *testing.T) {
			var output strings.Builder
			writer := csv.NewWriter(&output)
			if err := writer.Write([]string{"host", `\sandbox-local-test`, "N/A", "任意本地化状态", "batch", "date", test.code}); err != nil {
				t.Fatal(err)
			}
			writer.Flush()
			completed, _, err := parseScheduledTaskResult(output.String())
			if err != nil || completed != test.completed {
				t.Fatalf("completed=%v, want %v, error=%v", completed, test.completed, err)
			}
		})
	}
	for _, raw := range []string{"", "one,two", "a,b,c,d,e,f,not-a-number"} {
		if _, _, err := parseScheduledTaskResult(raw); err == nil {
			t.Fatalf("accepted invalid scheduler response %q", raw)
		}
	}
}

func TestTaskBrokerReportsBootstrapFailure(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "request.json"), []byte("invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RunTaskBroker(context.Background(), []string{directory}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "exit.txt"))
	if err != nil {
		t.Fatal(err)
	}
	code, ready, err := parseTaskExit(raw)
	if err != nil || !ready || code != -1 {
		t.Fatalf("code=%d ready=%v err=%v", code, ready, err)
	}
	failure, err := os.ReadFile(filepath.Join(directory, "failure.txt"))
	if err != nil || len(failure) == 0 {
		t.Fatalf("failure=%q err=%v", failure, err)
	}
}

func TestTaskCancellationSignal(t *testing.T) {
	directory := t.TempDir()
	transport := TaskTransport{Directory: directory}
	ctx, stop := taskContext(context.Background(), directory)
	defer stop()
	if err := transport.Cancel(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("controller did not observe cancellation")
	}
}
