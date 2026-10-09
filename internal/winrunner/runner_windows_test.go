//go:build windows

package winrunner

import "testing"

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
