package macos

import (
	"github.com/iFurySt/sandbox-local/internal/model"
	"strings"
	"testing"
)

func TestSeatbeltDefaultAction(t *testing.T) {
	t.Parallel()
	cwd := t.TempDir()
	original, err := buildProfile(model.Policy{}, cwd, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(original, "(version 1)\n(deny default)\n(allow process*)\n(allow sysctl-read)\n") {
		t.Fatal("default baseline changed")
	}
	explicit, err := buildProfile(model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: model.SeatbeltDefaultDeny}}, cwd, 0)
	if err != nil || original != explicit {
		t.Fatalf("explicit deny differs: %v", err)
	}
	_, err = buildProfile(model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: "unknown"}}, cwd, 0)
	if err == nil {
		t.Fatal("invalid action accepted")
	}
}
