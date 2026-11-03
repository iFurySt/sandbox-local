package sandbox

import (
	"context"
	"testing"
)

func TestSeatbeltPolicyRoundTrip(t *testing.T) {
	t.Parallel()
	manager, err := NewManager(Options{BackendPreference: BackendNoop})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	for _, action := range []SeatbeltDefaultAction{"", SeatbeltDefaultDeny, SeatbeltDefaultAllow, "unknown"} {
		req := Request{Command: []string{"echo", "test"}, Policy: Policy{Seatbelt: SeatbeltPolicy{DefaultAction: action}}}
		plan, err := manager.Prepare(context.Background(), req)
		if action == "unknown" {
			if err == nil {
				t.Fatal("invalid action accepted")
			}
			continue
		}
		if err != nil || string(plan.EffectivePolicy.Seatbelt.DefaultAction) != string(action) {
			t.Fatalf("action=%q plan=%+v error=%v", action, plan, err)
		}
	}
}
