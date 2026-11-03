package cli

import (
	"github.com/iFurySt/sandbox-local/internal/model"
	"github.com/iFurySt/sandbox-local/pkg/sandbox"
	"testing"
)

func TestSeatbeltPolicyForwarded(t *testing.T) {
	t.Parallel()
	policy := toPublicPolicy(model.Policy{Seatbelt: model.SeatbeltPolicy{DefaultAction: model.SeatbeltDefaultAllow}})
	if policy.Seatbelt.DefaultAction != sandbox.SeatbeltDefaultAllow {
		t.Fatalf("seatbelt policy lost: %+v", policy)
	}
}
