//go:build windows

package windows

import (
	"testing"

	"github.com/iFurySt/sandbox-local/internal/model"
	syswindows "golang.org/x/sys/windows"
)

func TestACLGrantAlsoTargetsWriteCapabilitySID(t *testing.T) {
	userSID, err := syswindows.StringToSid("S-1-5-21-1-2-3-4")
	if err != nil {
		t.Fatal(err)
	}
	capabilitySID, err := syswindows.StringToSid("S-1-5-21-5-6-7-8")
	if err != nil {
		t.Fatal(err)
	}
	entries := aclEntries(aclPlan{mode: syswindows.GRANT_ACCESS, mask: syswindows.FILE_GENERIC_WRITE}, 0, userSID, capabilitySID)
	if len(entries) != 2 {
		t.Fatalf("grant entries = %d, want 2", len(entries))
	}
	if entries[0].Trustee.TrusteeValue != syswindows.TrusteeValueFromSID(userSID) {
		t.Fatal("first grant does not target the sandbox account")
	}
	if entries[1].Trustee.TrusteeValue != syswindows.TrusteeValueFromSID(capabilitySID) {
		t.Fatal("second grant does not target the write capability SID")
	}
}

func TestACLDenyDoesNotTargetWriteCapabilitySID(t *testing.T) {
	userSID, err := syswindows.StringToSid("S-1-5-21-1-2-3-4")
	if err != nil {
		t.Fatal(err)
	}
	capabilitySID, err := syswindows.StringToSid("S-1-5-21-5-6-7-8")
	if err != nil {
		t.Fatal(err)
	}
	entries := aclEntries(aclPlan{mode: syswindows.DENY_ACCESS, mask: syswindows.FILE_WRITE_DATA}, 0, userSID, capabilitySID)
	if len(entries) != 1 {
		t.Fatalf("deny entries = %d, want 1", len(entries))
	}
}

func TestWriteDenyDoesNotBlockReads(t *testing.T) {
	t.Parallel()
	cwd := `C:\workspace`
	plans, _, err := filesystemPlans(model.FilesystemPolicy{
		ReadAllow: []string{cwd},
		WriteDeny: []string{cwd},
	}, cwd)
	if err != nil {
		t.Fatalf("filesystemPlans() error = %v", err)
	}
	var denyMask syswindows.ACCESS_MASK
	for _, plan := range plans {
		if plan.label == "write deny" && plan.path == cwd {
			denyMask = plan.mask
			break
		}
	}
	if denyMask == 0 {
		t.Fatal("write deny plan not found")
	}
	readMask := syswindows.ACCESS_MASK(syswindows.FILE_GENERIC_READ | syswindows.FILE_GENERIC_EXECUTE)
	if overlap := denyMask & readMask; overlap != 0 {
		t.Fatalf("write deny mask %#x overlaps read/execute mask %#x by %#x", denyMask, readMask, overlap)
	}
	wantWriteMask := syswindows.ACCESS_MASK(
		syswindows.FILE_WRITE_DATA |
			syswindows.FILE_APPEND_DATA |
			syswindows.FILE_WRITE_EA |
			syswindows.FILE_WRITE_ATTRIBUTES |
			syswindows.DELETE |
			fileDeleteChild |
			syswindows.WRITE_DAC |
			syswindows.WRITE_OWNER)
	if denyMask != wantWriteMask {
		t.Fatalf("write deny mask = %#x, want %#x", denyMask, wantWriteMask)
	}
}

func TestFilesystemPlansDoNotModifyAncestors(t *testing.T) {
	t.Parallel()
	cwd := `C:\Users\Administrator\AppData\Local\HiWork\workspace`
	plans, _, err := filesystemPlans(model.FilesystemPolicy{
		ReadAllow:  []string{cwd},
		WriteAllow: []string{cwd},
	}, cwd)
	if err != nil {
		t.Fatalf("filesystemPlans() error = %v", err)
	}
	for _, plan := range plans {
		if plan.label == "traverse grant" {
			t.Fatalf("filesystemPlans() modifies ancestor ACL %q", plan.path)
		}
		if plan.path != cwd {
			t.Fatalf("filesystemPlans() modifies %q outside the explicit policy path %q", plan.path, cwd)
		}
	}
}
