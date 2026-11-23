package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	syswindows "golang.org/x/sys/windows"
)

func TestInvocationACLCleanupPreservesOtherInvocation(t *testing.T) {
	for _, name := range []string{"first-finishes-first", "second-finishes-first"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			readACL := func() string {
				t.Helper()
				sd, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				return sd.String()
			}
			initial, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := initial.DACL()
			if err != nil {
				t.Fatal(err)
			}
			// Normalize the fixture through the same Win32 setter before
			// recording the baseline. The setter marks the DACL auto-inherited.
			if err := setPathDACL(root, dacl, false); err != nil {
				t.Fatal(err)
			}
			baseline := readACL()
			states := []*sandboxState{{}, {}}
			sids := []string{"S-1-5-21-123-234-345-456", "S-1-5-21-123-234-345-567"}
			for i, value := range sids {
				sid, err := syswindows.StringToSid(value)
				if err != nil {
					t.Fatal(err)
				}
				mode := syswindows.ACCESS_MODE(syswindows.GRANT_ACCESS)
				if i == 1 {
					mode = syswindows.DENY_ACCESS
				}
				entry := syswindows.EXPLICIT_ACCESS{AccessPermissions: syswindows.FILE_WRITE_DATA, AccessMode: mode,
					Trustee: syswindows.TRUSTEE{TrusteeForm: syswindows.TRUSTEE_IS_SID, TrusteeValue: syswindows.TrusteeValueFromSID(sid)}}
				if err := applyPathACL(root, entry, sid, states[i], map[string]struct{}{}, false); err != nil {
					t.Fatal(err)
				}
			}
			first, second := 0, 1
			if name == "second-finishes-first" {
				first, second = second, first
			}
			if err := states[first].Cleanup(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := readACL(); strings.Contains(got, sids[first]) || !strings.Contains(got, sids[second]) {
				t.Fatalf("cleanup changed the other invocation's ACE: %s", got)
			}
			if err := states[second].Cleanup(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := readACL(); got != baseline {
				t.Fatalf("final ACL differs from baseline: %s, want %s", got, baseline)
			}
		})
	}
}

func TestInvocationNullDACLRestoresAfterMultipleEntries(t *testing.T) {
	root := t.TempDir()
	if err := setPathDACL(root, nil, false); err != nil {
		t.Fatal(err)
	}
	state := &sandboxState{}
	snapshots := map[string]struct{}{}
	for _, value := range []string{"S-1-5-21-123-234-345-789", "S-1-15-3-123-234-345"} {
		sid, err := syswindows.StringToSid(value)
		if err != nil {
			t.Fatal(err)
		}
		entry := syswindows.EXPLICIT_ACCESS{AccessPermissions: syswindows.FILE_WRITE_DATA, AccessMode: syswindows.GRANT_ACCESS,
			Trustee: syswindows.TRUSTEE{TrusteeForm: syswindows.TRUSTEE_IS_SID, TrusteeValue: syswindows.TrusteeValueFromSID(sid)}}
		if err := applyPathACL(root, entry, sid, state, snapshots, false); err != nil {
			t.Fatal(err)
		}
	}
	if !state.keepLock || len(state.acls) != 1 || state.acls[0].sid != nil {
		t.Fatalf("null-DACL rollback lost exclusive ownership: %+v", state)
	}
	if err := state.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	sd, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if dacl != nil || (err != nil && !errors.Is(err, syswindows.ERROR_OBJECT_NOT_FOUND)) {
		t.Fatalf("null DACL not restored: %s err=%v", sd.String(), err)
	}
}

func TestInvocationCleanupWaitsForAppContainerACLWriter(t *testing.T) {
	root := t.TempDir()
	value := "S-1-5-21-123-234-345-890"
	sid, err := syswindows.StringToSid(value)
	if err != nil {
		t.Fatal(err)
	}
	state := &sandboxState{}
	entry := syswindows.EXPLICIT_ACCESS{AccessPermissions: syswindows.FILE_WRITE_DATA, AccessMode: syswindows.GRANT_ACCESS,
		Trustee: syswindows.TRUSTEE{TrusteeForm: syswindows.TRUSTEE_IS_SID, TrusteeValue: syswindows.TrusteeValueFromSID(sid)}}
	if err := applyPathACL(root, entry, sid, state, map[string]struct{}{}, false); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockAppContainerACL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlock != nil {
			if err := unlock(); err != nil {
				t.Error(err)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := state.Cleanup(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cleanup did not wait for other ACL writer: %v", err)
	}
	sd, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sd.String(), value) {
		t.Fatalf("cleanup changed ACL outside its lock: %s", sd.String())
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock = nil
	if err := state.Cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
}
