//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	syswindows "golang.org/x/sys/windows"
)

func TestMetadataAncestorsExcludeExplicitRootsAndVolume(t *testing.T) {
	got := metadataAncestors([]aclPlan{
		{path: `C:\private\workspace`, mode: syswindows.GRANT_ACCESS},
		{path: `c:\private\workspace\nested`, mode: syswindows.GRANT_ACCESS},
		{path: `C:\private\denied`, mode: syswindows.DENY_ACCESS},
		{path: `C:\private\workspace`, mode: syswindows.GRANT_ACCESS},
	})
	if !reflect.DeepEqual(got, []string{`C:\private`}) {
		t.Fatalf("metadata paths = %q", got)
	}
}

func TestAncestorDACLDoesNotPropagateAndRestores(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "unrelated.txt")
	if err := os.WriteFile(child, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := syswindows.GetNamedSecurityInfo(child, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := syswindows.StringToSid("S-1-5-21-1-2-3-4567")
	if err != nil {
		t.Fatal(err)
	}
	state := &sandboxState{}
	entry := syswindows.EXPLICIT_ACCESS{AccessPermissions: syswindows.FILE_READ_ATTRIBUTES | syswindows.FILE_TRAVERSE, AccessMode: syswindows.GRANT_ACCESS, Inheritance: syswindows.OBJECT_INHERIT_ACE | syswindows.CONTAINER_INHERIT_ACE,
		Trustee: syswindows.TRUSTEE{TrusteeForm: syswindows.TRUSTEE_IS_SID, TrusteeValue: syswindows.TrusteeValueFromSID(sid)}}
	parent, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyPathACL(root, entry, state, map[string]struct{}{}, true); err != nil {
		t.Fatal(err)
	}
	for _, restore := range []bool{false, true} {
		if restore {
			if err := state.Cleanup(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		after, err := syswindows.GetNamedSecurityInfo(child, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if before.String() != after.String() {
			t.Fatalf("restore=%v changed child ACL: %s -> %s", restore, before.String(), after.String())
		}
	}
	after, err := syswindows.GetNamedSecurityInfo(root, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if parent.String() != after.String() {
		t.Fatalf("parent not restored: %s -> %s", parent.String(), after.String())
	}
}
