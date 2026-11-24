//go:build windows

package windows

import (
	"context"
	"strings"
	"testing"
	"unicode"

	syswindows "golang.org/x/sys/windows"
)

func TestInvocationCredentialPasswordComplexity(t *testing.T) {
	for _, test := range []struct {
		name string
		fill byte
	}{
		{name: "repeated zero bytes", fill: 0},
		{name: "repeated letter bytes", fill: 0xaa},
		{name: "repeated maximum bytes", fill: 0xff},
	} {
		t.Run(test.name, func(t *testing.T) {
			var entropy [24]byte
			for i := range entropy {
				entropy[i] = test.fill
			}
			username, password := invocationLocalCredential(entropy)
			if len(username) > 20 || len(password) < 32 {
				t.Fatalf("unexpected credential lengths: account=%d password=%d", len(username), len(password))
			}
			for _, token := range strings.Split(username, "-") {
				if len(token) >= 3 && strings.Contains(strings.ToLower(password), strings.ToLower(token)) {
					t.Fatal("password contains a display-name token")
				}
			}
			for _, class := range []struct {
				name  string
				match func(rune) bool
			}{
				{name: "uppercase", match: unicode.IsUpper},
				{name: "lowercase", match: unicode.IsLower},
				{name: "digit", match: unicode.IsDigit},
				{name: "symbol", match: func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }},
			} {
				if !strings.ContainsFunc(password, class.match) {
					t.Errorf("password is missing %s", class.name)
				}
			}
		})
	}
}

func TestInvocationCredentialCreatesLocalUser(t *testing.T) {
	if !syswindows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires elevated Windows account management")
	}
	username, password, err := newInvocationLocalCredential()
	if err != nil {
		t.Fatal(err)
	}
	if err := createInvocationLocalUser(username, password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := deleteInvocationLocalUser(context.Background(), username); err != nil {
			t.Error(err)
		}
	})
	if _, _, err := lookupSID(username); err != nil {
		t.Fatal(err)
	}
}
