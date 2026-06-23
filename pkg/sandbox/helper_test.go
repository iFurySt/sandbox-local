package sandbox

import (
	"context"
	"testing"
)

func TestIsHelperInvocation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "empty", args: nil, want: false},
		{name: "ordinary command", args: []string{"run"}, want: false},
		{name: "helper command", args: []string{HelperCommand, "__exec-seccomp"}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsHelperInvocation(tt.args); got != tt.want {
				t.Fatalf("IsHelperInvocation(%v) = %t, want %t", tt.args, got, tt.want)
			}
		})
	}
}

func TestRunHelperUnknownCommand(t *testing.T) {
	if code := RunHelper(context.Background(), []string{"__missing"}); code == 0 {
		t.Fatal("RunHelper unexpectedly succeeded for an unknown command")
	}
}
