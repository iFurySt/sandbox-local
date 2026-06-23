package sandbox

import (
	"context"
	"os"

	"github.com/iFurySt/sandbox-local/internal/helpercmd"
	"github.com/iFurySt/sandbox-local/internal/helperprotocol"
)

const HelperCommand = helperprotocol.DispatchCommand

func IsHelperInvocation(args []string) bool {
	return len(args) > 0 && args[0] == HelperCommand
}

func MaybeRunHelper() bool {
	if !IsHelperInvocation(os.Args[1:]) {
		return false
	}
	os.Exit(RunHelper(context.Background(), os.Args[2:]))
	return true
}

func RunHelper(ctx context.Context, args []string) int {
	return helpercmd.Run(ctx, args, os.Stderr)
}
