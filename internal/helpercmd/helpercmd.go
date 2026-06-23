package helpercmd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/iFurySt/sandbox-local/internal/helperprotocol"
	"github.com/iFurySt/sandbox-local/internal/linuxbridge"
	"github.com/iFurySt/sandbox-local/internal/winrunner"
)

func Run(ctx context.Context, args []string, errOut io.Writer) int {
	if errOut == nil {
		errOut = os.Stderr
	}
	if err := run(ctx, args); err != nil {
		var exitErr winrunner.ExitCodeError
		if errors.As(err, &exitErr) {
			return exitErr.Code
		}
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("sandbox-local helper command is required")
	}
	command := args[0]
	rest := args[1:]
	switch command {
	case helperprotocol.ProxyBridgeCommand:
		return runProxyBridge(ctx, rest)
	case helperprotocol.ExecSeccompCommand:
		return linuxbridge.ExecWithSeccomp(stripSeparator(rest))
	case helperprotocol.WindowsRunnerCommand:
		return winrunner.Run(ctx, stripSeparator(rest))
	default:
		return fmt.Errorf("unknown sandbox-local helper command %q", command)
	}
}

func runProxyBridge(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet(helperprotocol.ProxyBridgeCommand, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	listen := flags.String("listen", "", "loopback listen address")
	socket := flags.String("unix", "", "upstream Unix socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return linuxbridge.Run(ctx, *listen, *socket, flags.Args())
}

func stripSeparator(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}
