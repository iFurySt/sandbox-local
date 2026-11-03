package main

import (
	"context"
	"os"

	"github.com/iFurySt/sandbox-local/internal/cli"
	"github.com/iFurySt/sandbox-local/pkg/sandbox"
)

func main() {
	sandbox.MaybeRunHelper()
	os.Exit(cli.Execute(context.Background()))
}
