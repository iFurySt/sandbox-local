package main

import (
	"context"
	"os"

	"github.com/iFurySt/sandbox-local/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background()))
}
