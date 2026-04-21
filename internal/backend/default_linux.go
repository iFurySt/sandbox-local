//go:build linux

package backend

import "github.com/iFurySt/sandbox-local/internal/backend/linux"

func platformBackend() Backend {
	return linux.New()
}
