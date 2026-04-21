//go:build darwin

package backend

import "github.com/iFurySt/sandbox-local/internal/backend/macos"

func platformBackend() Backend {
	return macos.New()
}
