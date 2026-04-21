//go:build windows

package backend

import "github.com/iFurySt/sandbox-local/internal/backend/windows"

func platformBackend() Backend {
	return windows.New()
}
