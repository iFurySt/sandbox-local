//go:build !darwin && !linux && !windows

package backend

func platformBackend() Backend {
	return NewNoopBackend()
}
