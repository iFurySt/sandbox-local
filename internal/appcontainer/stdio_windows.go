//go:build windows

package appcontainer

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// Console handles cannot be used by a CREATE_NO_WINDOW child. Always give
// the contained process pipes, even when the SDK itself runs in a console.
type pipeStdio struct {
	files   []*os.File
	child   []*os.File
	results chan error
}

func newPipeStdio(sid *windows.SID) (*pipeStdio, error) {
	s := &pipeStdio{results: make(chan error, 2)}
	security, err := objectSecurity(sid)
	if err != nil {
		return nil, err
	}
	pipe := func() (*os.File, *os.File, error) {
		var read, write windows.Handle
		if err := windows.CreatePipe(&read, &write, security, 0); err != nil {
			return nil, nil, err
		}
		return os.NewFile(uintptr(read), "sandbox-stdin"), os.NewFile(uintptr(write), "sandbox-stdout"), nil
	}
	stdin, input, err := pipe()
	if err != nil {
		return nil, err
	}
	s.files = append(s.files, stdin, input)
	out, stdout, err := pipe()
	if err != nil {
		s.close()
		return nil, err
	}
	s.files = append(s.files, out, stdout)
	errout, stderr, err := pipe()
	if err != nil {
		s.close()
		return nil, err
	}
	s.files = append(s.files, errout, stderr)
	s.child = []*os.File{stdin, stdout, stderr}
	go func() { _, _ = io.Copy(input, os.Stdin); _ = input.Close() }()
	go func() { _, err := io.Copy(os.Stdout, out); s.results <- err }()
	go func() { _, err := io.Copy(os.Stderr, errout); s.results <- err }()
	return s, nil
}

func (s *pipeStdio) closeChild() {
	for _, file := range s.child {
		_ = file.Close()
	}
}

func (s *pipeStdio) wait() error {
	return errors.Join(<-s.results, <-s.results)
}

func (s *pipeStdio) close() {
	for _, file := range s.files {
		_ = file.Close()
	}
}
