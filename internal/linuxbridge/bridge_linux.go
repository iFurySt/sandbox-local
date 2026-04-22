//go:build linux

package linuxbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func Run(ctx context.Context, listenAddr string, unixSocket string, command []string) error {
	if listenAddr == "" || unixSocket == "" {
		return errors.New("listen address and unix socket are required")
	}
	if len(command) == 0 {
		return errors.New("command is required")
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				forward(conn, unixSocket)
			}()
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append([]string{"__exec-seccomp", "--"}, command...)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	err = cmd.Run()
	_ = ln.Close()
	<-done
	wg.Wait()
	return err
}

func forward(client net.Conn, unixSocket string) {
	defer client.Close()
	upstream, err := net.Dial("unix", unixSocket)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		if c, ok := upstream.(*net.UnixConn); ok {
			_ = c.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		if c, ok := client.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}()
	wg.Wait()
}

func ExecWithSeccomp(command []string) error {
	if len(command) == 0 {
		return errors.New("command is required")
	}
	target := command[0]
	if !strings.ContainsRune(target, rune(os.PathSeparator)) {
		resolved, err := exec.LookPath(target)
		if err != nil {
			return err
		}
		target = resolved
	}
	if err := installNoUnixSocketFilter(); err != nil {
		return err
	}
	return syscall.Exec(target, command, os.Environ())
}

func installNoUnixSocketFilter() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	const (
		retAllow   = 0x7fff0000
		retErrno   = 0x00050000
		ldWAbs     = 0x20
		jmpJEqK    = 0x15
		retK       = 0x06
		arg0Offset = 16
	)
	deny := uint32(retErrno | unix.EPERM)
	filter := []unix.SockFilter{
		{Code: ldWAbs, K: uint32(arg0Offset)},
		{Code: jmpJEqK, Jt: 0, Jf: 1, K: uint32(unix.AF_UNIX)},
		{Code: retK, K: deny},
		{Code: retK, K: retAllow},
	}

	// Only apply the argument filter to socket/socketpair syscalls.
	program := []unix.SockFilter{
		{Code: ldWAbs, K: 0},
		{Code: jmpJEqK, Jt: 0, Jf: 4, K: uint32(unix.SYS_SOCKET)},
	}
	program = append(program, filter...)
	program = append(program,
		unix.SockFilter{Code: ldWAbs, K: 0},
		unix.SockFilter{Code: jmpJEqK, Jt: 0, Jf: 4, K: uint32(unix.SYS_SOCKETPAIR)},
	)
	program = append(program, filter...)
	program = append(program, unix.SockFilter{Code: retK, K: retAllow})

	fprog := unix.SockFprog{
		Len:    uint16(len(program)),
		Filter: &program[0],
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, uintptr(unix.SECCOMP_MODE_FILTER), uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		return err
	}
	return nil
}
