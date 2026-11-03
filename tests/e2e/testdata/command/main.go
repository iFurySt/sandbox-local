package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "argv":
		_ = json.NewEncoder(os.Stdout).Encode(os.Args[2:])
	case "stdin":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "streams":
		count, _ := strconv.Atoi(os.Args[2])
		var wg sync.WaitGroup
		for _, s := range []struct {
			file  *os.File
			value byte
		}{{os.Stdout, 'O'}, {os.Stderr, 'E'}} {
			wg.Add(1)
			go func(f *os.File, b byte) { defer wg.Done(); _, _ = f.Write(bytes.Repeat([]byte{b}, count)) }(s.file, s.value)
		}
		wg.Wait()
	case "exit":
		n, _ := strconv.Atoi(os.Args[2])
		os.Exit(n)
	case "marker-sleep":
		if err := os.WriteFile(os.Args[2], []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
		time.Sleep(60 * time.Second)
	case "descendant":
		fmt.Fprint(os.Stdout, "started")
		child := exec.Command(os.Args[0], "marker-sleep", os.Args[2])
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
		time.Sleep(60 * time.Second)
	case "sleep":
		fmt.Fprint(os.Stdout, "started")
		n, _ := strconv.Atoi(os.Args[2])
		time.Sleep(time.Duration(n) * time.Millisecond)
	case "write":
		if err := os.WriteFile(os.Args[2], []byte("probe"), 0600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
	case "read":
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(9)
		}
		_, _ = os.Stdout.Write(b)
	case "background":
		child := exec.Command(os.Args[0], append([]string{"background-child", os.Args[2]}, os.Args[3:]...)...)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(os.Args) > 3 {
			if err := os.WriteFile(os.Args[3]+".pid", []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
				panic(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				if _, err := os.Stat(os.Args[3]); err == nil {
					break
				}
				if time.Now().After(deadline) {
					panic("background did not open marker")
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		fmt.Fprint(os.Stdout, "foreground")
	case "background-child":
		var marker *os.File
		if len(os.Args) > 3 {
			var err error
			marker, err = os.Create(os.Args[3])
			if err != nil {
				panic(err)
			}
		}
		n, _ := strconv.Atoi(os.Args[2])
		time.Sleep(time.Duration(n) * time.Millisecond)
		if _, err := os.Stdout.Write([]byte("late")); err != nil {
			panic(err)
		}
		if _, err := os.Stderr.Write([]byte("late-error")); err != nil {
			panic(err)
		}
		if marker != nil {
			if _, err := marker.WriteString("survived"); err != nil {
				panic(err)
			}
			if err := marker.Close(); err != nil {
				panic(err)
			}
		}
		time.Sleep(30 * time.Second)
	default:
		os.Exit(3)
	}
}
