//go:build !windows

package main

import "os"

func checkDirectoryMetadata(path string) error {
	_, err := os.Stat(path)
	return err
}
