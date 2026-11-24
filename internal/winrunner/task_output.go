package winrunner

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// taskOutputCursor forwards new bytes from a broker-owned append-only file.
// It is used only by the task waiter; failures do not interrupt task cleanup.
type taskOutputCursor struct {
	path   string
	out    io.Writer
	offset int64
	err    error
}

func (c *taskOutputCursor) drain(limit int64) {
	if c.err != nil {
		return
	}
	file, err := os.Open(c.path)
	if errors.Is(err, os.ErrNotExist) && c.offset == 0 {
		return // The broker may not have opened its output file yet.
	}
	if err != nil {
		c.err = fmt.Errorf("open Windows broker output: %w", err)
		return
	}
	c.err = errors.Join(c.copyAvailable(file, limit), file.Close())
}

func (c *taskOutputCursor) copyAvailable(file *os.File, limit int64) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat Windows broker output: %w", err)
	}
	remaining := info.Size() - c.offset
	if remaining < 0 {
		return errors.New("Windows broker output was truncated")
	}
	if remaining == 0 {
		return nil
	}
	if limit > 0 {
		remaining = min(remaining, limit)
	}
	n, err := io.CopyN(c.out, io.NewSectionReader(file, c.offset, remaining), remaining)
	c.offset += n
	if err != nil {
		return fmt.Errorf("forward Windows broker output: %w", err)
	}
	return nil
}
