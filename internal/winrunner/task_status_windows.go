//go:build windows

package winrunner

import (
	"context"
	"encoding/csv"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func scheduledTaskCompleted(ctx context.Context, name string) (bool, uint32, error) {
	raw, err := exec.CommandContext(ctx, "schtasks.exe", "/Query", "/TN", name, "/V", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return false, 0, fmt.Errorf("query scheduled-task completion: %w", err)
	}
	return parseScheduledTaskResult(string(raw))
}

func parseScheduledTaskResult(raw string) (bool, uint32, error) {
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(raw, "\ufeff")))
	row, err := reader.Read()
	if err != nil || len(row) < 7 {
		return false, 0, fmt.Errorf("invalid scheduled-task status response")
	}
	// /V CSV columns are ordered by schtasks, independent of translated labels
	// and state names. Last Result is a numeric HRESULT or action exit code.
	value, err := strconv.ParseInt(strings.TrimSpace(row[6]), 0, 64)
	if err != nil {
		return false, 0, fmt.Errorf("invalid scheduled-task result code: %w", err)
	}
	result := uint32(value)
	const (
		taskRunning   = 0x41301
		taskNotYetRun = 0x41303
		taskQueued    = 0x41325
	)
	return result != taskRunning && result != taskNotYetRun && result != taskQueued, result, nil
}
