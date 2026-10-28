package appcontainer

import "fmt"

const Environment = "SANDBOX_LOCAL_APPCONTAINER"

type Config struct {
	SID         string `json:"sid"`
	DenySID     string `json:"deny_sid"`
	NetworkOpen bool   `json:"network_open"`
}

type ExitCodeError struct{ Code int }

func (e ExitCodeError) Error() string {
	return fmt.Sprintf("AppContainer command exited with code %d", e.Code)
}
