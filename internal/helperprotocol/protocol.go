package helperprotocol

const (
	DispatchCommand      = "__sandbox-local-helper"
	ProxyBridgeCommand   = "__proxy-bridge"
	ExecSeccompCommand   = "__exec-seccomp"
	WindowsRunnerCommand = "__windows-runner"
)

func Wrap(command string, args ...string) []string {
	wrapped := make([]string, 0, 2+len(args))
	wrapped = append(wrapped, DispatchCommand, command)
	wrapped = append(wrapped, args...)
	return wrapped
}
