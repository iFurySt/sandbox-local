//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/iFurySt/sandbox-local/internal/fsx"
	"github.com/iFurySt/sandbox-local/internal/model"
	syswindows "golang.org/x/sys/windows"
)

const (
	backendName = "windows-local-user"

	envWindowsUser     = "SANDBOX_LOCAL_WINDOWS_USER"
	envWindowsPassword = "SANDBOX_LOCAL_WINDOWS_PASSWORD"
	envWindowsDomain   = "SANDBOX_LOCAL_WINDOWS_DOMAIN"
	envWindowsRequest  = "SANDBOX_LOCAL_WINDOWS_REQUEST_ENV"

	fileDeleteChild syswindows.ACCESS_MASK = 0x40
)

type Backend struct{}

func New() Backend {
	return Backend{}
}

func (Backend) Name() string {
	return backendName
}

func (Backend) Platform() string {
	return runtime.GOOS
}

func (b Backend) Check(ctx context.Context) model.CapabilityReport {
	report := model.CapabilityReport{
		Backend:      b.Name(),
		Platform:     b.Platform(),
		Available:    true,
		Sandboxed:    true,
		NetworkModes: []string{string(model.NetworkOffline), string(model.NetworkOpen)},
		Warnings:     []string{"network allowlist is not supported by the Windows backend yet"},
		Notes:        []string{"Windows enforcement uses a temporary local user, filesystem ACLs, Job Object cleanup, and outbound firewall rules for offline mode"},
	}
	for _, name := range []string{"net.exe", "powershell.exe"} {
		if _, err := exec.LookPath(name); err != nil {
			report.Available = false
			report.Sandboxed = false
			report.Missing = append(report.Missing, name)
		}
	}
	if err := exec.CommandContext(ctx, "net", "session").Run(); err != nil {
		report.Available = false
		report.Sandboxed = false
		report.Missing = append(report.Missing, "elevated administrator token")
		report.Warnings = append(report.Warnings, "Windows sandbox setup needs elevation to create temporary users, edit ACLs, and manage firewall rules")
	}
	return report
}

func (b Backend) Prepare(ctx context.Context, req model.Request) (model.PreparedCommand, model.Cleanup, error) {
	if len(req.Command) == 0 {
		return model.PreparedCommand{}, nil, fmt.Errorf("command is required")
	}
	if req.Policy.Network.Mode == model.NetworkAllowlist {
		return model.PreparedCommand{}, nil, fmt.Errorf("backend %q does not support network allowlist enforcement", b.Name())
	}
	cwd := req.Cwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return model.PreparedCommand{}, nil, err
		}
	}
	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	report := b.Check(ctx)
	if !report.Available {
		return model.PreparedCommand{}, nil, fmt.Errorf("backend %q is unavailable: %s", b.Name(), strings.Join(report.Missing, ", "))
	}
	state, warnings, err := setup(ctx, req.Policy, absCwd)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		_ = state.Cleanup(context.Background())
		return model.PreparedCommand{}, nil, err
	}
	requestEnv, err := json.Marshal(req.Env)
	if err != nil {
		_ = state.Cleanup(context.Background())
		return model.PreparedCommand{}, nil, err
	}
	env := map[string]string{}
	env[envWindowsUser] = state.username
	env[envWindowsPassword] = state.password
	env[envWindowsDomain] = "."
	env[envWindowsRequest] = string(requestEnv)
	command := []string{exe, "__windows-runner", "--"}
	command = append(command, req.Command...)
	return model.PreparedCommand{
		Backend:  b.Name(),
		Platform: b.Platform(),
		Command:  command,
		Cwd:      absCwd,
		Env:      env,
		Warnings: append(warnings, report.Warnings...),
	}, state.Cleanup, nil
}

type sandboxState struct {
	username  string
	password  string
	sidString string
	ruleName  string
	acls      []aclSnapshot
	lock      syswindows.Handle
}

type aclSnapshot struct {
	path string
	sddl string
}

func setup(ctx context.Context, policy model.Policy, cwd string) (*sandboxState, []string, error) {
	lock, err := acquireSetupLock()
	if err != nil {
		return nil, nil, err
	}
	username, password, err := newLocalCredential()
	if err != nil {
		_ = syswindows.CloseHandle(lock)
		return nil, nil, err
	}
	state := &sandboxState{username: username, password: password, lock: lock}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			_ = state.Cleanup(context.Background())
		}
	}()

	if err := createLocalUser(ctx, username, password); err != nil {
		return nil, nil, err
	}
	sid, sidString, err := lookupSID(username)
	if err != nil {
		return nil, nil, err
	}
	state.sidString = sidString
	warnings, err := applyFilesystemPolicy(policy.Filesystem, cwd, sid, state)
	if err != nil {
		return nil, nil, err
	}
	switch policy.Network.Mode {
	case "", model.NetworkOffline:
		ruleName := "sandbox-local-" + username
		if err := addOfflineFirewallRule(ctx, ruleName, sidString); err != nil {
			return nil, nil, err
		}
		state.ruleName = ruleName
	case model.NetworkOpen:
	default:
		return nil, nil, fmt.Errorf("unsupported network mode %q", policy.Network.Mode)
	}

	cleanupOnError = false
	return state, warnings, nil
}

func (s *sandboxState) Cleanup(ctx context.Context) error {
	var errs []error
	if s.ruleName != "" {
		if err := removeFirewallRule(ctx, s.ruleName); err != nil {
			errs = append(errs, err)
		}
	}
	for i := len(s.acls) - 1; i >= 0; i-- {
		if err := restoreACL(s.acls[i]); err != nil {
			errs = append(errs, err)
		}
	}
	if s.username != "" {
		if err := deleteLocalUser(ctx, s.username); err != nil {
			errs = append(errs, err)
		}
		if err := removeLocalUserProfile(ctx, s.username); err != nil {
			errs = append(errs, err)
		}
	}
	if s.lock != 0 {
		if err := syswindows.ReleaseMutex(s.lock); err != nil {
			errs = append(errs, err)
		}
		if err := syswindows.CloseHandle(s.lock); err != nil {
			errs = append(errs, err)
		}
		s.lock = 0
	}
	return errors.Join(errs...)
}

func acquireSetupLock() (syswindows.Handle, error) {
	name, err := syswindows.UTF16PtrFromString(`Local\sandbox-local-windows-backend`)
	if err != nil {
		return 0, err
	}
	lock, err := syswindows.CreateMutex(nil, false, name)
	if err != nil && !(errors.Is(err, syswindows.ERROR_ALREADY_EXISTS) && lock != 0) {
		return 0, err
	}
	if _, err := syswindows.WaitForSingleObject(lock, syswindows.INFINITE); err != nil {
		_ = syswindows.CloseHandle(lock)
		return 0, err
	}
	return lock, nil
}

func applyFilesystemPolicy(policy model.FilesystemPolicy, cwd string, sid *syswindows.SID, state *sandboxState) ([]string, error) {
	plans, warnings, err := filesystemPlans(policy, cwd)
	if err != nil {
		return nil, err
	}
	snapshots := map[string]struct{}{}
	for _, plan := range plans {
		info, err := os.Stat(plan.path)
		if err != nil {
			if plan.required {
				return nil, fmt.Errorf("%s path %q is not available: %w", plan.label, plan.path, err)
			}
			warnings = append(warnings, fmt.Sprintf("%s path %q does not exist and was not applied", plan.label, plan.path))
			continue
		}
		inheritance := uint32(0)
		if info.IsDir() && plan.inherit {
			inheritance = syswindows.OBJECT_INHERIT_ACE | syswindows.CONTAINER_INHERIT_ACE
		}
		entry := syswindows.EXPLICIT_ACCESS{
			AccessPermissions: plan.mask,
			AccessMode:        plan.mode,
			Inheritance:       inheritance,
			Trustee: syswindows.TRUSTEE{
				TrusteeForm:  syswindows.TRUSTEE_IS_SID,
				TrusteeType:  syswindows.TRUSTEE_IS_USER,
				TrusteeValue: syswindows.TrusteeValueFromSID(sid),
			},
		}
		if err := applyACL(plan.path, entry, state, snapshots); err != nil {
			return nil, fmt.Errorf("apply %s ACL to %q: %w", plan.label, plan.path, err)
		}
	}
	return warnings, nil
}

type aclPlan struct {
	path     string
	label    string
	mode     syswindows.ACCESS_MODE
	mask     syswindows.ACCESS_MASK
	inherit  bool
	required bool
}

func filesystemPlans(policy model.FilesystemPolicy, cwd string) ([]aclPlan, []string, error) {
	var plans []aclPlan
	readAllow, err := fsx.AbsList(append([]string{cwd}, policy.ReadAllow...), cwd)
	if err != nil {
		return nil, nil, err
	}
	writeAllow, err := fsx.AbsList(policy.WriteAllow, cwd)
	if err != nil {
		return nil, nil, err
	}
	writeDeny, err := fsx.AbsList(policy.WriteDeny, cwd)
	if err != nil {
		return nil, nil, err
	}
	readDeny, err := fsx.AbsList(policy.ReadDeny, cwd)
	if err != nil {
		return nil, nil, err
	}

	ancestorSet := map[string]struct{}{}
	for _, path := range append(append([]string{}, readAllow...), writeAllow...) {
		for _, ancestor := range ancestors(path) {
			ancestorSet[ancestor] = struct{}{}
		}
	}
	ancestorsList := make([]string, 0, len(ancestorSet))
	for path := range ancestorSet {
		ancestorsList = append(ancestorsList, path)
	}
	slices.Sort(ancestorsList)
	for _, path := range ancestorsList {
		plans = append(plans, aclPlan{
			path:     path,
			label:    "traverse grant",
			mode:     syswindows.GRANT_ACCESS,
			mask:     syswindows.ACCESS_MASK(syswindows.FILE_TRAVERSE | syswindows.FILE_READ_ATTRIBUTES | syswindows.READ_CONTROL | syswindows.SYNCHRONIZE),
			inherit:  false,
			required: false,
		})
	}
	for _, path := range readAllow {
		plans = append(plans, aclPlan{
			path:     path,
			label:    "read grant",
			mode:     syswindows.GRANT_ACCESS,
			mask:     syswindows.ACCESS_MASK(syswindows.FILE_GENERIC_READ | syswindows.FILE_GENERIC_EXECUTE),
			inherit:  true,
			required: true,
		})
	}
	for _, path := range writeAllow {
		plans = append(plans, aclPlan{
			path:     path,
			label:    "write grant",
			mode:     syswindows.GRANT_ACCESS,
			mask:     syswindows.ACCESS_MASK(syswindows.FILE_GENERIC_READ|syswindows.FILE_GENERIC_WRITE|syswindows.FILE_GENERIC_EXECUTE) | syswindows.DELETE | fileDeleteChild,
			inherit:  true,
			required: true,
		})
	}
	for _, path := range writeDeny {
		plans = append(plans, aclPlan{
			path:    path,
			label:   "write deny",
			mode:    syswindows.DENY_ACCESS,
			mask:    syswindows.ACCESS_MASK(syswindows.FILE_GENERIC_WRITE) | syswindows.DELETE | fileDeleteChild | syswindows.WRITE_DAC | syswindows.WRITE_OWNER,
			inherit: true,
		})
	}
	for _, path := range readDeny {
		plans = append(plans, aclPlan{
			path:    path,
			label:   "read deny",
			mode:    syswindows.DENY_ACCESS,
			mask:    syswindows.ACCESS_MASK(syswindows.FILE_GENERIC_READ|syswindows.FILE_GENERIC_EXECUTE|syswindows.FILE_GENERIC_WRITE) | syswindows.DELETE | fileDeleteChild,
			inherit: true,
		})
	}
	return plans, nil, nil
}

func applyACL(path string, entry syswindows.EXPLICIT_ACCESS, state *sandboxState, snapshots map[string]struct{}) error {
	key := strings.ToLower(path)
	if _, ok := snapshots[key]; !ok {
		sd, err := syswindows.GetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		state.acls = append(state.acls, aclSnapshot{path: path, sddl: sd.String()})
		snapshots[key] = struct{}{}
	}
	sd, err := syswindows.GetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, syswindows.ERROR_OBJECT_NOT_FOUND) {
		return err
	}
	newACL, err := syswindows.ACLFromEntries([]syswindows.EXPLICIT_ACCESS{entry}, dacl)
	if err != nil {
		return err
	}
	return syswindows.SetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION, nil, nil, newACL, nil)
}

func restoreACL(snapshot aclSnapshot) error {
	sd, err := syswindows.SecurityDescriptorFromString(snapshot.sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, syswindows.ERROR_OBJECT_NOT_FOUND) {
		return err
	}
	return syswindows.SetNamedSecurityInfo(snapshot.path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func ancestors(path string) []string {
	cleaned := filepath.Clean(path)
	var out []string
	for {
		parent := filepath.Dir(cleaned)
		if parent == cleaned || parent == "." || parent == "" {
			break
		}
		out = append(out, parent)
		cleaned = parent
	}
	slices.Reverse(out)
	return out
}

func createLocalUser(ctx context.Context, username string, password string) error {
	cmd := exec.CommandContext(ctx, "net", "user", username, password, "/add", "/expires:never", "/passwordchg:no")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create temporary Windows user: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func deleteLocalUser(ctx context.Context, username string) error {
	cmd := exec.CommandContext(ctx, "net", "user", username, "/delete")
	if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "could not be found") {
		return fmt.Errorf("delete temporary Windows user: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func lookupSID(username string) (*syswindows.SID, string, error) {
	sid, _, typ, err := syswindows.LookupSID("", username)
	if err != nil {
		return nil, "", err
	}
	if typ != syswindows.SidTypeUser {
		return nil, "", fmt.Errorf("temporary account %q resolved to SID type %d", username, typ)
	}
	return sid, sid.String(), nil
}

func addOfflineFirewallRule(ctx context.Context, ruleName string, sid string) error {
	localUserSDDL := "D:(A;;CC;;;" + sid + ")"
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		fmt.Sprintf(
			"New-NetFirewallRule -DisplayName '%s' -Direction Outbound -Action Block -LocalUser '%s' | Out-Null",
			escapePowerShellSingleQuoted(ruleName),
			escapePowerShellSingleQuoted(localUserSDDL),
		),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create offline firewall rule: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeFirewallRule(ctx context.Context, ruleName string) error {
	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command",
		fmt.Sprintf(
			"Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue",
			escapePowerShellSingleQuoted(ruleName),
		),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove offline firewall rule: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func newLocalCredential() (string, string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", err
	}
	suffix := hex.EncodeToString(randomBytes[:4])
	username := "sbx" + suffix
	password := "Sbx!" + hex.EncodeToString(randomBytes[:4]) + "9"
	return username, password, nil
}

func localUserProfilePath(username string) string {
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	return filepath.Join(systemDrive+`\`, "Users", username)
}

func removeLocalUserProfile(ctx context.Context, username string) error {
	path := localUserProfilePath(username)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var lastErr error
	for range 6 {
		cmd := exec.CommandContext(ctx, "cmd.exe", "/c", "rmdir", "/s", "/q", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			lastErr = fmt.Errorf("remove temporary Windows profile: %w: %s", err, strings.TrimSpace(string(out)))
		} else if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("remove temporary Windows profile: %s still exists", path)
}

func cloneMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
