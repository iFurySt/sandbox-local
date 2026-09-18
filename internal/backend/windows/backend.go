//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/iFurySt/sandbox-local/internal/fsx"
	"github.com/iFurySt/sandbox-local/internal/helper"
	"github.com/iFurySt/sandbox-local/internal/helperprotocol"
	"github.com/iFurySt/sandbox-local/internal/model"
	syswindows "golang.org/x/sys/windows"
)

const (
	backendName = "windows-local-user"

	envWindowsUser               = "SANDBOX_LOCAL_WINDOWS_USER"
	envWindowsPassword           = "SANDBOX_LOCAL_WINDOWS_PASSWORD"
	envWindowsDomain             = "SANDBOX_LOCAL_WINDOWS_DOMAIN"
	envWindowsRequest            = "SANDBOX_LOCAL_WINDOWS_REQUEST_ENV"
	envWindowsWriteCapabilitySID = "SANDBOX_LOCAL_WINDOWS_WRITE_CAPABILITY_SID"

	fileDeleteChild syswindows.ACCESS_MASK = 0x40

	policyCreateAccount = 0x00000010
	policyLookupNames   = 0x00000800

	seBatchLogonRight = "SeBatchLogonRight"
	sandboxUsername   = "sandboxlocal"
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
		NetworkModes: []string{string(model.NetworkOffline), string(model.NetworkAllowlist), string(model.NetworkOpen)},
		Warnings:     []string{"Windows network allowlist uses a host-managed proxy plus per-user outbound firewall blocking; loopback remains available for the managed proxy"},
		Notes:        []string{"Windows uses a disabled local runner account plus a fresh per-run capability SID, a write-restricted token, filesystem ACLs, a one-shot scheduled task, and per-user outbound firewall rules"},
	}
	for _, name := range []string{"net.exe", "powershell.exe", "schtasks.exe"} {
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
		report.Warnings = append(report.Warnings, "Windows sandbox setup needs elevation to manage sandboxlocal, edit ACLs, create scheduled tasks, and manage firewall rules")
	}
	return report
}

func (b Backend) Setup(ctx context.Context) (model.SetupReport, error) {
	report := model.SetupReport{
		Backend:  b.Name(),
		Platform: b.Platform(),
		Ready:    true,
		Notes: []string{
			"setup leaves the sandboxlocal account disabled after provisioning",
			"OpenSSH Server is only required for remote validation, not for local SDK usage",
		},
	}
	check := b.Check(ctx)
	report.Missing = append(report.Missing, check.Missing...)
	report.Warnings = append(report.Warnings, check.Warnings...)
	report.Notes = append(report.Notes, check.Notes...)
	if !check.Available {
		report.Ready = false
		return report, fmt.Errorf("backend %q is unavailable: %s", b.Name(), strings.Join(check.Missing, ", "))
	}
	if status, err := windowsServiceStatus(ctx, "Schedule"); err != nil {
		report.Ready = false
		report.Missing = append(report.Missing, "Task Scheduler service")
		return report, err
	} else if !strings.EqualFold(status, "Running") {
		report.Ready = false
		report.Missing = append(report.Missing, "Task Scheduler service running")
		return report, fmt.Errorf("Task Scheduler service is %s", status)
	}
	if status, err := windowsServiceStatus(ctx, "MpsSvc"); err != nil {
		report.Ready = false
		report.Missing = append(report.Missing, "Windows Firewall service")
		return report, err
	} else if !strings.EqualFold(status, "Running") {
		report.Ready = false
		report.Missing = append(report.Missing, "Windows Firewall service running")
		return report, fmt.Errorf("Windows Firewall service is %s", status)
	}
	if _, err := powerShellOutput(ctx, "Get-Command New-NetFirewallRule -ErrorAction Stop | Out-Null; 'ok'"); err != nil {
		report.Ready = false
		report.Missing = append(report.Missing, "New-NetFirewallRule")
		return report, err
	}
	if status, err := windowsServiceStatus(ctx, "sshd"); err != nil {
		report.Warnings = append(report.Warnings, "OpenSSH Server service is not installed or not readable")
	} else if !strings.EqualFold(status, "Running") {
		report.Warnings = append(report.Warnings, fmt.Sprintf("OpenSSH Server service is %s", status))
	}

	lock, err := acquireSetupLock()
	if err != nil {
		report.Ready = false
		return report, err
	}
	state := &sandboxState{lock: lock}
	defer state.releaseLockOnly()

	username, password, err := newLocalCredential()
	if err != nil {
		report.Ready = false
		return report, err
	}
	existed := localUserExists(ctx, username)
	if err := createLocalUser(ctx, username, password); err != nil {
		report.Ready = false
		return report, err
	}
	report.Changed = true
	if existed {
		report.Actions = append(report.Actions, "reset sandboxlocal password")
	} else {
		report.Actions = append(report.Actions, "created sandboxlocal user")
	}
	sid, _, err := lookupSID(username)
	if err != nil {
		report.Ready = false
		return report, err
	}
	if err := grantAccountRight(sid, seBatchLogonRight); err != nil {
		report.Ready = false
		return report, fmt.Errorf("grant batch logon right to sandbox Windows user: %w", err)
	}
	report.Actions = append(report.Actions, "granted SeBatchLogonRight to sandboxlocal")
	if err := disableLocalUser(ctx, username); err != nil {
		report.Ready = false
		return report, err
	}
	report.Actions = append(report.Actions, "disabled sandboxlocal user")
	report.Ready = true
	return report, nil
}

func (b Backend) Prepare(ctx context.Context, req model.Request) (model.PreparedCommand, model.Cleanup, error) {
	if len(req.Command) == 0 {
		return model.PreparedCommand{}, nil, fmt.Errorf("command is required")
	}
	cwd := req.Cwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return model.PreparedCommand{}, nil, err
		}
	}
	absCwd, err := fsx.Abs(cwd, "")
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	report := b.Check(ctx)
	if !report.Available {
		return model.PreparedCommand{}, nil, fmt.Errorf("backend %q is unavailable: %s", b.Name(), strings.Join(report.Missing, ", "))
	}
	state, warnings, err := setup(ctx, req.Policy, absCwd, req.ManagedProxyPort)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	exe, err := helper.Resolve(req.HelperPath)
	if err != nil {
		_ = state.Cleanup(context.WithoutCancel(ctx))
		return model.PreparedCommand{}, nil, err
	}
	requestEnv, err := json.Marshal(req.Env)
	if err != nil {
		_ = state.Cleanup(context.WithoutCancel(ctx))
		return model.PreparedCommand{}, nil, err
	}
	env := map[string]string{}
	env[envWindowsUser] = state.username
	env[envWindowsPassword] = state.password
	env[envWindowsDomain] = "."
	env[envWindowsRequest] = string(requestEnv)
	env[envWindowsWriteCapabilitySID] = state.writeCapabilitySID
	command := []string{exe, helperprotocol.DispatchCommand, helperprotocol.WindowsRunnerCommand, "--"}
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
	username           string
	password           string
	sidString          string
	writeCapabilitySID string
	ruleName           string
	acls               []aclSnapshot
	lock               syswindows.Handle
}

type aclSnapshot struct {
	path string
	sddl string
}

func setup(ctx context.Context, policy model.Policy, cwd string, managedProxyPort int) (*sandboxState, []string, error) {
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
			_ = state.Cleanup(context.WithoutCancel(ctx))
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
	writeCapabilitySID, err := newCapabilitySID()
	if err != nil {
		return nil, nil, err
	}
	state.writeCapabilitySID = writeCapabilitySID.String()
	if err := grantAccountRight(sid, seBatchLogonRight); err != nil {
		return nil, nil, fmt.Errorf("grant batch logon right to sandbox Windows user: %w", err)
	}
	warnings, err := applyFilesystemPolicy(policy.Filesystem, cwd, sid, writeCapabilitySID, state)
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
	case model.NetworkAllowlist:
		if managedProxyPort <= 0 {
			return nil, nil, fmt.Errorf("network allowlist requires a managed proxy port")
		}
		ruleName := "sandbox-local-" + username
		if err := addOfflineFirewallRule(ctx, ruleName, sidString); err != nil {
			return nil, nil, err
		}
		state.ruleName = ruleName
		warnings = append(warnings, fmt.Sprintf("Windows allowlist is enforced through HTTP_PROXY/HTTPS_PROXY on 127.0.0.1:%d and a per-user outbound firewall block", managedProxyPort))
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
		if err := disableLocalUser(ctx, s.username); err != nil {
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

func (s *sandboxState) releaseLockOnly() {
	if s.lock == 0 {
		return
	}
	_ = syswindows.ReleaseMutex(s.lock)
	_ = syswindows.CloseHandle(s.lock)
	s.lock = 0
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

func applyFilesystemPolicy(policy model.FilesystemPolicy, cwd string, sid, writeCapabilitySID *syswindows.SID, state *sandboxState) ([]string, error) {
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
		entries := aclEntries(plan, inheritance, sid, writeCapabilitySID)
		if err := applyACL(plan.path, entries[0], state, snapshots); err != nil {
			return nil, fmt.Errorf("apply %s ACL to %q: %w", plan.label, plan.path, err)
		}
		if len(entries) == 2 {
			entry := entries[1]
			if err := applyACL(plan.path, entry, state, snapshots); err != nil {
				return nil, fmt.Errorf("apply %s capability ACL to %q: %w", plan.label, plan.path, err)
			}
		}
	}
	return warnings, nil
}

func aclEntries(plan aclPlan, inheritance uint32, sid, writeCapabilitySID *syswindows.SID) []syswindows.EXPLICIT_ACCESS {
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
	entries := []syswindows.EXPLICIT_ACCESS{entry}
	if plan.mode == syswindows.GRANT_ACCESS {
		entry.Trustee.TrusteeValue = syswindows.TrusteeValueFromSID(writeCapabilitySID)
		entries = append(entries, entry)
	}
	return entries
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
			path:  path,
			label: "write deny",
			mode:  syswindows.DENY_ACCESS,
			// Deny only data-mutation rights. FILE_GENERIC_WRITE must not be
			// used here: its STANDARD_RIGHTS_WRITE component is READ_CONTROL,
			// and the generic mapping also pulls in SYNCHRONIZE. A read-only
			// open requests GENERIC_READ, which maps to FILE_READ_DATA plus
			// READ_CONTROL and SYNCHRONIZE, so denying those standard rights
			// would block every read ("Access is denied"), not just writes.
			mask: syswindows.ACCESS_MASK(
				syswindows.FILE_WRITE_DATA |
					syswindows.FILE_APPEND_DATA |
					syswindows.FILE_WRITE_EA |
					syswindows.FILE_WRITE_ATTRIBUTES |
					syswindows.DELETE |
					fileDeleteChild |
					syswindows.WRITE_DAC |
					syswindows.WRITE_OWNER),
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
