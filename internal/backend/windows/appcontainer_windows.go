//go:build windows

package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iFurySt/sandbox-local/internal/appcontainer"
	"github.com/iFurySt/sandbox-local/internal/helper"
	"github.com/iFurySt/sandbox-local/internal/helperprotocol"
	"github.com/iFurySt/sandbox-local/internal/model"
	syswindows "golang.org/x/sys/windows"
)

const appContainerBackendName = "windows-appcontainer"

func hasAdministratorGroup() bool {
	groups, err := syswindows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		return false
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.String() == "S-1-5-32-544" && group.Attributes&syswindows.SE_GROUP_ENABLED != 0 &&
			group.Attributes&syswindows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return true
		}
	}
	return false
}

func appContainerCheck() model.CapabilityReport {
	report := model.CapabilityReport{
		Backend: appContainerBackendName, Platform: "windows", Available: true, Sandboxed: true,
		NetworkModes: []string{string(model.NetworkOffline), string(model.NetworkOpen)},
		Notes:        []string{"Per-invocation AppContainer profiles require no administrator privileges, local accounts, scheduled tasks, or firewall changes"},
		Warnings: []string{
			"AppContainer open networking retains Windows loopback isolation; domain allowlists require the elevated backend",
			"PowerShell and other USER32 workloads require an interactive user session; service and SSH sessions may fail DLL initialization",
		},
	}
	if err := appcontainer.Available(); err != nil {
		report.Available, report.Sandboxed = false, false
		report.Missing = append(report.Missing, "Windows AppContainer APIs: "+err.Error())
	}
	return report
}

func setupAppContainer() (model.SetupReport, error) {
	profile, err := appcontainer.NewProfile()
	report := model.SetupReport{Backend: appContainerBackendName, Platform: "windows", Ready: err == nil}
	if err != nil {
		return report, err
	}
	if err := profile.Close(); err != nil {
		report.Ready = false
		return report, err
	}
	report.Notes = []string{"AppContainer creation and removal succeeded; no administrator provisioning is needed"}
	return report, nil
}

type appContainerState struct {
	profile *appcontainer.Profile
	denySID *syswindows.SID
	paths   []string
}

func prepareAppContainer(ctx context.Context, req model.Request) (model.PreparedCommand, model.Cleanup, error) {
	if err := ctx.Err(); err != nil {
		return model.PreparedCommand{}, nil, err
	}
	if len(req.Command) == 0 {
		return model.PreparedCommand{}, nil, errors.New("command is required")
	}
	if mode := req.Policy.Network.Mode; mode != "" && mode != model.NetworkOffline && mode != model.NetworkOpen {
		return model.PreparedCommand{}, nil, fmt.Errorf("Windows AppContainer cannot enforce network mode %q; use offline/open or an administrator-managed backend", mode)
	}
	plans, warnings, err := filesystemPlans(req.Policy.Filesystem, req.Cwd)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	exe, err := helper.Resolve(req.HelperPath)
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	profile, err := appcontainer.NewProfile()
	if err != nil {
		return model.PreparedCommand{}, nil, err
	}
	denySID, err := newCapabilitySID()
	if err != nil {
		return model.PreparedCommand{}, nil, errors.Join(err, profile.Close())
	}
	state := &appContainerState{profile: profile, denySID: denySID}
	fail := func(err error) (model.PreparedCommand, model.Cleanup, error) {
		return model.PreparedCommand{}, nil, errors.Join(err, state.cleanup(context.WithoutCancel(ctx)))
	}
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		info, err := os.Stat(plan.path)
		if err != nil {
			if plan.required || !errors.Is(err, os.ErrNotExist) {
				return fail(fmt.Errorf("AppContainer %s path %q: %w", plan.label, plan.path, err))
			}
			continue
		}
		entry := aclEntries(plan, 0, profile.SID, profile.SID)[0]
		if plan.mode == syswindows.DENY_ACCESS {
			entry.Trustee.TrusteeValue = syswindows.TrusteeValueFromSID(denySID)
		}
		if info.IsDir() && plan.inherit {
			entry.Inheritance = syswindows.OBJECT_INHERIT_ACE | syswindows.CONTAINER_INHERIT_ACE
		}
		// DELETE_CHILD on a writable parent would override a child's DELETE
		// denial. Children instead inherit DELETE and explicit denials win.
		if plan.mode == syswindows.GRANT_ACCESS {
			entry.AccessPermissions &^= fileDeleteChild | syswindows.WRITE_DAC | syswindows.WRITE_OWNER
		}
		if err := updateAppContainerACL(ctx, plan.path, entry); err != nil {
			// Read-only system installations can already be exposed to ALL
			// APPLICATION PACKAGES. Never require their DACL to be writable;
			// the actual contained open still enforces their existing ACL.
			if plan.label == "read grant" && errors.Is(err, syswindows.ERROR_ACCESS_DENIED) {
				warnings = append(warnings, "AppContainer uses existing read ACL for "+plan.path)
				continue
			}
			return fail(fmt.Errorf("apply AppContainer %s to %q: %w", plan.label, plan.path, err))
		}
		state.paths = append(state.paths, plan.path)
		if plan.mode == syswindows.GRANT_ACCESS {
			deny := entry
			deny.AccessMode = syswindows.DENY_ACCESS
			deny.AccessPermissions = syswindows.WRITE_DAC | syswindows.WRITE_OWNER
			deny.Trustee.TrusteeValue = syswindows.TrusteeValueFromSID(denySID)
			if err := updateAppContainerACL(ctx, plan.path, deny); err != nil {
				return fail(fmt.Errorf("protect AppContainer resource ACL: %w", err))
			}
		}
	}
	config, err := json.Marshal(appcontainer.Config{SID: profile.SID.String(), DenySID: denySID.String(), NetworkOpen: req.Policy.Network.Mode == model.NetworkOpen})
	if err != nil {
		return fail(err)
	}
	command := append([]string{exe, helperprotocol.DispatchCommand, helperprotocol.AppContainerRunnerCommand, "--"}, req.Command...)
	env := make(map[string]string, len(req.Env)+1)
	for key, value := range req.Env {
		env[key] = value
	}
	env[appcontainer.Environment] = string(config)
	return model.PreparedCommand{
		Backend: appContainerBackendName, Platform: "windows", Command: command, Cwd: req.Cwd,
		Env: env, Warnings: warnings,
	}, state.cleanup, nil
}

func updateAppContainerACL(ctx context.Context, path string, entry syswindows.EXPLICIT_ACCESS) error {
	return editAppContainerACL(ctx, path, func(old *syswindows.ACL) (*syswindows.ACL, error) {
		return syswindows.ACLFromEntries([]syswindows.EXPLICIT_ACCESS{entry}, old)
	})
}

func editAppContainerACL(ctx context.Context, path string, edit func(*syswindows.ACL) (*syswindows.ACL, error)) (resultErr error) {
	unlock, err := lockAppContainerACL(ctx)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, unlock()) }()
	sd, err := syswindows.GetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := edit(old)
	if err != nil {
		return err
	}
	return syswindows.SetNamedSecurityInfo(path, syswindows.SE_FILE_OBJECT, syswindows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func (s *appContainerState) cleanup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var errs []error
	seen := make(map[string]bool)
	for i := len(s.paths) - 1; i >= 0; i-- {
		path := s.paths[i]
		key := strings.ToLower(path)
		if seen[key] {
			continue
		}
		seen[key] = true
		// Remove only this invocation's SID, preserving overlapping runs and
		// unrelated ACL changes made while the command was running.
		for _, sid := range []*syswindows.SID{s.profile.SID, s.denySID} {
			if err := editAppContainerACL(ctx, path, func(old *syswindows.ACL) (*syswindows.ACL, error) { return removeInvocationACE(old, sid) }); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove AppContainer ACL from %q: %w", path, err))
			}
		}
	}
	return errors.Join(append(errs, s.profile.Close())...)
}
