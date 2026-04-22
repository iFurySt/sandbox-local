package backend

import (
	"context"
	"fmt"
	"runtime"

	"github.com/iFurySt/sandbox-local/internal/model"
)

type Backend interface {
	Name() string
	Platform() string
	Check(context.Context) model.CapabilityReport
	Prepare(context.Context, model.Request) (model.PreparedCommand, model.Cleanup, error)
}

type SetupBackend interface {
	Setup(context.Context) (model.SetupReport, error)
}

func Select(ctx context.Context, pref model.BackendPreference, enforcement model.EnforcementMode) (Backend, model.CapabilityReport, error) {
	if pref == "" {
		pref = model.BackendAuto
	}
	if enforcement == "" {
		enforcement = model.EnforcementRequire
	}

	if pref == model.BackendNoop {
		b := NewNoopBackend()
		return b, b.Check(ctx), nil
	}
	if pref != model.BackendAuto {
		return nil, model.CapabilityReport{}, fmt.Errorf("unsupported backend preference %q", pref)
	}

	b := platformBackend()
	report := b.Check(ctx)
	if report.Available {
		return b, report, nil
	}
	if enforcement == model.EnforcementBestEffort {
		fallback := NewNoopBackend()
		fallbackReport := fallback.Check(ctx)
		fallbackReport.Warnings = append(fallbackReport.Warnings, report.Warnings...)
		fallbackReport.Missing = append(fallbackReport.Missing, report.Missing...)
		return fallback, fallbackReport, nil
	}
	return nil, report, fmt.Errorf("platform sandbox backend %q is unavailable on %s", report.Backend, runtime.GOOS)
}
