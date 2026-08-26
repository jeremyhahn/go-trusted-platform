// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package app

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
)

// fakeNTPService records what platform bring-up asked the time service to do.
type fakeNTPService struct {
	applyErr   error
	syncErr    error
	applyCalls int
	syncCalls  int
}

// Apply records the call and returns the scripted error.
func (f *fakeNTPService) Apply(context.Context) error {
	f.applyCalls++
	return f.applyErr
}

// WaitForSync records the call and returns the scripted error.
func (f *fakeNTPService) RotateNTSMaterial(context.Context, *memguard.MemoryEnclave, []byte) error {
	return nil
}

func (f *fakeNTPService) WaitForSync(context.Context) error {
	f.syncCalls++
	return f.syncErr
}

// withFakeNTPService swaps the construction seam for the duration of a test.
func withFakeNTPService(t *testing.T, fake *fakeNTPService) {
	t.Helper()
	original := newNTPService
	newNTPService = func(*ntp.Config, *slog.Logger) (ntpService, *ntp.Service, error) {
		return fake, nil, nil
	}
	t.Cleanup(func() { newNTPService = original })
}

// testApp builds a minimal App with the given time configuration.
func testApp(config *ntp.Config) *App {
	return &App{
		Logger:    logging.NewLogger(slog.LevelError, nil),
		NTPConfig: config,
	}
}

// gatedConfig returns a consume-mode config whose startup gate is enabled.
func gatedConfig(action ntp.TimeoutAction) *ntp.Config {
	return &ntp.Config{
		Enabled: true,
		Mode:    ntp.ModeConsume,
		Consume: &ntp.ConsumeConfig{
			Upstream: []ntp.UpstreamSource{{Address: "198.18.0.10", IBurst: true}},
			StartupGate: &ntp.StartupGate{
				BlockUntilSynced: true,
				Timeout:          120 * time.Second,
				OnTimeout:        action,
			},
		},
		RTC: &ntp.RTCConfig{WriteBack: true},
	}
}

func TestStartNTPIsANoOpWithoutAConfiguredSection(t *testing.T) {
	fake := &fakeNTPService{}
	withFakeNTPService(t, fake)

	cases := map[string]*ntp.Config{
		"absent section":   nil,
		"disabled section": {Enabled: false},
	}

	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			app := testApp(config)
			if err := app.StartNTP(context.Background()); err != nil {
				t.Fatalf("StartNTP() error = %v, want nil", err)
			}
			if fake.applyCalls != 0 {
				t.Fatal("an absent ntp: section must not touch chrony")
			}
			if app.NTPService != nil {
				t.Fatal("NTPService should stay nil when time sync is not configured")
			}
		})
	}
}

func TestStartNTPConfiguresChronyAndWaitsForSync(t *testing.T) {
	fake := &fakeNTPService{}
	withFakeNTPService(t, fake)

	app := testApp(gatedConfig(ntp.ActionWarnAndContinue))
	if err := app.StartNTP(context.Background()); err != nil {
		t.Fatalf("StartNTP() error = %v", err)
	}
	if fake.applyCalls != 1 || fake.syncCalls != 1 {
		t.Fatalf("apply/sync calls = %d/%d, want 1/1", fake.applyCalls, fake.syncCalls)
	}
}

func TestStartNTPRejectsAMalformedSection(t *testing.T) {
	// A configuration bug is fatal: it is an operator error, not a
	// transient runtime condition, and silently ignoring it would leave
	// the node running on an unmanaged clock.
	app := testApp(&ntp.Config{Enabled: true, Mode: "sometimes"})

	var modeErr ntp.ErrInvalidMode
	if err := app.StartNTP(context.Background()); !errors.As(err, &modeErr) {
		t.Fatalf("StartNTP() error = %v, want ErrInvalidMode", err)
	}
}

func TestStartNTPContinuesWhenChronyCannotBeConfigured(t *testing.T) {
	// Mirrors initSDN / StartDNS: a runtime failure is logged and the node
	// keeps booting with the ntp health component reporting the problem.
	fake := &fakeNTPService{applyErr: ntp.ErrServiceCommandFailed{
		Service: "chronyd",
		Action:  "restart",
		Cause:   errors.New("exit status 1"),
	}}
	withFakeNTPService(t, fake)

	app := testApp(gatedConfig(ntp.ActionWarnAndContinue))
	if err := app.StartNTP(context.Background()); err != nil {
		t.Fatalf("StartNTP() error = %v, want nil", err)
	}
	if fake.syncCalls != 0 {
		t.Fatal("the sync gate must not run when chrony could not be configured")
	}
}

func TestStartNTPAppliesTheGateTimeoutPolicy(t *testing.T) {
	timeout := ntp.ErrSyncTimeout{Seconds: 120}

	t.Run("warn-and-continue boots the node", func(t *testing.T) {
		withFakeNTPService(t, &fakeNTPService{syncErr: timeout})
		app := testApp(gatedConfig(ntp.ActionWarnAndContinue))
		if err := app.StartNTP(context.Background()); err != nil {
			t.Fatalf("StartNTP() error = %v, want nil under warn-and-continue", err)
		}
	})

	t.Run("fail-startup aborts bring-up", func(t *testing.T) {
		withFakeNTPService(t, &fakeNTPService{syncErr: timeout})
		app := testApp(gatedConfig(ntp.ActionFailStartup))

		var gateErr ErrNTPStartupGate
		err := app.StartNTP(context.Background())
		if !errors.As(err, &gateErr) {
			t.Fatalf("StartNTP() error = %v, want ErrNTPStartupGate", err)
		}
		var syncTimeout ntp.ErrSyncTimeout
		if !errors.As(err, &syncTimeout) {
			t.Fatalf("ErrNTPStartupGate must unwrap to the timeout, got %v", err)
		}
		if gateErr.Error() == "" {
			t.Fatal("ErrNTPStartupGate must carry a message")
		}
	})

	t.Run("non-timeout gate failures do not abort", func(t *testing.T) {
		withFakeNTPService(t, &fakeNTPService{syncErr: errors.New("control socket vanished")})
		app := testApp(gatedConfig(ntp.ActionFailStartup))
		if err := app.StartNTP(context.Background()); err != nil {
			t.Fatalf("StartNTP() error = %v, want nil for a non-timeout failure", err)
		}
	})
}
