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

package ntp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// memFS is an in-memory FileSystem so unit tests never touch the host.
type memFS struct {
	files    map[string][]byte
	modes    map[string]os.FileMode
	dirs     map[string]struct{}
	writeErr error
}

// newMemFS builds an empty in-memory filesystem.
func newMemFS() *memFS {
	return &memFS{
		files: make(map[string][]byte),
		modes: make(map[string]os.FileMode),
		dirs:  make(map[string]struct{}),
	}
}

// ReadFile returns the stored contents of path.
func (m *memFS) ReadFile(path string) ([]byte, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return data, nil
}

// WriteFile stores data at path.
func (m *memFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.files[path] = append([]byte(nil), data...)
	m.modes[path] = perm
	return nil
}

// MkdirAll records the created directory.
func (m *memFS) MkdirAll(path string, _ os.FileMode) error {
	m.dirs[path] = struct{}{}
	return nil
}

// fakeController is a scripted Controller.
type fakeController struct {
	tracking     []*Tracking
	trackingErrs []error
	sources      []Source
	sourcesErr   error
	stepErr      error
	calls        atomic.Int64
	stepCalls    atomic.Int64
}

// Tracking returns the next scripted tracking report, repeating the last one
// once the script is exhausted.
func (f *fakeController) Tracking(context.Context) (*Tracking, error) {
	idx := int(f.calls.Add(1)) - 1
	if idx < len(f.trackingErrs) && f.trackingErrs[idx] != nil {
		return nil, f.trackingErrs[idx]
	}
	if len(f.tracking) == 0 {
		return nil, errors.New("no tracking scripted")
	}
	if idx >= len(f.tracking) {
		idx = len(f.tracking) - 1
	}
	return f.tracking[idx], nil
}

// Sources returns the scripted sources.
func (f *fakeController) Sources(context.Context) ([]Source, error) {
	if f.sourcesErr != nil {
		return nil, f.sourcesErr
	}
	return f.sources, nil
}

// MakeStep records the call and returns the scripted error.
func (f *fakeController) MakeStep(context.Context) error {
	f.stepCalls.Add(1)
	return f.stepErr
}

// quietLogger discards output so tests stay silent.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testPaths keeps every rendered artifact under a virtual prefix.
func testPaths() Paths {
	return Paths{
		ConfigFile:    "/etc/chrony/chrony.conf",
		DriftFile:     "/var/lib/chrony/chrony.drift",
		NTSCertFile:   "/etc/chrony/nts-server.crt",
		NTSKeyFile:    "/etc/chrony/nts-server.key",
		NTSDumpDir:    "/var/lib/chrony",
		CommandSocket: "/run/chrony/chronyd.sock",
	}
}

// syncedTracking is a converged tracking report.
func syncedTracking() *Tracking {
	return &Tracking{
		ReferenceID:      "CB00710F",
		ReferenceName:    "198.18.0.1",
		Stratum:          3,
		RefTime:          time.Unix(1755000000, 0).UTC(),
		SystemTimeOffset: -0.000012,
		LastOffset:       -0.000009,
		RootDelay:        0.023,
		RootDispersion:   0.045,
		LeapStatus:       "Normal",
	}
}

// unsyncedTracking is what chronyd reports before it has a reference.
func unsyncedTracking() *Tracking {
	return &Tracking{LeapStatus: LeapNotSynchronised}
}

// newTestService builds a Service wired entirely to fakes.
func newTestService(t *testing.T, cfg *Config, controller Controller, runner CommandRunner, fs FileSystem) *Service {
	t.Helper()
	opts := []Option{
		WithPaths(testPaths()),
		WithLogger(quietLogger()),
		WithPollInterval(time.Millisecond),
	}
	if controller != nil {
		opts = append(opts, WithController(controller))
	}
	if runner != nil {
		opts = append(opts, WithRunner(runner))
	}
	if fs != nil {
		opts = append(opts, WithFileSystem(fs))
	}
	svc, err := NewService(cfg, opts...)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return svc
}

func TestNewServiceRejectsNilAndInvalidConfig(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, ErrNilConfig{}) {
		t.Fatalf("NewService(nil) error = %v, want ErrNilConfig", err)
	}

	_, err := NewService(&Config{Enabled: true, Mode: "bogus"})
	var modeErr ErrInvalidMode
	if !errors.As(err, &modeErr) {
		t.Fatalf("NewService() error = %v, want ErrInvalidMode", err)
	}
}

func TestApplyRendersEnablesAndRestartsChrony(t *testing.T) {
	cfg := controlPlaneConfig()
	// Simulate the secrets engine having already substituted the kms://
	// URIs with real PEM material.
	cfg.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	cfg.Serve.NTS.KeyURI = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n"

	fs := newMemFS()
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""},
		"restart": {Output: ""},
		"status":  {Err: errors.New("stopped")},
	})
	svc := newTestService(t, cfg, &fakeController{}, runner, fs)

	if err := svc.Apply(context.Background()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	rendered, ok := fs.files[testPaths().ConfigFile]
	if !ok {
		t.Fatal("chrony.conf was not written")
	}
	if !strings.Contains(string(rendered), "allow 198.18.0.0/24") {
		t.Fatalf("rendered config missing the allow-list:\n%s", rendered)
	}
	if got := fs.modes[testPaths().NTSKeyFile]; got != keyFileMode {
		t.Fatalf("NTS key mode = %v, want %v", got, keyFileMode)
	}
	if string(fs.files[testPaths().NTSCertFile]) != cfg.Serve.NTS.CertURI {
		t.Fatal("NTS certificate material was not materialized")
	}
	if _, ok := runner.callFor("default"); !ok {
		t.Fatal("chronyd was not enabled in the default runlevel")
	}
	if _, ok := runner.callFor("restart"); !ok {
		t.Fatal("chronyd was not restarted after rendering")
	}
}

func TestApplyIsIdempotentWhenNothingChanged(t *testing.T) {
	cfg := consumerConfig()
	fs := newMemFS()
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""},
		"restart": {Output: ""},
		"status":  {Output: "started"},
	})
	svc := newTestService(t, cfg, &fakeController{}, runner, fs)
	ctx := context.Background()

	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}

	restarts := 0
	for _, call := range runner.calls {
		if len(call.Args) > 0 && call.Args[len(call.Args)-1] == "restart" {
			restarts++
		}
	}
	if restarts != 1 {
		t.Fatalf("restart count = %d, want 1 (unchanged config must not disturb a converged clock)", restarts)
	}
}

func TestApplyRejectsDisabledConfigAndHostFailures(t *testing.T) {
	t.Run("disabled section", func(t *testing.T) {
		svc := newTestService(t, &Config{Enabled: false}, &fakeController{}, newFakeRunner(nil), newMemFS())
		if err := svc.Apply(context.Background()); !errors.Is(err, ErrDisabled{}) {
			t.Fatalf("Apply() error = %v, want ErrDisabled", err)
		}
	})

	t.Run("unresolved NTS material", func(t *testing.T) {
		cfg := controlPlaneConfig()
		svc := newTestService(t, cfg, &fakeController{}, newFakeRunner(nil), newMemFS())
		var unresolved ErrUnresolvedNTSMaterial
		if err := svc.Apply(context.Background()); !errors.As(err, &unresolved) {
			t.Fatalf("Apply() error = %v, want ErrUnresolvedNTSMaterial", err)
		}
		if unresolved.Field != "serve.nts.cert-uri" {
			t.Fatalf("Field = %q, want serve.nts.cert-uri", unresolved.Field)
		}
	})

	t.Run("config write failure", func(t *testing.T) {
		fs := newMemFS()
		fs.writeErr = errors.New("read-only filesystem")
		svc := newTestService(t, consumerConfig(), &fakeController{}, newFakeRunner(nil), fs)
		var writeErr ErrWriteConfigFailed
		if err := svc.Apply(context.Background()); !errors.As(err, &writeErr) {
			t.Fatalf("Apply() error = %v, want ErrWriteConfigFailed", err)
		}
	})

	t.Run("rc-update failure", func(t *testing.T) {
		runner := newFakeRunner(map[string]fakeResponse{
			"default": {Output: "no such service", Err: errors.New("exit status 1")},
		})
		svc := newTestService(t, consumerConfig(), &fakeController{}, runner, newMemFS())
		var svcErr ErrServiceCommandFailed
		if err := svc.Apply(context.Background()); !errors.As(err, &svcErr) {
			t.Fatalf("Apply() error = %v, want ErrServiceCommandFailed", err)
		}
	})

	t.Run("restart failure", func(t *testing.T) {
		runner := newFakeRunner(map[string]fakeResponse{
			"default": {Output: ""},
			"restart": {Output: "failed", Err: errors.New("exit status 1")},
			"status":  {Err: errors.New("stopped")},
		})
		svc := newTestService(t, consumerConfig(), &fakeController{}, runner, newMemFS())
		var svcErr ErrServiceCommandFailed
		if err := svc.Apply(context.Background()); !errors.As(err, &svcErr) {
			t.Fatalf("Apply() error = %v, want ErrServiceCommandFailed", err)
		}
		if svcErr.Action != "restart" {
			t.Fatalf("Action = %q, want restart", svcErr.Action)
		}
	})
}

func TestStatusCombinesTrackingWithSourceReachability(t *testing.T) {
	controller := &fakeController{
		tracking: []*Tracking{syncedTracking()},
		sources: []Source{
			{Address: "198.18.0.1", Reach: 377, Reachable: true, State: SourceStateSelected},
			{Address: "203.0.113.9", Reach: 0, Reachable: false, State: SourceStateUnreachable},
		},
	}
	svc := newTestService(t, controlPlaneConfig(), controller, newFakeRunner(nil), newMemFS())

	status, err := svc.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if !status.Synced || !status.Healthy() {
		t.Fatalf("status = %+v, want synced and healthy", status)
	}
	if status.SourcesTotal != 2 || status.SourcesReachable != 1 {
		t.Fatalf("sources = %d/%d, want 1/2", status.SourcesReachable, status.SourcesTotal)
	}
	if status.Mode != string(ModeBoth) {
		t.Fatalf("Mode = %q, want both", status.Mode)
	}
	if svc.LastStatus() == nil {
		t.Fatal("LastStatus() = nil after a successful poll")
	}
}

func TestStatusPropagatesControlFailureAndDisabledConfig(t *testing.T) {
	t.Run("control socket down", func(t *testing.T) {
		controller := &fakeController{trackingErrs: []error{ErrControlUnavailable{Command: "tracking", Cause: errors.New("no socket")}}}
		svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())
		var unavailable ErrControlUnavailable
		if _, err := svc.Status(context.Background()); !errors.As(err, &unavailable) {
			t.Fatalf("Status() error = %v, want ErrControlUnavailable", err)
		}
	})

	t.Run("disabled section", func(t *testing.T) {
		svc := newTestService(t, &Config{Enabled: false}, &fakeController{}, newFakeRunner(nil), newMemFS())
		if _, err := svc.Status(context.Background()); !errors.Is(err, ErrDisabled{}) {
			t.Fatalf("Status() error = %v, want ErrDisabled", err)
		}
		if _, err := svc.Sources(context.Background()); !errors.Is(err, ErrDisabled{}) {
			t.Fatalf("Sources() error = %v, want ErrDisabled", err)
		}
		if _, err := svc.Step(context.Background()); !errors.Is(err, ErrDisabled{}) {
			t.Fatalf("Step() error = %v, want ErrDisabled", err)
		}
	})

	t.Run("source enumeration failure is not fatal", func(t *testing.T) {
		controller := &fakeController{
			tracking:   []*Tracking{syncedTracking()},
			sourcesErr: errors.New("sources unavailable"),
		}
		svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())
		status, err := svc.Status(context.Background())
		if err != nil {
			t.Fatalf("Status() error = %v, want nil", err)
		}
		if status.SourcesTotal != 0 {
			t.Fatalf("SourcesTotal = %d, want 0", status.SourcesTotal)
		}
	})
}

func TestStepRefusesWithoutAReachableSource(t *testing.T) {
	controller := &fakeController{
		tracking: []*Tracking{syncedTracking()},
		sources: []Source{
			{Address: "203.0.113.9", Reach: 0, Reachable: false},
		},
	}
	svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())

	var noSource ErrNoReachableSource
	if _, err := svc.Step(context.Background()); !errors.As(err, &noSource) {
		t.Fatalf("Step() error = %v, want ErrNoReachableSource", err)
	}
	if noSource.Total != 1 {
		t.Fatalf("Total = %d, want 1", noSource.Total)
	}
	if controller.stepCalls.Load() != 0 {
		t.Fatal("makestep was issued despite no reachable source")
	}
}

func TestStepCorrectsTheClockWhenASourceIsReachable(t *testing.T) {
	controller := &fakeController{
		tracking: []*Tracking{syncedTracking()},
		sources: []Source{
			{Address: "198.18.0.1", Reach: 377, Reachable: true},
		},
	}
	svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())

	status, err := svc.Step(context.Background())
	if err != nil {
		t.Fatalf("Step() error = %v", err)
	}
	if !status.Synced {
		t.Fatalf("status = %+v, want synced", status)
	}
	if controller.stepCalls.Load() != 1 {
		t.Fatalf("makestep calls = %d, want 1", controller.stepCalls.Load())
	}
}

func TestStepSurfacesControllerFailures(t *testing.T) {
	t.Run("source enumeration failure", func(t *testing.T) {
		controller := &fakeController{sourcesErr: errors.New("boom")}
		svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())
		if _, err := svc.Step(context.Background()); err == nil {
			t.Fatal("Step() = nil error, want the source enumeration failure")
		}
	})

	t.Run("makestep failure", func(t *testing.T) {
		controller := &fakeController{
			tracking: []*Tracking{syncedTracking()},
			sources:  []Source{{Reach: 377, Reachable: true}},
			stepErr:  errors.New("500 Failure"),
		}
		svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())
		if _, err := svc.Step(context.Background()); err == nil {
			t.Fatal("Step() = nil error, want the makestep failure")
		}
	})
}

func TestWaitForSyncReturnsOnceChronyConverges(t *testing.T) {
	controller := &fakeController{
		tracking: []*Tracking{unsyncedTracking(), unsyncedTracking(), syncedTracking()},
	}
	runner := newFakeRunner(map[string]fakeResponse{"--utc": {Output: ""}})
	cfg := consumerConfig()
	cfg.Consume.StartupGate.Timeout = 5 * time.Second
	svc := newTestService(t, cfg, controller, runner, newMemFS())

	if err := svc.WaitForSync(context.Background()); err != nil {
		t.Fatalf("WaitForSync() error = %v", err)
	}
	if _, ok := runner.callFor("--utc"); !ok {
		t.Fatal("hardware clock write-back was not performed after sync")
	}
}

func TestWaitForSyncTimesOutWhenTheClockNeverConverges(t *testing.T) {
	controller := &fakeController{tracking: []*Tracking{unsyncedTracking()}}
	cfg := consumerConfig()
	cfg.Consume.StartupGate.Timeout = 20 * time.Millisecond
	svc := newTestService(t, cfg, controller, newFakeRunner(nil), newMemFS())

	var timeout ErrSyncTimeout
	if err := svc.WaitForSync(context.Background()); !errors.As(err, &timeout) {
		t.Fatalf("WaitForSync() error = %v, want ErrSyncTimeout", err)
	}
	if timeout.Seconds != 0.02 {
		t.Fatalf("Seconds = %v, want 0.02", timeout.Seconds)
	}
}

func TestWaitForSyncIsANoOpWhenTheGateIsDisabled(t *testing.T) {
	cfg := consumerConfig()
	cfg.Consume.StartupGate.BlockUntilSynced = false
	controller := &fakeController{tracking: []*Tracking{unsyncedTracking()}}
	svc := newTestService(t, cfg, controller, newFakeRunner(nil), newMemFS())

	if err := svc.WaitForSync(context.Background()); err != nil {
		t.Fatalf("WaitForSync() error = %v, want nil", err)
	}
	if controller.calls.Load() != 0 {
		t.Fatal("a disabled gate must not poll chronyd")
	}
}

func TestWaitForSyncSkipsRTCWriteBackWhenDisabled(t *testing.T) {
	cfg := consumerConfig()
	cfg.RTC = &RTCConfig{WriteBack: false}
	controller := &fakeController{tracking: []*Tracking{syncedTracking()}}
	runner := newFakeRunner(nil)
	svc := newTestService(t, cfg, controller, runner, newMemFS())

	if err := svc.WaitForSync(context.Background()); err != nil {
		t.Fatalf("WaitForSync() error = %v", err)
	}
	if _, ok := runner.callFor("--utc"); ok {
		t.Fatal("hwclock was invoked despite rtc.write-back being false")
	}
}

func TestRTCWriteBackFailureIsNonFatal(t *testing.T) {
	controller := &fakeController{tracking: []*Tracking{syncedTracking()}}
	runner := newFakeRunner(map[string]fakeResponse{
		"--utc": {Output: "hwclock: ioctl(RTC_SET_TIME) failed", Err: errors.New("exit status 1")},
	})
	svc := newTestService(t, consumerConfig(), controller, runner, newMemFS())

	if err := svc.WaitForSync(context.Background()); err != nil {
		t.Fatalf("WaitForSync() error = %v, want nil (system clock is already correct)", err)
	}
}

func TestAnomalyDetectionIgnoresTheFirstBootCorrection(t *testing.T) {
	firstBoot := syncedTracking()
	firstBoot.LastOffset = -63072000 // two years, the lab-node-2 incident.

	later := syncedTracking()
	later.LastOffset = 42 // a 42s jump long after convergence.

	controller := &fakeController{tracking: []*Tracking{firstBoot, later}}
	svc := newTestService(t, consumerConfig(), controller, newFakeRunner(nil), newMemFS())
	ctx := context.Background()

	first, err := svc.Status(ctx)
	if err != nil {
		t.Fatalf("first Status() error = %v", err)
	}
	if first.Anomaly {
		t.Fatal("the first-boot correction must not be flagged as an anomaly")
	}

	second, err := svc.Status(ctx)
	if err != nil {
		t.Fatalf("second Status() error = %v", err)
	}
	if !second.Anomaly {
		t.Fatal("a large post-convergence step must be flagged as an anomaly")
	}
	if second.Healthy() {
		t.Fatal("Healthy() = true for an anomalous clock, want false")
	}
	if !strings.Contains(second.AnomalyReason, "after the first-boot correction") {
		t.Fatalf("AnomalyReason = %q, want an explanation", second.AnomalyReason)
	}
}

func TestStatusHealthyRejectsUnusableStrata(t *testing.T) {
	cases := map[string]*Status{
		"nil status":   nil,
		"unsynced":     {Synced: false, Stratum: 3},
		"stratum zero": {Synced: true, Stratum: 0},
		"stratum 16":   {Synced: true, Stratum: 16},
		"anomalous":    {Synced: true, Stratum: 3, Anomaly: true},
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			if status.Healthy() {
				t.Fatalf("Healthy() = true for %+v, want false", status)
			}
		})
	}
}

func TestServiceAccessorsExposeConfiguration(t *testing.T) {
	cfg := controlPlaneConfig()
	svc := newTestService(t, cfg, &fakeController{}, newFakeRunner(nil), newMemFS())

	if svc.Config() != cfg {
		t.Fatal("Config() did not return the configured section")
	}
	if svc.Mode() != ModeBoth {
		t.Fatalf("Mode() = %q, want both", svc.Mode())
	}
	if svc.LastStatus() != nil {
		t.Fatal("LastStatus() should be nil before the first poll")
	}
}
