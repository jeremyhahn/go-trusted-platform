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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
)

// ntsKeyEnclave wraps PEM bytes the way certificate renewal does. The
// enclave WIPES the slice it is handed, so the copy keeps the caller's
// literal intact for the assertions that follow the rotation.
func ntsKeyEnclave(t *testing.T, keyPEM []byte) *memguard.MemoryEnclave {
	t.Helper()
	enclave := memguard.NewMemoryEnclave(append([]byte(nil), keyPEM...))
	t.Cleanup(enclave.Destroy)
	return enclave
}

// memFS is an in-memory FileSystem so unit tests never touch the host.
type memFS struct {
	files    map[string][]byte
	modes    map[string]os.FileMode
	dirs     map[string]struct{}
	symlinks map[string]string
	writeErr error
	// writeErrsBase scripts failures by basename, so a write into a
	// content-addressed version directory can be failed without knowing
	// the directory name in advance.
	writeErrsBase map[string]error
	renameErrs    map[string]error
	symlinkErrs   map[string]error
}

// newMemFS builds an empty in-memory filesystem.
func newMemFS() *memFS {
	return &memFS{
		files:    make(map[string][]byte),
		modes:    make(map[string]os.FileMode),
		dirs:     make(map[string]struct{}),
		symlinks: make(map[string]string),
	}
}

// ReadFile returns a copy of the stored contents of path — a fresh buffer,
// exactly like os.ReadFile, so callers that zeroize what they read cannot
// corrupt the stored file.
func (m *memFS) ReadFile(path string) ([]byte, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

// WriteFile stores data at path, honoring scripted failures.
func (m *memFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	if err, ok := m.writeErrsBase[filepath.Base(path)]; ok {
		return err
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

// Rename moves stored content — a file or a symlink — honoring a scripted
// per-destination failure.
func (m *memFS) Rename(oldpath, newpath string) error {
	if m.renameErrs != nil {
		if err, ok := m.renameErrs[newpath]; ok {
			return err
		}
	}
	if target, ok := m.symlinks[oldpath]; ok {
		m.symlinks[newpath] = target
		delete(m.symlinks, oldpath)
		return nil
	}
	data, ok := m.files[oldpath]
	if !ok {
		return os.ErrNotExist
	}
	m.files[newpath] = data
	m.modes[newpath] = m.modes[oldpath]
	delete(m.files, oldpath)
	delete(m.modes, oldpath)
	return nil
}

// Symlink records newname pointing at oldname, honoring scripted failures.
func (m *memFS) Symlink(oldname, newname string) error {
	if err, ok := m.symlinkErrs[newname]; ok {
		return err
	}
	m.symlinks[newname] = oldname
	return nil
}

// Readlink returns the recorded target of newname.
func (m *memFS) Readlink(path string) (string, error) {
	target, ok := m.symlinks[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return target, nil
}

// Remove deletes a file or symlink entry.
func (m *memFS) Remove(path string) error {
	if _, ok := m.symlinks[path]; ok {
		delete(m.symlinks, path)
		return nil
	}
	if _, ok := m.files[path]; ok {
		delete(m.files, path)
		delete(m.modes, path)
		return nil
	}
	return os.ErrNotExist
}

// RemoveAll deletes every entry at or under path.
func (m *memFS) RemoveAll(path string) error {
	prefix := path + "/"
	for p := range m.files {
		if p == path || strings.HasPrefix(p, prefix) {
			delete(m.files, p)
			delete(m.modes, p)
		}
	}
	for p := range m.symlinks {
		if p == path || strings.HasPrefix(p, prefix) {
			delete(m.symlinks, p)
		}
	}
	delete(m.dirs, path)
	return nil
}

// currentNTSPair resolves the published NTS pair the way the service does:
// through the material store's current symlink.
func currentNTSPair(t *testing.T, fs *memFS, paths Paths) (cert, key string, mode os.FileMode) {
	t.Helper()
	target, ok := fs.symlinks[paths.NTSMaterialDir+"/"+ntsCurrentLink]
	if !ok {
		return "", "", 0
	}
	base := paths.NTSMaterialDir + "/" + target
	return string(fs.files[base+"/"+ntsCertFileName]),
		string(fs.files[base+"/"+ntsKeyFileName]),
		fs.modes[base+"/"+ntsKeyFileName]
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
		ConfigFile:     "/etc/chrony/chrony.conf",
		DriftFile:      "/var/lib/chrony/chrony.drift",
		NTSMaterialDir: "/etc/chrony/nts.d",
		NTSDumpDir:     "/var/lib/chrony",
		CommandSocket:  "/run/chrony/chronyd.sock",
	}
}

// syncedTracking is a converged tracking report.
func syncedTracking() *Tracking {
	return &Tracking{
		ReferenceID:      "CB00710F",
		ReferenceName:    "10.4.200.1",
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
	cfg.Serve.NTS.KeyURI = genTestKeyPEM()

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
	if !strings.Contains(string(rendered), "allow 10.4.200.0/24") {
		t.Fatalf("rendered config missing the allow-list:\n%s", rendered)
	}
	cert, _, keyMode := currentNTSPair(t, fs, testPaths())
	if keyMode != keyFileMode {
		t.Fatalf("NTS key mode = %v, want %v", keyMode, keyFileMode)
	}
	if cert != cfg.Serve.NTS.CertURI {
		t.Fatal("NTS certificate material was not materialized")
	}
	if _, ok := runner.callFor("default"); !ok {
		t.Fatal("chronyd was not enabled in the default runlevel")
	}
	if _, ok := runner.callFor("restart"); !ok {
		t.Fatal("chronyd was not restarted after rendering")
	}
}

// A reference the secrets engine left in place is refused whatever its
// scheme, including one no resolver serves (the removed gateway alias is
// built from parts so the repository carries no spelling of it).
func TestAssertResolvedRefusesAnyLeftoverReference(t *testing.T) {
	for _, value := range []string{
		"kms://platform/ntp/nts-key",
		"file:///etc/ntp/nts.key",
		"secret" + "://platform/ntp/nts-key",
		"  vault+v2.x://a/b  ",
	} {
		err := assertResolved("serve.nts.key-uri", value)
		var unresolved ErrUnresolvedNTSMaterial
		if !errors.As(err, &unresolved) {
			t.Fatalf("assertResolved(%q) = %v, want ErrUnresolvedNTSMaterial", value, err)
		}
		if unresolved.Value != strings.TrimSpace(value) {
			t.Fatalf("Value = %q, want the trimmed reference %q", unresolved.Value, strings.TrimSpace(value))
		}
	}
}

// Resolved material passes, and a value that only looks like a scheme (an
// invalid scheme character, or no scheme before "://") is material, not a
// reference; an empty value is missing material.
func TestAssertResolvedAcceptsMaterialAndRefusesEmpty(t *testing.T) {
	for _, value := range []string{
		genTestKeyPEM(),
		"://no-scheme",
		"1kms://digit-first",
		"km s://space-in-scheme",
	} {
		if err := assertResolved("serve.nts.key-uri", value); err != nil {
			t.Fatalf("assertResolved(%q) = %v, want nil", value, err)
		}
	}
	err := assertResolved("serve.nts.cert-uri", "   ")
	if !errors.Is(err, ErrMissingNTSMaterial{Field: "serve.nts.cert-uri"}) {
		t.Fatalf("assertResolved(blank) = %v, want ErrMissingNTSMaterial", err)
	}
}

// TestApplyRestartsWhenNTSMaterialRotates asserts certificate renewal can
// deploy through Apply: rotated NTS material restarts chronyd even though
// the rendered chrony.conf is unchanged (chronyd only reads the NTS-KE
// certificate and key at startup), and identical material stays idempotent.
func TestApplyRestartsWhenNTSMaterialRotates(t *testing.T) {
	cfg := controlPlaneConfig()
	cfg.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	cfg.Serve.NTS.KeyURI = genTestKeyPEM()

	fs := newMemFS()
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""},
		"restart": {Output: ""},
		"status":  {Output: "started"},
	})
	svc := newTestService(t, cfg, &fakeController{}, runner, fs)
	ctx := context.Background()

	restarts := func() int {
		count := 0
		for _, call := range runner.calls {
			if len(call.Args) > 0 && call.Args[len(call.Args)-1] == "restart" {
				count++
			}
		}
		return count
	}

	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	if got := restarts(); got != 1 {
		t.Fatalf("restart count after first Apply = %d, want 1", got)
	}

	// Unchanged material: converged clock must not be disturbed.
	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if got := restarts(); got != 1 {
		t.Fatalf("restart count after unchanged Apply = %d, want 1", got)
	}

	// Renewal rotates the resolved material in place.
	cfg.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n"
	cfg.Serve.NTS.KeyURI = genTestKeyPEM()
	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("post-rotation Apply() error = %v", err)
	}
	if got := restarts(); got != 2 {
		t.Fatalf("restart count after rotation = %d, want 2 (chronyd must pick up the new NTS identity)", got)
	}
	if cert, _, _ := currentNTSPair(t, fs, testPaths()); cert != cfg.Serve.NTS.CertURI {
		t.Fatal("rotated NTS certificate was not materialized")
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
			{Address: "10.4.200.1", Reach: 377, Reachable: true, State: SourceStateSelected},
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
			{Address: "10.4.200.1", Reach: 377, Reachable: true},
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
	firstBoot.LastOffset = -63072000 // two years, the node-02 incident.

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

// TestRotateNTSMaterialDeploysWithoutConfigMutation asserts renewal-driven
// rotation restarts chronyd with the new material while leaving the shared
// Config untouched — configuration readers must never observe renewal
// writes (#57 review).
func TestRotateNTSMaterialDeploysWithoutConfigMutation(t *testing.T) {
	cfg := controlPlaneConfig()
	cfg.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	cfg.Serve.NTS.KeyURI = genTestKeyPEM()

	fs := newMemFS()
	runner := newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""},
		"restart": {Output: ""},
		"status":  {Output: "started"},
	})
	svc := newTestService(t, cfg, &fakeController{}, runner, fs)
	ctx := context.Background()

	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	newKey := []byte(genTestKeyPEM())
	newCert := []byte("-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n")
	if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); err != nil {
		t.Fatalf("RotateNTSMaterial() error = %v", err)
	}

	cert, key, _ := currentNTSPair(t, fs, testPaths())
	if cert != string(newCert) {
		t.Fatal("rotated certificate was not materialized")
	}
	if key != string(newKey) {
		t.Fatal("rotated key was not materialized")
	}
	if cfg.Serve.NTS.CertURI != "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" {
		t.Fatal("shared Config must not be mutated by rotation")
	}
	if svc.pendingRotation != nil {
		t.Fatal("rotation material must not be retained after deployment (#57 protected-memory review)")
	}

	// A later Apply must neither regress the store to the startup
	// material nor hold key plaintext to do so: the deployed pair is
	// verified by digest.
	if err := svc.Apply(ctx); err != nil {
		t.Fatalf("post-rotation Apply() error = %v", err)
	}
	if cert, _, _ := currentNTSPair(t, fs, testPaths()); cert != string(newCert) {
		t.Fatal("Apply after rotation must not regress the published material")
	}

	restarts := 0
	for _, call := range runner.calls {
		if len(call.Args) > 0 && call.Args[len(call.Args)-1] == "restart" {
			restarts++
		}
	}
	if restarts != 2 {
		t.Fatalf("restart count = %d, want 2 (startup + rotation)", restarts)
	}

	t.Run("empty material is rejected", func(t *testing.T) {
		if err := svc.RotateNTSMaterial(ctx, nil, newCert); err == nil {
			t.Fatal("empty key material must be rejected")
		}
		if err := svc.RotateNTSMaterial(ctx, memguard.NewMemoryEnclave(nil), newCert); err == nil {
			t.Fatal("a zero-length key enclave must be rejected")
		}
		if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), nil); err == nil {
			t.Fatal("empty certificate material must be rejected")
		}
	})

	// A destroyed enclave must fail closed rather than publish an empty
	// key file: the rotation carries no unprotected copy to fall back to.
	t.Run("a destroyed key enclave fails closed", func(t *testing.T) {
		dead := memguard.NewMemoryEnclave(append([]byte(nil), newKey...))
		dead.Destroy()
		if err := svc.RotateNTSMaterial(ctx, dead, newCert); err == nil {
			t.Fatal("a destroyed key enclave must be rejected")
		}
		cert, key, _ := currentNTSPair(t, fs, testPaths())
		if cert != string(newCert) || key != string(newKey) {
			t.Fatal("a rejected rotation must leave the published pair intact")
		}
	})

	t.Run("rotation on a non-NTS service is ErrDisabled", func(t *testing.T) {
		consumer := newTestService(t, consumerConfig(), &fakeController{}, newFakeRunner(map[string]fakeResponse{
			"default": {Output: ""}, "restart": {Output: ""}, "status": {Output: "started"},
		}), newMemFS())
		if err := consumer.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); !errors.Is(err, ErrDisabled{}) {
			t.Fatalf("error = %v, want ErrDisabled", err)
		}
	})
}

// TestRotateNTSMaterialConcurrency drives rotation, Apply, and config reads
// concurrently; run under -race this proves renewal deployment cannot race
// the service's other entry points.
func TestRotateNTSMaterialConcurrency(t *testing.T) {
	cfg := controlPlaneConfig()
	cfg.Serve.NTS.CertURI = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	cfg.Serve.NTS.KeyURI = genTestKeyPEM()
	svc := newTestService(t, cfg, &fakeController{}, newFakeRunner(map[string]fakeResponse{
		"default": {Output: ""}, "restart": {Output: ""}, "status": {Output: "started"},
	}), newMemFS())
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			key := memguard.NewMemoryEnclave(
				[]byte(genTestKeyPEM()))
			defer key.Destroy()
			cert := []byte(fmt.Sprintf("-----BEGIN CERTIFICATE-----\nC%d\n-----END CERTIFICATE-----\n", n))
			_ = svc.RotateNTSMaterial(ctx, key, cert)
		}(i)
		go func() {
			defer wg.Done()
			_ = svc.Apply(ctx)
		}()
		go func() {
			defer wg.Done()
			_ = svc.Config().Active()
			_ = svc.Mode()
		}()
	}
	wg.Wait()
}

// TestNTSMaterialDeployIsAtomic asserts the versioned-store publication has
// a single commit point: any failure — a key write during first install, or
// the symlink swap during rotation — leaves the previously published pair
// exactly as it was, so a chronyd restart outside Apply can never see a
// mismatched certificate/key pair (#57 review, rounds 6 and 7).
func TestNTSMaterialDeployIsAtomic(t *testing.T) {
	oldCert := "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
	oldKey := genTestKeyPEM()
	newKey := []byte(genTestKeyPEM())
	newCert := []byte("-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n")
	currentLink := testPaths().NTSMaterialDir + "/" + ntsCurrentLink
	fakeRunnerResponses := map[string]fakeResponse{
		"default": {Output: ""}, "restart": {Output: ""}, "status": {Output: "started"},
	}
	ctx := context.Background()

	newSvc := func(t *testing.T) (*Service, *memFS) {
		cfg := controlPlaneConfig()
		cfg.Serve.NTS.CertURI = oldCert
		cfg.Serve.NTS.KeyURI = oldKey
		fs := newMemFS()
		return newTestService(t, cfg, &fakeController{}, newFakeRunner(fakeRunnerResponses), fs), fs
	}

	t.Run("first install with failing key write publishes nothing", func(t *testing.T) {
		svc, fs := newSvc(t)
		// Fail every key write regardless of the version directory name.
		fs.writeErrsBase = map[string]error{ntsKeyFileName: errors.New("injected key write failure")}

		if err := svc.Apply(ctx); err == nil {
			t.Fatal("Apply must fail when the key cannot be written")
		}
		if _, ok := fs.symlinks[currentLink]; ok {
			t.Fatal("no version may be published when the pair is incomplete")
		}
	})

	t.Run("rotation with failing swap keeps the old pair published", func(t *testing.T) {
		svc, fs := newSvc(t)
		if err := svc.Apply(ctx); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}

		fs.renameErrs = map[string]error{currentLink: errors.New("injected swap failure")}
		if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); err == nil {
			t.Fatal("rotation must fail when the publication swap fails")
		}
		cert, key, _ := currentNTSPair(t, fs, testPaths())
		if cert != oldCert || key != oldKey {
			t.Fatalf("published pair = (%q, %q) — the old coherent pair must remain published", cert, key)
		}

		// After the failure clears, the same rotation succeeds and
		// publishes the complete new pair.
		fs.renameErrs = nil
		if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); err != nil {
			t.Fatalf("retry rotation error = %v", err)
		}
		cert, key, _ = currentNTSPair(t, fs, testPaths())
		if cert != string(newCert) || key != string(newKey) {
			t.Fatal("retry must publish the complete new pair")
		}
	})

	t.Run("rotation removes the superseded version from disk", func(t *testing.T) {
		svc, fs := newSvc(t)
		if err := svc.Apply(ctx); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		oldTarget := fs.symlinks[currentLink]
		if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); err != nil {
			t.Fatalf("RotateNTSMaterial() error = %v", err)
		}
		oldKeyPath := testPaths().NTSMaterialDir + "/" + oldTarget + "/" + ntsKeyFileName
		if _, ok := fs.files[oldKeyPath]; ok {
			t.Fatal("the superseded private key must not accumulate on disk")
		}
	})

	t.Run("tampered current link never leads cleanup outside the store", func(t *testing.T) {
		for name, target := range map[string]string{
			"parent traversal": "../../victim",
			"nested path":      "v-aabbccdd/../../../victim",
			"absolute path":    "/victim",
			"unexpected name":  "victim",
		} {
			t.Run(name, func(t *testing.T) {
				svc, fs := newSvc(t)
				// A pre-tampered current link pointing outside the store,
				// with a victim in its blast radius.
				fs.symlinks[currentLink] = target
				fs.files["/victim/data"] = []byte("do not delete")
				fs.files[filepath.Clean(testPaths().NTSMaterialDir+"/"+target)+"/data"] = []byte("do not delete either")

				// Deploying heals the store: the tampered target must be
				// treated as unreadable, never resolved or removed.
				if err := svc.Apply(ctx); err != nil {
					t.Fatalf("Apply() error = %v", err)
				}
				if string(fs.files["/victim/data"]) != "do not delete" {
					t.Fatal("cleanup escaped the material store through a tampered link")
				}
				cert, key, _ := currentNTSPair(t, fs, testPaths())
				if cert != oldCert || key != oldKey {
					t.Fatal("deploy must republish a valid version over the tampered link")
				}
			})
		}
	})

	t.Run("valid version names are recognized, everything else is not", func(t *testing.T) {
		if !validNTSVersionName("v-" + strings.Repeat("ab", 16)) {
			t.Fatal("a generated version name must validate")
		}
		for _, bad := range []string{
			"", "v-", "victim", "/abs", "../../victim",
			"v-" + strings.Repeat("ab", 16) + "/nested",
			"v-" + strings.Repeat("AB", 16), // uppercase hex is not ours
			"v-" + strings.Repeat("zz", 16),
			"v-" + strings.Repeat("ab", 15),
		} {
			if validNTSVersionName(bad) {
				t.Fatalf("%q must not validate as a version name", bad)
			}
		}
	})

	t.Run("tampered store after rotation is a typed error, not a regression", func(t *testing.T) {
		svc, fs := newSvc(t)
		if err := svc.Apply(ctx); err != nil {
			t.Fatalf("Apply() error = %v", err)
		}
		if err := svc.RotateNTSMaterial(ctx, ntsKeyEnclave(t, newKey), newCert); err != nil {
			t.Fatalf("RotateNTSMaterial() error = %v", err)
		}
		// Sever the published pair: the rotated key exists nowhere in
		// process memory, so Apply must fail typed instead of silently
		// regressing to the startup material.
		target := fs.symlinks[currentLink]
		delete(fs.files, testPaths().NTSMaterialDir+"/"+target+"/"+ntsKeyFileName)
		var lost ErrRotatedNTSMaterialLost
		if err := svc.Apply(ctx); !errors.As(err, &lost) {
			t.Fatalf("Apply() error = %v, want ErrRotatedNTSMaterialLost", err)
		}
	})
}
