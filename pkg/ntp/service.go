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
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// DefaultServiceName is the OpenRC service chrony installs.
const DefaultServiceName = "chronyd"

// DefaultPollInterval is how often the startup gate polls chronyd's control
// socket while waiting for the clock to converge.
const DefaultPollInterval = 2 * time.Second

// configFileMode is the permission of the rendered chrony.conf. It is
// world-readable: it carries no secrets, only source addresses and CIDRs.
const configFileMode os.FileMode = 0o644

// keyFileMode is the permission of the NTS private key.
const keyFileMode os.FileMode = 0o600

// certFileMode is the permission of the NTS server certificate.
const certFileMode os.FileMode = 0o644

// dirMode is the permission of directories the service creates.
const dirMode os.FileMode = 0o755

// openRCBinary manages OpenRC services on the running system.
const openRCBinary = "rc-service"

// openRCUpdateBinary enables OpenRC services in a runlevel.
const openRCUpdateBinary = "rc-update"

// hwclockBinary writes the system clock back to the RTC.
const hwclockBinary = "hwclock"

// defaultRunlevel is the OpenRC runlevel chronyd is enabled in.
const defaultRunlevel = "default"

// FileSystem is the subset of filesystem operations the service performs.
// Injecting it keeps unit tests entirely in memory.
type FileSystem interface {
	// ReadFile returns the contents of path.
	ReadFile(path string) ([]byte, error)

	// WriteFile writes data to path with the given permissions.
	WriteFile(path string, data []byte, perm os.FileMode) error

	// MkdirAll creates path and any missing parents.
	MkdirAll(path string, perm os.FileMode) error
}

// osFileSystem is the production FileSystem backed by the os package.
type osFileSystem struct{}

// ReadFile returns the contents of path.
func (osFileSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile writes data to path with the given permissions.
func (osFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// MkdirAll creates path and any missing parents.
func (osFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// anomalyState records a detected clock anomaly. It is swapped atomically so
// readers never take a lock on the status path.
type anomalyState struct {
	// Reason explains the anomaly in operator-readable form.
	Reason string
}

// Service renders chrony's configuration, manages its OpenRC lifecycle, and
// reports the resulting synchronization state. It owns no NTP protocol logic.
type Service struct {
	config      *Config
	paths       Paths
	controller  Controller
	runner      CommandRunner
	fs          FileSystem
	logger      *slog.Logger
	serviceName string
	poll        time.Duration

	firstSyncDone atomic.Bool
	anomaly       atomic.Pointer[anomalyState]
	lastStatus    atomic.Pointer[Status]
}

// Option customizes a Service. Options exist so tests can substitute the
// command runner, filesystem, and control client; production callers use the
// defaults.
type Option func(*Service)

// WithController overrides the chrony control client.
func WithController(controller Controller) Option {
	return func(s *Service) { s.controller = controller }
}

// WithRunner overrides the system command runner.
func WithRunner(runner CommandRunner) Option {
	return func(s *Service) { s.runner = runner }
}

// WithFileSystem overrides the filesystem.
func WithFileSystem(fs FileSystem) Option {
	return func(s *Service) { s.fs = fs }
}

// WithPaths overrides the chrony filesystem layout.
func WithPaths(paths Paths) Option {
	return func(s *Service) { s.paths = paths }
}

// WithServiceName overrides the OpenRC service name.
func WithServiceName(name string) Option {
	return func(s *Service) { s.serviceName = name }
}

// WithLogger sets the service logger.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Service) { s.logger = logger }
}

// WithPollInterval overrides the startup-gate poll cadence.
func WithPollInterval(interval time.Duration) Option {
	return func(s *Service) { s.poll = interval }
}

// NewService builds a time-synchronization service for config. It validates
// the configuration up front so a malformed `ntp:` section is rejected before
// anything touches the host.
func NewService(config *Config, opts ...Option) (*Service, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	s := &Service{
		config:      config,
		paths:       DefaultPaths(),
		fs:          osFileSystem{},
		runner:      execRunner{},
		logger:      slog.Default(),
		serviceName: DefaultServiceName,
		poll:        DefaultPollInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.controller == nil {
		s.controller = NewController(s.paths.CommandSocket, s.runner)
	}

	return s, nil
}

// Config returns the service's configuration.
func (s *Service) Config() *Config { return s.config }

// Mode returns the configured serve/consume/both role.
func (s *Service) Mode() Mode { return s.config.Mode }

// Apply renders chrony.conf (plus any NTS material), enables the OpenRC
// service, and restarts chronyd when the rendered configuration changed. It
// is idempotent: an unchanged configuration on a running daemon is a no-op,
// so a platformd restart never disturbs a converged clock.
func (s *Service) Apply(ctx context.Context) error {
	if !s.config.Active() {
		return ErrDisabled{}
	}

	if err := s.writeNTSMaterial(); err != nil {
		return err
	}

	rendered, err := Render(s.config, s.paths)
	if err != nil {
		return err
	}

	changed, err := s.writeConfigFile([]byte(rendered))
	if err != nil {
		return err
	}

	if err := s.enableService(ctx); err != nil {
		return err
	}

	if !changed && s.serviceRunning(ctx) {
		s.logger.Debug("ntp: chrony configuration unchanged and daemon running",
			slog.String("config", s.paths.ConfigFile))
		return nil
	}

	return s.restartService(ctx)
}

// writeNTSMaterial materializes the resolved NTS certificate and key. The
// platform secrets engine replaces the kms:// URIs with PEM material before
// the service starts; a value that still looks like a URI means the engine
// did not run or could not resolve it, which is a hard error rather than a
// silent downgrade to unauthenticated time.
func (s *Service) writeNTSMaterial() error {
	if !s.config.NTSServing() {
		return nil
	}

	nts := s.config.Serve.NTS
	if err := assertResolved("serve.nts.cert-uri", nts.CertURI); err != nil {
		return err
	}
	if err := assertResolved("serve.nts.key-uri", nts.KeyURI); err != nil {
		return err
	}

	if err := s.fs.MkdirAll(s.paths.NTSDumpDir, dirMode); err != nil {
		return ErrWriteConfigFailed{Path: s.paths.NTSDumpDir, Cause: err}
	}
	if err := s.fs.MkdirAll(filepath.Dir(s.paths.NTSCertFile), dirMode); err != nil {
		return ErrWriteConfigFailed{Path: filepath.Dir(s.paths.NTSCertFile), Cause: err}
	}
	if err := s.fs.WriteFile(s.paths.NTSCertFile, []byte(nts.CertURI), certFileMode); err != nil {
		return ErrWriteConfigFailed{Path: s.paths.NTSCertFile, Cause: err}
	}
	if err := s.fs.WriteFile(s.paths.NTSKeyFile, []byte(nts.KeyURI), keyFileMode); err != nil {
		return ErrWriteConfigFailed{Path: s.paths.NTSKeyFile, Cause: err}
	}

	return nil
}

// unresolvedSchemes are the secret-reference schemes that must have been
// substituted by the platform secrets engine before the service runs.
var unresolvedSchemes = []string{"kms://", "secret://", "file://"}

// assertResolved rejects a value that is still a secret reference.
func assertResolved(field, value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ErrMissingNTSMaterial{Field: field}
	}
	for _, scheme := range unresolvedSchemes {
		if strings.HasPrefix(trimmed, scheme) {
			return ErrUnresolvedNTSMaterial{Field: field, Value: trimmed}
		}
	}
	return nil
}

// writeConfigFile writes chrony.conf and reports whether the content changed.
func (s *Service) writeConfigFile(rendered []byte) (bool, error) {
	if err := s.fs.MkdirAll(filepath.Dir(s.paths.ConfigFile), dirMode); err != nil {
		return false, ErrWriteConfigFailed{Path: filepath.Dir(s.paths.ConfigFile), Cause: err}
	}

	existing, readErr := s.fs.ReadFile(s.paths.ConfigFile)
	if readErr == nil && bytes.Equal(existing, rendered) {
		return false, nil
	}

	if err := s.fs.WriteFile(s.paths.ConfigFile, rendered, configFileMode); err != nil {
		return false, ErrWriteConfigFailed{Path: s.paths.ConfigFile, Cause: err}
	}
	return true, nil
}

// enableService adds chronyd to the default runlevel. rc-update is
// idempotent, so this is safe on every boot.
func (s *Service) enableService(ctx context.Context) error {
	out, err := s.runner.Run(ctx, openRCUpdateBinary, "add", s.serviceName, defaultRunlevel)
	if err != nil {
		return ErrServiceCommandFailed{
			Service: s.serviceName,
			Action:  "rc-update add",
			Output:  string(out),
			Cause:   err,
		}
	}
	return nil
}

// restartService restarts chronyd so a freshly rendered configuration takes
// effect.
func (s *Service) restartService(ctx context.Context) error {
	out, err := s.runner.Run(ctx, openRCBinary, s.serviceName, "restart")
	if err != nil {
		return ErrServiceCommandFailed{
			Service: s.serviceName,
			Action:  "restart",
			Output:  string(out),
			Cause:   err,
		}
	}
	s.logger.Info("ntp: chrony restarted with platform-rendered configuration",
		slog.String("service", s.serviceName),
		slog.String("config", s.paths.ConfigFile),
		slog.String("mode", string(s.config.Mode)))
	return nil
}

// serviceRunning reports whether OpenRC considers chronyd started.
func (s *Service) serviceRunning(ctx context.Context) bool {
	_, err := s.runner.Run(ctx, openRCBinary, s.serviceName, "status")
	return err == nil
}

// Status returns the current synchronization state, combining chronyd's
// tracking report with source reachability counts.
func (s *Service) Status(ctx context.Context) (*Status, error) {
	if !s.config.Active() {
		return nil, ErrDisabled{}
	}

	tracking, err := s.controller.Tracking(ctx)
	if err != nil {
		return nil, err
	}

	status := &Status{
		Synced:         tracking.Synced(),
		Stratum:        tracking.Stratum,
		LeapStatus:     tracking.LeapStatus,
		OffsetSeconds:  tracking.SystemTimeOffset,
		RootDispersion: tracking.RootDispersion,
		RootDelay:      tracking.RootDelay,
		LastSync:       tracking.RefTime,
		Mode:           string(s.config.Mode),
		ReferenceID:    tracking.ReferenceID,
		ReferenceName:  tracking.ReferenceName,
	}

	// Source counts are informational: a control socket that answers
	// tracking but not sources still yields a usable status.
	if sources, srcErr := s.controller.Sources(ctx); srcErr == nil {
		status.SourcesTotal = uint32(len(sources))
		for i := range sources {
			if sources[i].Reachable {
				status.SourcesReachable++
			}
		}
	} else {
		s.logger.Debug("ntp: source enumeration failed", slog.String("error", srcErr.Error()))
	}

	s.detectAnomaly(tracking)
	if state := s.anomaly.Load(); state != nil {
		status.Anomaly = true
		status.AnomalyReason = state.Reason
	}

	s.lastStatus.Store(status)
	return status, nil
}

// detectAnomaly flags a large correction observed after the first-boot
// correction. Before the first sync, large steps are the expected repair of a
// stale RTC; afterwards they mean a failing oscillator or a hostile source.
func (s *Service) detectAnomaly(tracking *Tracking) {
	if !tracking.Synced() {
		return
	}
	if !s.firstSyncDone.Load() {
		s.firstSyncDone.Store(true)
		return
	}
	if s.anomaly.Load() != nil {
		return
	}

	offset := tracking.LastOffset
	if offset < 0 {
		offset = -offset
	}
	if time.Duration(offset*float64(time.Second)) <= LargeStepThreshold {
		return
	}

	reason := "clock corrected by " + formatSeconds(tracking.LastOffset) +
		"s after the first-boot correction"
	s.anomaly.Store(&anomalyState{Reason: reason})
	s.logger.Warn("ntp: large clock correction after initial sync",
		slog.Float64("offset_seconds", tracking.LastOffset),
		slog.String("reference", tracking.ReferenceName))
}

// Sources returns the configured time sources and their measurement state.
func (s *Service) Sources(ctx context.Context) ([]Source, error) {
	if !s.config.Active() {
		return nil, ErrDisabled{}
	}
	return s.controller.Sources(ctx)
}

// Step forces an immediate clock correction. It refuses when chronyd has no
// reachable source, because a step with nothing to step towards would move
// the clock on stale data.
func (s *Service) Step(ctx context.Context) (*Status, error) {
	if !s.config.Active() {
		return nil, ErrDisabled{}
	}

	sources, err := s.controller.Sources(ctx)
	if err != nil {
		return nil, err
	}

	reachable := 0
	for i := range sources {
		if sources[i].Reachable {
			reachable++
		}
	}
	if reachable == 0 {
		return nil, ErrNoReachableSource{Total: len(sources)}
	}

	if err := s.controller.MakeStep(ctx); err != nil {
		return nil, err
	}

	return s.Status(ctx)
}

// WaitForSync blocks until chronyd reports a synchronized clock or the
// startup gate expires. When the gate is disabled it returns immediately.
// On success it optionally writes the corrected time back to the RTC so the
// next cold boot starts sane even before the network is up.
func (s *Service) WaitForSync(ctx context.Context) error {
	if !s.config.GateEnabled() {
		return nil
	}

	timeout := s.config.GateTimeout()
	gateCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(s.poll)
	defer ticker.Stop()

	for {
		status, err := s.Status(gateCtx)
		switch {
		case err != nil:
			s.logger.Debug("ntp: waiting for chrony control socket",
				slog.String("error", err.Error()))
		case status.Synced:
			s.logger.Info("ntp: clock synchronized",
				slog.Uint64("stratum", uint64(status.Stratum)),
				slog.Float64("offset_seconds", status.OffsetSeconds),
				slog.String("reference", status.ReferenceName))
			s.writeRTC(ctx)
			return nil
		}

		select {
		case <-gateCtx.Done():
			return ErrSyncTimeout{Seconds: timeout.Seconds()}
		case <-ticker.C:
		}
	}
}

// writeRTC persists the synchronized system time to the hardware clock. A
// failure is logged, not fatal: the system clock is already correct and the
// health surface reports the degraded state.
func (s *Service) writeRTC(ctx context.Context) {
	if !s.config.RTCWriteBack() {
		return
	}
	out, err := s.runner.Run(ctx, hwclockBinary, "--systohc", "--utc")
	if err != nil {
		s.logger.Warn("ntp: hardware clock write-back failed",
			slog.String("error", ErrRTCWriteFailed{Output: string(out), Cause: err}.Error()))
		return
	}
	s.logger.Info("ntp: system time written back to the hardware clock")
}

// LastStatus returns the most recently observed status without contacting
// chronyd. It returns nil before the first successful poll.
func (s *Service) LastStatus() *Status { return s.lastStatus.Load() }

// formatSeconds renders a signed offset with millisecond resolution.
func formatSeconds(value float64) string {
	return strconv.FormatFloat(value, 'f', 3, 64)
}
