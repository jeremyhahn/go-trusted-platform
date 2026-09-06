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
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
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

	// Rename atomically replaces newpath with oldpath.
	Rename(oldpath, newpath string) error

	// Symlink creates newname as a symbolic link to oldname.
	Symlink(oldname, newname string) error

	// Readlink returns the target of the symbolic link at path.
	Readlink(path string) (string, error)

	// Remove deletes the file or symlink at path.
	Remove(path string) error

	// RemoveAll deletes path and everything under it.
	RemoveAll(path string) error
}

// osFileSystem is the production FileSystem backed by the os package.
type osFileSystem struct{}

// ReadFile returns the contents of path.
func (osFileSystem) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile writes data to path with the given permissions, staging the
// content in the destination directory and renaming it into place.
//
// It does NOT open path directly, because os.WriteFile would do two unsafe
// things with an entry that already exists there: apply perm only when it
// creates the file (so the NTS private key could inherit a wider mode from
// a stale inode), and follow a symlink (so the key could land somewhere an
// attacker chose, where 0600 protects them rather than us). A freshly
// created O_EXCL temp file can be neither, the chmod precedes the write so
// the plaintext never occupies a world-readable inode, and the rename
// replaces the NAME — discarding any planted symlink instead of following
// it. The write is atomic as a side effect: no reader ever sees a partial
// file.
func (osFileSystem) WriteFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Cleans up every failure path below; a no-op once the rename lands.
	defer func() { _ = os.Remove(tmp) }()

	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MkdirAll creates path and any missing parents.
func (osFileSystem) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// Rename atomically replaces newpath with oldpath.
func (osFileSystem) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

// Symlink creates newname as a symbolic link to oldname.
func (osFileSystem) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

// Readlink returns the target of the symbolic link at path.
func (osFileSystem) Readlink(path string) (string, error) { return os.Readlink(path) }

// Remove deletes the file or symlink at path.
func (osFileSystem) Remove(path string) error { return os.Remove(path) }

// RemoveAll deletes path and everything under it.
func (osFileSystem) RemoveAll(path string) error { return os.RemoveAll(path) }

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

	// mu serializes Apply and NTS material rotation. Renewal-driven
	// rotation must not race the startup Apply or another rotation, and
	// the shared *Config is never mutated at runtime.
	mu sync.Mutex

	// pendingRotation, when non-nil, carries renewal material for the
	// duration of a single locked rotation. RotateNTSMaterial clears it
	// before returning, so the service never RETAINS a plaintext copy of
	// the renewed private key — the material is borrowed from the caller
	// for exactly one deployment (#57 review, protected-memory scope in
	// issue #60). Set and read only under mu.
	pendingRotation *ntsRotationMaterial

	// rotatedCertHash/rotatedKeyHash are SHA-256 digests of the material
	// the last successful rotation deployed. Digests are not secret: they
	// let later Applies verify the on-disk pair is still the rotated one
	// without holding key plaintext, and refuse to regress the store to
	// the startup-resolved (superseded) material. Set and read only
	// under mu.
	rotatedCertHash []byte
	rotatedKeyHash  []byte

	firstSyncDone atomic.Bool
	anomaly       atomic.Pointer[anomalyState]
	lastStatus    atomic.Pointer[Status]

	// serveNames latches the last CheckServeNames result: advertised
	// NTS-KE names this node's own allow list refuses. Behind an atomic
	// pointer like anomaly, so Status reads it without the service lock.
	serveNames atomic.Pointer[serveNameState]
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
// service, and restarts chronyd when either the rendered configuration or
// the NTS key material changed. It is idempotent: an unchanged configuration
// on a running daemon is a no-op, so a platformd restart never disturbs a
// converged clock. Rotated NTS material alone triggers a restart because
// chronyd reads the NTS-KE certificate and key only at startup — this is
// how certificate renewal deploys to the running server.
func (s *Service) Apply(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applyLocked(ctx)
}

// ntsRotationMaterial carries a renewed NTS pair through one locked
// deployment. The private key stays in the caller's protected-memory
// enclave — this service never holds the plaintext in an ordinary field,
// and borrows it only for the duration of the write. The certificate is
// public, so it travels as a plain slice. Discarded before
// RotateNTSMaterial returns; the enclave belongs to the caller.
type ntsRotationMaterial struct {
	key  *memguard.MemoryEnclave
	cert []byte
}

// RotateNTSMaterial deploys renewed NTS key material into the running
// service. The private key arrives in the caller's protected-memory
// enclave and is BORROWED for the duration of this locked call — the
// plaintext is materialized only inside the enclave's scoped Open, around
// the write itself, and the service keeps no copy: the shared *Config is
// NEVER mutated at runtime (so configuration readers cannot race the
// renewal), and afterwards the service holds only SHA-256 digests, enough
// for later Applies to verify the on-disk pair without regressing it. The
// chrony configuration is re-applied, which publishes the material through
// the versioned store and restarts chronyd (the NTS-material change
// detection in Apply). Certificate renewal is the only caller; a daemon
// restart converges to the same material through normal secret resolution,
// since renewal wrote the KMS first.
func (s *Service) RotateNTSMaterial(ctx context.Context, key *memguard.MemoryEnclave, certPEM []byte) error {
	if key == nil || !key.IsAlive() || key.Size() == 0 || len(certPEM) == 0 {
		return ErrMissingNTSMaterial{Field: "rotated key/certificate material"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.config.NTSServing() {
		return ErrDisabled{}
	}
	s.pendingRotation = &ntsRotationMaterial{key: key, cert: certPEM}
	defer func() { s.pendingRotation = nil }()
	return s.applyLocked(ctx)
}

// applyLocked is Apply's body; callers hold s.mu.
func (s *Service) applyLocked(ctx context.Context) error {
	if !s.config.Active() {
		return ErrDisabled{}
	}

	ntsChanged, err := s.writeNTSMaterial()
	if err != nil {
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

	if !changed && !ntsChanged && s.serviceRunning(ctx) {
		s.logger.Debug("ntp: chrony configuration unchanged and daemon running",
			slog.String("config", s.paths.ConfigFile))
		return nil
	}

	return s.restartService(ctx)
}

// writeNTSMaterial materializes the NTS certificate and key and reports
// whether the published material changed, so Apply can restart chronyd when
// the material rotates. Material comes from exactly one of three sources:
// an in-flight rotation (pendingRotation), the versioned store itself when
// a prior rotation superseded the startup material (verified by digest,
// never regressed), or the startup-resolved config values. The platform
// secrets engine replaces the kms:// URIs with PEM material before the
// service starts; a value that still looks like a URI means the engine did
// not run or could not resolve it, which is a hard error rather than a
// silent downgrade to unauthenticated time.
func (s *Service) writeNTSMaterial() (bool, error) {
	if !s.config.NTSServing() {
		return false, nil
	}

	switch {
	case s.pendingRotation != nil:
		return s.writeRotatedNTSMaterial()
	case s.rotatedKeyHash != nil:
		// A prior rotation deployed material the shared Config does not
		// hold (it is never mutated at runtime) and the service does not
		// retain. Verify the published pair is still the rotated one;
		// rewriting the startup material here would silently regress
		// chronyd to a superseded NTS identity.
		return false, s.verifyRotatedNTSMaterial()
	default:
		return s.writeConfiguredNTSMaterial()
	}
}

// writeConfiguredNTSMaterial publishes the pair the platform secrets
// engine resolved into the configuration before the service started.
//
// The key plaintext reaches this path as an ordinary config string: the
// engine substitutes `kms://` references in place, and a Go string cannot
// be wiped. The copy taken here IS wiped once the write completes, which
// narrows the window without closing it; the durable fix is a
// handle-preserving resolution below Layer 5 (go-quicbaas#136, tracked
// here as #60 — see docs/security/protected-memory.md).
func (s *Service) writeConfiguredNTSMaterial() (bool, error) {
	nts := s.config.Serve.NTS
	if err := assertResolved("serve.nts.cert-uri", nts.CertURI); err != nil {
		return false, err
	}
	if err := assertResolved("serve.nts.key-uri", nts.KeyURI); err != nil {
		return false, err
	}
	if err := s.fs.MkdirAll(s.paths.NTSDumpDir, dirMode); err != nil {
		return false, ErrWriteConfigFailed{Path: s.paths.NTSDumpDir, Cause: err}
	}

	keyData := []byte(nts.KeyURI)
	defer zeroBytes(keyData)
	return s.deployNTSMaterial([]byte(nts.CertURI), keyData)
}

// writeRotatedNTSMaterial publishes an in-flight rotation. The key
// plaintext exists only inside the enclave borrow: the store write and the
// digest that supersedes it both happen within the callback, so no
// plaintext copy outlives the deployment.
func (s *Service) writeRotatedNTSMaterial() (bool, error) {
	// Checked before the borrow so any error out of Open below is the
	// callback's own, and so a dead enclave fails closed with a typed
	// error rather than publishing an empty key file.
	if !s.pendingRotation.key.IsAlive() {
		return false, ErrNTSKeyEnclaveUnavailable{}
	}
	if err := s.fs.MkdirAll(s.paths.NTSDumpDir, dirMode); err != nil {
		return false, ErrWriteConfigFailed{Path: s.paths.NTSDumpDir, Cause: err}
	}

	certData := s.pendingRotation.cert
	var changed bool
	err := s.pendingRotation.key.Open(func(keyData []byte) error {
		deployed, err := s.deployNTSMaterial(certData, keyData)
		if err != nil {
			return err
		}
		changed = deployed

		// The rotated pair is on disk (or already was): record its
		// digests so later Applies verify instead of regress. Recorded
		// even when the deploy failed to restart chronyd upstream —
		// the digests describe the STORE, not the daemon.
		certSum := sha256.Sum256(certData)
		keySum := sha256.Sum256(keyData)
		s.rotatedCertHash = certSum[:]
		s.rotatedKeyHash = keySum[:]
		return nil
	})
	if err != nil {
		return false, err
	}
	return changed, nil
}

// deployNTSMaterial publishes a certificate/key pair through the versioned
// material store. The pair lands as ONE unit: both files are written into a
// fresh content-addressed version directory, and the `current` symlink is
// retargeted with a single atomic rename — the only commit point. A failure
// anywhere before that rename leaves the previously published pair
// untouched, and no observer of the store — chronyd restarts included — can
// ever see a certificate from one version beside a key from another.
func (s *Service) deployNTSMaterial(certData, keyData []byte) (bool, error) {
	if err := s.fs.MkdirAll(s.paths.NTSMaterialDir, dirMode); err != nil {
		return false, ErrWriteConfigFailed{Path: s.paths.NTSMaterialDir, Cause: err}
	}

	currentLink := filepath.Join(s.paths.NTSMaterialDir, ntsCurrentLink)
	oldTarget, _ := s.fs.Readlink(currentLink)

	curCert, curKey, readErr := s.readCurrentNTSMaterial()
	if readErr == nil && bytes.Equal(curCert, certData) && bytes.Equal(curKey, keyData) {
		zeroBytes(curKey)
		return false, nil
	}
	zeroBytes(curKey)

	// Content-addressed version name: identical material maps to the same
	// directory, so a retried deploy is idempotent.
	sum := sha256.New()
	sum.Write(certData)
	sum.Write(keyData)
	version := "v-" + hex.EncodeToString(sum.Sum(nil)[:16])
	versionDir := filepath.Join(s.paths.NTSMaterialDir, version)

	if err := s.fs.MkdirAll(versionDir, dirMode); err != nil {
		return false, ErrWriteConfigFailed{Path: versionDir, Cause: err}
	}
	if err := s.fs.WriteFile(filepath.Join(versionDir, ntsCertFileName), certData, certFileMode); err != nil {
		return false, ErrWriteConfigFailed{Path: filepath.Join(versionDir, ntsCertFileName), Cause: err}
	}
	if err := s.fs.WriteFile(filepath.Join(versionDir, ntsKeyFileName), keyData, keyFileMode); err != nil {
		return false, ErrWriteConfigFailed{Path: filepath.Join(versionDir, ntsKeyFileName), Cause: err}
	}

	// Publish: stage a link beside `current`, then atomically rename it
	// into place. A stale staging link from a crashed prior attempt is
	// removed first.
	stagingLink := currentLink + ".tmp"
	_ = s.fs.Remove(stagingLink)
	if err := s.fs.Symlink(version, stagingLink); err != nil {
		return false, ErrWriteConfigFailed{Path: stagingLink, Cause: err}
	}
	if err := s.fs.Rename(stagingLink, currentLink); err != nil {
		_ = s.fs.Remove(stagingLink)
		return false, ErrWriteConfigFailed{Path: currentLink, Cause: err}
	}

	// The old version is unpublished; remove it so superseded private
	// keys do not accumulate on disk. Best-effort: the swap has already
	// committed. Only a target matching the internally generated
	// version-name format is ever removed — a tampered `current` link
	// (`../../etc`, an absolute path, anything not ours) must not turn
	// rotation into recursive deletion outside the store (round-8
	// review); validNTSVersionName admits no separators, so the join
	// cannot escape NTSMaterialDir.
	if validNTSVersionName(oldTarget) && oldTarget != version {
		if err := s.fs.RemoveAll(filepath.Join(s.paths.NTSMaterialDir, oldTarget)); err != nil {
			s.logger.Warn("ntp: failed to remove superseded NTS material version",
				slog.String("version", oldTarget), slog.String("error", err.Error()))
		}
	}
	return true, nil
}

// validNTSVersionName reports whether name has exactly the shape
// deployNTSMaterial generates: "v-" followed by 32 lowercase hex digits.
// Nothing else — no separators, no traversal, no absolute paths — is ever
// treated as a version directory of the store.
func validNTSVersionName(name string) bool {
	const hexLen = 32
	if len(name) != len("v-")+hexLen || !strings.HasPrefix(name, "v-") {
		return false
	}
	for _, c := range name[len("v-"):] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// readCurrentNTSMaterial reads the published pair through explicit symlink
// resolution, so the service's own view of the store never depends on
// kernel symlink traversal (and the in-memory test filesystem stays
// trivial). A `current` link whose target is not an internally generated
// version name is rejected — the store is treated as unreadable, never
// followed outside NTSMaterialDir.
func (s *Service) readCurrentNTSMaterial() (cert, key []byte, err error) {
	target, err := s.fs.Readlink(filepath.Join(s.paths.NTSMaterialDir, ntsCurrentLink))
	if err != nil {
		return nil, nil, err
	}
	if !validNTSVersionName(target) {
		return nil, nil, ErrInvalidNTSVersionLink{Target: target}
	}
	versionDir := filepath.Join(s.paths.NTSMaterialDir, target)
	cert, err = s.fs.ReadFile(filepath.Join(versionDir, ntsCertFileName))
	if err != nil {
		return nil, nil, err
	}
	key, err = s.fs.ReadFile(filepath.Join(versionDir, ntsKeyFileName))
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// verifyRotatedNTSMaterial confirms the published store still holds the
// pair the last rotation deployed, comparing SHA-256 digests so the check
// needs no retained plaintext. A missing or diverged store is a hard typed
// error: the rotated private key exists nowhere else in the process, so the
// only safe recovery is a daemon restart that re-resolves the pair from the
// KMS (renewal wrote the KMS first).
func (s *Service) verifyRotatedNTSMaterial() error {
	cert, key, err := s.readCurrentNTSMaterial()
	if err != nil {
		return ErrRotatedNTSMaterialLost{Cause: err}
	}
	certSum := sha256.Sum256(cert)
	keySum := sha256.Sum256(key)
	zeroBytes(key)
	if !bytes.Equal(certSum[:], s.rotatedCertHash) || !bytes.Equal(keySum[:], s.rotatedKeyHash) {
		return ErrRotatedNTSMaterialLost{}
	}
	return nil
}

// zeroBytes overwrites b so transient plaintext read for a comparison does
// not linger in the buffer once it is no longer referenced.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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

	// Latched by CheckServeNames at provisioning and renewal, never
	// resolved here: a DNS lookup per status poll would put the resolver
	// in the health path for an answer that only changes when the
	// configuration or the zone does.
	status.ServeNameFindings = s.ServeNameFindings()

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
