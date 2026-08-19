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

package bmc

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	"github.com/jeremyhahn/go-trusted-platform/pkg/quirks"
)

// CertManagerFactory constructs a ManagedCertificateManager for the
// given configuration. Backend subpackages register themselves at
// init time; the Redfish backend registers from this package directly.
type CertManagerFactory func(cfg *Config, logger *slog.Logger) (ManagedCertificateManager, error)

var (
	certFactoriesMu sync.RWMutex
	certFactories   = map[CertBackend]CertManagerFactory{}
)

// RegisterCertFactory announces a CertificateManager implementation for
// the given backend. Calls from multiple goroutines are safe. A factory
// previously registered for the same backend is replaced.
//
// Subpackages implementing vendor-specific backends (e.g., pkg/bmc/smc
// for Supermicro ATEN CGI) call this in their init() function so that
// importing the subpackage is sufficient to make the backend usable by
// AutoCertManager.
func RegisterCertFactory(backend CertBackend, f CertManagerFactory) {
	if f == nil {
		return
	}
	certFactoriesMu.Lock()
	defer certFactoriesMu.Unlock()
	certFactories[backend] = f
}

// lookupCertFactory resolves a registered backend factory.
func lookupCertFactory(backend CertBackend) (CertManagerFactory, bool) {
	certFactoriesMu.RLock()
	defer certFactoriesMu.RUnlock()
	f, ok := certFactories[backend]
	return f, ok
}

// init registers the Redfish cert backend. The Supermicro CGI backend
// registers itself from pkg/bmc/smc so that importing that subpackage
// is opt-in.
func init() {
	RegisterCertFactory(CertBackendRedfish, NewRedfishCertManager)
}

// AutoCertManager orchestrates BMC web-server TLS certificate
// management by probing the BMC's vendor, selecting an appropriate
// backend (Redfish CertificateService or Supermicro ATEN CGI), and
// falling back on unsupported responses where vendor policy allows.
//
// The selected backend is logged once, after first probe. Operators
// may pin a backend explicitly via config to bypass probing.
//
// GetWebCertificate reads the BMC's live TLS handshake peer
// certificate directly, independent of the backend selection. This
// works on every BMC regardless of cert-management support.
type AutoCertManager struct {
	cfg     *Config
	backend CertBackend
	logger  *slog.Logger

	mu       sync.Mutex
	resolved CertBackend               // resolved backend (after probe)
	vendor   Vendor                    // resolved vendor (after probe)
	primary  ManagedCertificateManager // lazily constructed
	fallback ManagedCertificateManager // lazily constructed (vendor-defined)
	probed   bool
}

// Compile-time interface checks.
var _ CertificateManager = (*AutoCertManager)(nil)
var _ ManagedCertificateManager = (*AutoCertManager)(nil)

// NewAutoCertManager constructs an AutoCertManager for the given
// configuration. backend selects the strategy:
//   - CertBackendAuto: probe vendor, pick recommended backend, fall back on 501
//   - CertBackendRedfish: force Redfish CertificateService
//   - CertBackendSMCCGI: force Supermicro ATEN CGI (no fallback)
//
// Vendor probing is deferred to first use so construction never does
// network I/O.
func NewAutoCertManager(cfg *Config, backend CertBackend, logger *slog.Logger) (*AutoCertManager, error) {
	if cfg == nil {
		return nil, ErrNilConfig{}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if backend == "" {
		backend = CertBackendAuto
	}
	if !backend.IsValid() {
		return nil, ErrInvalidConfig{Field: "backend", Reason: "unrecognized backend: " + string(backend)}
	}
	return &AutoCertManager{
		cfg:     cfg,
		backend: backend,
		logger:  logger,
	}, nil
}

// Backend returns the resolved backend. If probing has not yet run,
// returns the requested backend (which may be CertBackendAuto).
func (m *AutoCertManager) Backend() CertBackend {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.probed {
		return m.resolved
	}
	return m.backend
}

// Close releases any instantiated backend managers.
func (m *AutoCertManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	if m.primary != nil {
		if err := m.primary.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.primary = nil
	}
	if m.fallback != nil {
		if err := m.fallback.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.fallback = nil
	}
	return firstErr
}

// GetWebCertificate returns the leaf certificate presented by the
// BMC's HTTPS interface. Implementation reads the live TLS handshake
// peer cert, independent of the configured backend.
func (m *AutoCertManager) GetWebCertificate(ctx context.Context) (*x509.Certificate, error) {
	tlsCfg, err := BuildTLSConfig(ctx, m.cfg)
	if err != nil {
		return nil, err
	}
	state, err := peerCertificate(ctx, m.cfg.Address, m.cfg.Port, tlsCfg)
	if err != nil {
		return nil, err
	}
	if len(state.PeerCertificates) == 0 {
		return nil, ErrConnectionFailed{
			Address: m.cfg.Address,
			Cause:   errors.New("BMC presented no peer certificates"),
		}
	}
	return state.PeerCertificates[0], nil
}

// ReplaceWebCertificate uploads certPEM+keyPEM to the BMC using the
// resolved backend. On a first-call, vendor probe runs; thereafter the
// backend is cached. If the primary backend returns an unsupported
// response (501 / "not implemented" / "not supported") and vendor
// policy allows, a secondary backend is attempted.
func (m *AutoCertManager) ReplaceWebCertificate(ctx context.Context, certPEM []byte, keyPEM *memguard.MemoryEnclave) error {
	primary, fallback, err := m.resolveBackends(ctx)
	if err != nil {
		return err
	}
	if err := primary.ReplaceWebCertificate(ctx, certPEM, keyPEM); err != nil {
		if fallback == nil || !isUnsupportedBackendError(err) {
			return err
		}
		m.log("autocert: primary backend unsupported, trying fallback",
			"primary", primary.Backend(),
			"fallback", fallback.Backend(),
			"error", err.Error())
		if fbErr := fallback.ReplaceWebCertificate(ctx, certPEM, keyPEM); fbErr != nil {
			return ErrAutoCertAllBackendsFailed{
				Primary:   primary.Backend(),
				Fallback:  fallback.Backend(),
				PrimaryE:  err,
				FallbackE: fbErr,
			}
		}
		m.log("autocert: fallback backend succeeded",
			"backend", fallback.Backend())
		return nil
	}
	return nil
}

// resolveBackends returns the primary (and optional fallback)
// ManagedCertificateManager instances, running vendor probing lazily.
// Results are cached for the lifetime of the AutoCertManager.
//
// Under CertBackendAuto, the resolved Quirk's CertBackendFallback chain
// is consulted to wire a fallback backend (e.g. Supermicro lists
// ["redfish", "smc-cgi"] so the Redfish primary falls through to the
// ATEN CGI endpoint when the standard CertificateService returns
// "unsupported"). The CertBackendSMCCGI fallback is gated by the
// AllowCGIFallback config flag.
func (m *AutoCertManager) resolveBackends(ctx context.Context) (ManagedCertificateManager, ManagedCertificateManager, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.primary != nil {
		return m.primary, m.fallback, nil
	}

	resolved := m.backend
	var vendor Vendor
	if resolved == CertBackendAuto {
		probe, err := NewVendorProbe(m.cfg, m.logger)
		if err != nil {
			return nil, nil, ErrAutoCertResolve{Cause: err}
		}
		vendor, err = probe.Detect(ctx, m.cfg)
		if err != nil {
			return nil, nil, ErrAutoCertResolve{Cause: err}
		}
		resolved = RecommendCertBackend(vendor)
		if resolved == CertBackendSMCCGI && !m.cfg.AllowCGIFallback {
			return nil, nil, ErrAutoCertCGIGated{Vendor: vendor}
		}
	}

	primaryFactory, ok := lookupCertFactory(resolved)
	if !ok {
		return nil, nil, ErrAutoCertBackendUnavailable{Backend: resolved}
	}
	primary, err := primaryFactory(m.cfg, m.logger)
	if err != nil {
		return nil, nil, err
	}

	// Wire a fallback backend if the resolved Quirk advertises a
	// fallback chain that names a registered backend other than the
	// resolved primary. This is the data-driven replacement for the
	// previous inline `vendor == VendorSupermicro` branch.
	var fallback ManagedCertificateManager
	if m.backend == CertBackendAuto {
		fallback = m.wireFallbackBackend(vendor, resolved)
	}

	m.resolved = resolved
	m.vendor = vendor
	m.primary = primary
	m.fallback = fallback
	m.probed = true

	m.log("autocert: resolved backend",
		"vendor", string(vendor),
		"requested", string(m.backend),
		"resolved", string(resolved),
		"has_fallback", fallback != nil)

	return primary, fallback, nil
}

// wireFallbackBackend selects and constructs the secondary cert backend per
// the resolved Quirk's CertBackendFallback chain. The first chain entry that
//
//   - is registered as a CertBackend factory,
//   - is NOT the resolved primary backend, and
//   - passes any vendor-policy gate (CGI is gated by AllowCGIFallback)
//
// is returned. Returns nil when no usable fallback exists. Construction
// errors on the candidate factory cause the candidate to be skipped (the
// next entry, if any, is tried) — the fallback is best-effort.
func (m *AutoCertManager) wireFallbackBackend(vendor Vendor, resolved CertBackend) ManagedCertificateManager {
	quirk := quirks.Resolve(vendor.ManufacturerString(), "")
	for _, name := range quirk.CertBackendFallback {
		candidate := CertBackend(name)
		if !candidate.IsValid() {
			continue
		}
		if candidate == resolved {
			// Same as the primary — not a fallback.
			continue
		}
		// Honour the CGI policy gate even when listed as a vendor
		// fallback. AllowCGIFallback is the only documented gate; new
		// gates can be added here as a map[CertBackend]func(*Config) bool.
		if candidate == CertBackendSMCCGI && !m.cfg.AllowCGIFallback {
			continue
		}
		factory, ok := lookupCertFactory(candidate)
		if !ok {
			continue
		}
		fb, err := factory(m.cfg, m.logger)
		if err != nil {
			continue
		}
		return fb
	}
	return nil
}

// isUnsupportedBackendError returns true if err represents an
// "unsupported / not implemented" response that should trigger
// fallback to a secondary backend. Matches HTTP 501 and common
// "not implemented" / "not supported" / "MethodNotAllowed" strings
// across Redfish vendor implementations.
func isUnsupportedBackendError(err error) bool {
	if err == nil {
		return false
	}
	// Typed Redfish request errors carry the status code.
	var rErr ErrRedfishRequest
	if errors.As(err, &rErr) {
		if rErr.StatusCode == 501 || rErr.StatusCode == 405 || rErr.StatusCode == 404 {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"not implemented",
		"unimplemented",
		"not supported",
		"methodnotallowed",
		"method not allowed",
		"501",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// log emits a structured log entry if a logger is configured.
func (m *AutoCertManager) log(msg string, args ...any) {
	if m.logger != nil {
		m.logger.Info("bmc: "+msg, args...)
	}
}
