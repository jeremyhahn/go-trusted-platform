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
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// CertKind classifies a managed certificate by what kind of endpoint
// it protects. The renewal handler uses this to emit structured log
// entries and to disambiguate identically-named targets during audit.
type CertKind string

const (
	// CertKindWebservice identifies a TLS cert served by a platformd
	// HTTP(S) webservice.
	CertKindWebservice CertKind = "webservice"

	// CertKindBMC identifies a TLS cert served by a baseboard
	// management controller's web UI / Redfish endpoint.
	CertKindBMC CertKind = "bmc"

	// CertKindNTS identifies the NTS-KE server certificate chrony serves
	// for RFC 8915 Network Time Security.
	CertKindNTS CertKind = "nts"

	// CertKindDaemon identifies platformd's own TLS identity, the
	// certificate its gRPC, QUIC, REST and MCP listeners present (#36).
	CertKindDaemon CertKind = "daemon"
)

// validCertKinds is a lookup table for valid CertKind values, used
// by IsValid.
var validCertKinds = map[CertKind]struct{}{
	CertKindWebservice: {},
	CertKindBMC:        {},
	CertKindNTS:        {},
	CertKindDaemon:     {},
}

// IsValid reports whether k is a recognized CertKind.
func (k CertKind) IsValid() bool {
	_, ok := validCertKinds[k]
	return ok
}

// ErrNilCurrentCertificate reports that a target's Current returned no
// certificate and no error. Named rather than inlined so the renewal sweep and
// the boot reconciliation describe the same condition identically.
type ErrNilCurrentCertificate struct{}

func (ErrNilCurrentCertificate) Error() string {
	return "app: endpoint returned a nil certificate"
}

// CertTarget describes an actively-managed certificate identity. A
// target carries two callbacks — Current reads the live certificate
// for expiry inspection; Reissue performs a fresh issuance end-to-end
// (CSR → ACME/CA → deploy).
//
// Targets are registered at platformd boot once initial issuance
// completes, and consumed by the cert-renewal scheduler handler
// during its periodic sweep.
type CertTarget struct {
	// Name uniquely identifies this target within a CertTargetRegistry.
	// Convention: "<kind>.<identifier>" (e.g., "bmc.device-17",
	// "webservice.admin"). Case-sensitive.
	Name string

	// Kind classifies the endpoint type.
	Kind CertKind

	// Current returns the certificate currently served by the
	// endpoint. The returned certificate is the leaf — chain elements
	// are not returned. Called by the renewal handler to read NotAfter
	// and decide whether reissuance is due.
	Current func(ctx context.Context) (*x509.Certificate, error)

	// Reissue runs a full issuance sequence for the target:
	// CSR build, ACME request (or local CA fallback), and deploy.
	// On success the endpoint presents the new certificate on its
	// next TLS handshake.
	Reissue func(ctx context.Context) error

	// DueOverride optionally makes a target due for reissuance for reasons
	// other than imminent expiry, returning the reason for the sweep log.
	// Optional: nil means expiry is the only trigger, which is correct for
	// targets whose served certificate is always one we issued.
	//
	// It is consulted on BOTH outcomes of Current: with (cert, nil) when a
	// certificate was read, and with (nil, err) when it could not be. The second
	// case matters -- an endpoint serving no certificate at all is exactly the
	// one that needs issuing, and treating an unreadable endpoint as merely
	// "failed" leaves it unable to converge for as long as the process lives.
	//
	// It exists because expiry is not a sufficient trigger everywhere. A BMC
	// that has never been provisioned presents a long-lived FACTORY
	// certificate: it is not close to expiry and never will be, so an
	// expiry-only sweep would skip it every day and the configured identity
	// would never be deployed. That is not hypothetical -- it is precisely the
	// state left behind when boot-time provisioning fails and the failure is
	// (correctly) non-fatal.
	DueOverride func(ctx context.Context, cert *x509.Certificate, readErr error) (due bool, reason string)
}

// Validate checks the CertTarget's required fields.
func (t *CertTarget) Validate() error {
	if t == nil {
		return ErrNilCertTarget
	}
	if t.Name == "" {
		return ErrInvalidCertTarget{Field: "name", Reason: "required"}
	}
	if !t.Kind.IsValid() {
		return ErrInvalidCertTarget{Field: "kind", Reason: fmt.Sprintf("unrecognized kind %q", t.Kind)}
	}
	if t.Current == nil {
		return ErrInvalidCertTarget{Field: "current", Reason: "required"}
	}
	if t.Reissue == nil {
		return ErrInvalidCertTarget{Field: "reissue", Reason: "required"}
	}
	return nil
}

// CertTargetRegistry is an in-process registry of CertTarget entries.
// Safe for concurrent use. The zero value is not usable; construct
// via NewCertTargetRegistry.
//
// One registry is typically attached to the running platformd App so
// the cert-renewal scheduler handler can iterate all managed targets
// per tick.
type CertTargetRegistry struct {
	mu      sync.RWMutex
	targets map[string]*CertTarget
}

// NewCertTargetRegistry returns an empty registry ready for use.
func NewCertTargetRegistry() *CertTargetRegistry {
	return &CertTargetRegistry{targets: make(map[string]*CertTarget)}
}

// Register adds target to the registry. Returns ErrDuplicateCertTarget
// if a target with the same Name is already registered. Use
// Replace to overwrite an existing entry intentionally.
func (r *CertTargetRegistry) Register(target *CertTarget) error {
	if err := target.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.targets[target.Name]; exists {
		return ErrDuplicateCertTarget{Name: target.Name}
	}
	r.targets[target.Name] = target
	return nil
}

// Replace adds or overwrites the entry for target.Name. Useful when
// re-registering after a config reload.
func (r *CertTargetRegistry) Replace(target *CertTarget) error {
	if err := target.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[target.Name] = target
	return nil
}

// Unregister removes the entry for name. Returns nil if the entry
// does not exist (idempotent).
func (r *CertTargetRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, name)
}

// Get returns the target with the given name. The second return
// value reports whether an entry exists.
func (r *CertTargetRegistry) Get(name string) (*CertTarget, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.targets[name]
	return t, ok
}

// Len returns the number of registered targets.
func (r *CertTargetRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.targets)
}

// Snapshot returns a slice of all registered targets in deterministic
// order (sorted by Name). The slice is safe for the caller to iterate
// concurrently with further Register/Unregister calls — pointers are
// to the live CertTarget values but are not mutated by the registry.
func (r *CertTargetRegistry) Snapshot() []*CertTarget {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*CertTarget, 0, len(r.targets))
	for _, t := range r.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByKind returns all registered targets matching the given kind, in
// deterministic (Name-sorted) order.
func (r *CertTargetRegistry) ByKind(kind CertKind) []*CertTarget {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*CertTarget, 0)
	for _, t := range r.targets {
		if t.Kind == kind {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// --- errors ---

// ErrNilCertTarget indicates a nil CertTarget was passed to a registry
// operation.
var ErrNilCertTarget = errors.New("app: nil cert target")

// ErrInvalidCertTarget indicates a CertTarget failed validation.
type ErrInvalidCertTarget struct {
	Field  string
	Reason string
}

func (e ErrInvalidCertTarget) Error() string {
	return fmt.Sprintf("app: invalid cert target %s: %s", e.Field, e.Reason)
}

// ErrDuplicateCertTarget indicates Register was called for a name
// that is already registered.
type ErrDuplicateCertTarget struct {
	Name string
}

func (e ErrDuplicateCertTarget) Error() string {
	return fmt.Sprintf("app: cert target already registered: %s", e.Name)
}

// ErrCertRenewalSweepIncomplete reports that a renewal sweep stopped before
// evaluating every target, so the results are partial.
//
// It exists because a truncated sweep is otherwise indistinguishable from a
// complete one: the handler derives success from the per-target results, and a
// short list of healthy results reads as a clean tick over certificates that
// were never checked.
type ErrCertRenewalSweepIncomplete struct {
	Evaluated int
	Total     int
	Cause     error
}

func (e ErrCertRenewalSweepIncomplete) Error() string {
	return fmt.Sprintf("app: certificate renewal sweep incomplete, evaluated %d of "+
		"%d targets: %v", e.Evaluated, e.Total, e.Cause)
}

func (e ErrCertRenewalSweepIncomplete) Unwrap() error { return e.Cause }
