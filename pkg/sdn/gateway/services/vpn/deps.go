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

package vpn

import (
	"context"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// IdentityPolicy decides whether an mTLS peer is a platform device. The
// caller-admission Policy satisfies it.
type IdentityPolicy interface {
	Evaluate(ctx context.Context, peer *calleradmission.Peer) calleradmission.Decision
}

// Verifier produces the attestation verdict for a device's quote. The daemon
// adapts the attestation service to it; the verdict must be for DeviceID.
type Verifier interface {
	Verify(ctx context.Context, deviceID string, nonce []byte, attestation *manifest.HostAttestation) (*verdict.DeviceVerdict, error)
}

// PostureEvaluator evaluates a posture report against a named policy. The
// OPA engine satisfies it.
type PostureEvaluator interface {
	Evaluate(ctx context.Context, policyName string, input map[string]interface{}) (*opa.EvaluationResult, error)
}

// FactorVerifier verifies a person factor bound to the session nonce for the
// operator behind the device. The daemon implements it over the SDK's FIDO2
// and PIV clients.
type FactorVerifier interface {
	Verify(ctx context.Context, tenantID, deviceID string, nonce []byte, factor *PersonFactor) error
}

// DataPlane programs the peer for a lease in the datapath. Implementations
// are the WireGuard plane (`!fips`) and the MASQUE plane; the unit-test
// double records calls.
type DataPlane interface {
	Kind() DataPlaneKind
	InstallPeer(ctx context.Context, lease *Lease) error
	RemovePeer(ctx context.Context, leaseID LeaseID) error
}

// ManagedDataPlane is a DataPlane that owns a device and a listener: the
// gateway starts it before the admission service accepts leases and stops
// it after. Both shipped planes are managed; the unit-test double is not.
type ManagedDataPlane interface {
	DataPlane
	// Start brings the plane's device and listener up. It is idempotent.
	Start(ctx context.Context) error
	// Stop tears every session down and removes the device. It is idempotent.
	Stop(ctx context.Context) error
}

// LeaseStore persists leases. The in-memory store is the gateway's
// projection; the daemon may back it with the control plane.
type LeaseStore interface {
	Put(ctx context.Context, lease *Lease) error
	Get(ctx context.Context, id LeaseID) (*Lease, error)
	Delete(ctx context.Context, id LeaseID) error
	// List returns every lease, ordered by IssuedAt.
	List(ctx context.Context) ([]*Lease, error)
	// FindByDevice returns the tenant's lease for the device, if any.
	FindByDevice(ctx context.Context, tenantID, deviceID string) (*Lease, bool, error)
}

// Clock is the time source; tests inject one.
type Clock interface {
	Now() time.Time
	// Tick returns a channel that delivers once every d.
	Tick(d time.Duration) (<-chan time.Time, func())
}

// realClock is the wall clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Tick(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Deps are the service's dependencies. Every one is an interface.
type Deps struct {
	Identity IdentityPolicy
	Verifier Verifier
	Posture  PostureEvaluator
	Factors  FactorVerifier
	IPAM     ipam.Allocator
	// DataPlanes are the planes this gateway runs, keyed by kind; every kind
	// the Config offers must be present.
	DataPlanes map[DataPlaneKind]DataPlane
	Leases     LeaseStore
	Audit      calleradmission.Auditor
	Clock      Clock
	Logger     *slog.Logger
}

func (d *Deps) validate(cfg Config) error {
	switch {
	case d.Identity == nil:
		return &ErrDepsMissing{Dep: "Identity"}
	case d.Verifier == nil:
		return &ErrDepsMissing{Dep: "Verifier"}
	case d.Posture == nil:
		return &ErrDepsMissing{Dep: "Posture"}
	case d.Factors == nil:
		return &ErrDepsMissing{Dep: "Factors"}
	case d.IPAM == nil:
		return &ErrDepsMissing{Dep: "IPAM"}
	case d.Leases == nil:
		return &ErrDepsMissing{Dep: "Leases"}
	case d.Audit == nil:
		return &ErrDepsMissing{Dep: "Audit"}
	}
	for _, k := range cfg.DataPlanes {
		if d.DataPlanes[k] == nil {
			return &ErrDepsMissing{Dep: "DataPlanes[" + string(k) + "]"}
		}
	}
	return nil
}
