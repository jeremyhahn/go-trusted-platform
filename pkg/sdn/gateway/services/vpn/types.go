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
	"net/netip"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// DataPlaneKind names a data plane an admitted client is placed on.
// DataPlaneMASQUE exists in every build; DataPlaneWireGuard is declared in a
// `!fips` file and is absent — not disabled — from a FIPS build.
type DataPlaneKind string

// DataPlaneMASQUE is CONNECT-IP over HTTP/3 (RFC 9484) on the platform's
// QUIC stack, FIPS-approved primitives only.
const DataPlaneMASQUE DataPlaneKind = "masque"

// dataPlaneKinds is the set of kinds this build offers. The `!fips` file
// registers WireGuard at init.
var dataPlaneKinds = map[DataPlaneKind]bool{DataPlaneMASQUE: true}

// Known reports whether kind is a data plane this build can offer.
func (k DataPlaneKind) Known() bool {
	return dataPlaneKinds[k]
}

// LeaseID identifies a lease. It is opaque to clients.
type LeaseID string

// PersonFactorKind names how the person proved presence.
type PersonFactorKind string

const (
	// PersonFactorFIDO2 is a WebAuthn/FIDO2 assertion over the session nonce.
	PersonFactorFIDO2 PersonFactorKind = "fido2"
	// PersonFactorPIV is a PIV signature over the session nonce.
	PersonFactorPIV PersonFactorKind = "piv"
)

// PersonFactor is the person's proof of presence bound to the session nonce.
// It is a signature, never a shared secret.
type PersonFactor struct {
	Kind         PersonFactorKind
	CredentialID string
	Assertion    []byte
}

// SecureBootPosture is the client's Secure Boot state.
type SecureBootPosture struct {
	Enabled   bool `json:"enabled"`
	SetupMode bool `json:"setup_mode"`
	Available bool `json:"available"`
}

// IMAPosture is the client's IMA state.
type IMAPosture struct {
	Available    bool   `json:"available"`
	Enabled      bool   `json:"enabled"`
	PolicyLoaded bool   `json:"policy_loaded"`
	LogDigest    string `json:"log_digest,omitempty"`
}

// FDEPosture is the client's disk-encryption state.
type FDEPosture struct {
	RootEncrypted bool `json:"root_encrypted"`
}

// PostureReport is what the client agent can collect today (docs/vpn
// engineering §4). It is the OPA input verbatim.
type PostureReport struct {
	SecureBoot    SecureBootPosture `json:"secure_boot"`
	IMA           IMAPosture        `json:"ima"`
	FDE           FDEPosture        `json:"fde"`
	AgentVersion  string            `json:"agent_version"`
	OSRelease     string            `json:"os_release"`
	KernelRelease string            `json:"kernel_release"`
	CollectedAt   time.Time         `json:"collected_at"`
}

// PeerKeys is the client-side data-plane material an admission carries: a
// WireGuard peer public key, or nothing for MASQUE (the TLS client
// certificate is the identity there).
type PeerKeys struct {
	WireGuardPublicKey []byte
}

// AdmissionRequest is one fresh admission (docs/vpn api.md §2).
type AdmissionRequest struct {
	// Peer is the mTLS peer the admission listener extracted.
	Peer *calleradmission.Peer
	// DeviceID is the device the client claims to be; the verifier binds it
	// to the quote.
	DeviceID string
	// TenantID scopes the lease and the pool.
	TenantID string
	// Nonce echoes the challenge the service issued.
	Nonce []byte
	// Attestation is the quote and host state the verifier checks.
	Attestation *manifest.HostAttestation
	// Posture is the OPA input.
	Posture *PostureReport
	// PersonFactor is the presence proof; nil when the policy does not
	// require one on this step.
	PersonFactor *PersonFactor
	// DataPlane is the requested data plane.
	DataPlane DataPlaneKind
	// Peer keys for the requested data plane.
	Keys PeerKeys
	// RequestedZones are the zones the client asks to reach.
	RequestedZones []string
}

// Evidence is what a renewal re-submits: a fresh quote and posture, and the
// person factor when the policy requires it on renewal.
type Evidence struct {
	Nonce        []byte
	Attestation  *manifest.HostAttestation
	Posture      *PostureReport
	PersonFactor *PersonFactor
}

// VerdictSummary is the part of the attestation verdict a lease carries.
type VerdictSummary struct {
	Passed        bool   `json:"passed"`
	Cryptographic bool   `json:"cryptographic"`
	ProfileID     uint64 `json:"profile_id"`
}

// Lease is what an admitted client holds. It is a tenant-scoped entity on
// the control plane; the gateway keeps a projection.
type Lease struct {
	ID        LeaseID        `json:"id"`
	DeviceID  string         `json:"device_id"`
	TenantID  string         `json:"tenant_id"`
	Address   netip.Prefix   `json:"address"`
	Zones     []string       `json:"zones"`
	DataPlane DataPlaneKind  `json:"data_plane"`
	Keys      PeerKeys       `json:"-"`
	IssuedAt  time.Time      `json:"issued_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Renewals  int            `json:"renewals"`
	Verdict   VerdictSummary `json:"verdict"`
}

// Expired reports whether the lease is past its expiry at now.
func (l *Lease) Expired(now time.Time) bool {
	return !now.Before(l.ExpiresAt)
}

// RevokeReason names why a lease ended.
type RevokeReason string

const (
	// RevokeExpired: the lease passed ExpiresAt without a renewal.
	RevokeExpired RevokeReason = "expired"
	// RevokeOperator: an operator revoked it.
	RevokeOperator RevokeReason = "operator"
	// RevokeClient: the client disconnected.
	RevokeClient RevokeReason = "client"
	// RevokeReplaced: a second admission for the same device replaced it.
	RevokeReplaced RevokeReason = "replaced"
	// RevokeAttestation: re-attestation failed.
	RevokeAttestation RevokeReason = "attestation-failed"
	// RevokePosture: the posture drifted into violation.
	RevokePosture RevokeReason = "posture-violation"
)

// PersonFactorPolicy says when the person must prove presence.
type PersonFactorPolicy struct {
	OnAdmit bool `yaml:"on-admit" json:"on_admit" mapstructure:"on-admit"`
	OnRenew bool `yaml:"on-renew" json:"on_renew" mapstructure:"on-renew"`
}

// ListenerConfig is the admission listener's bind point (mTLS-only).
type ListenerConfig struct {
	BindHost string `yaml:"bind-host" json:"bind_host" mapstructure:"bind-host"`
	Port     int    `yaml:"port" json:"port" mapstructure:"port"`
}

// Config is the service configuration (docs/vpn engineering §5).
type Config struct {
	Listener            ListenerConfig     `yaml:"listener" json:"listener" mapstructure:"listener"`
	DataPlanes          []DataPlaneKind    `yaml:"data-planes" json:"data_planes" mapstructure:"data-planes"`
	Pool                string             `yaml:"pool" json:"pool" mapstructure:"pool"`
	LeaseTTL            time.Duration      `yaml:"lease-ttl" json:"lease_ttl" mapstructure:"lease-ttl"`
	RenewWindow         time.Duration      `yaml:"renew-window" json:"renew_window" mapstructure:"renew-window"`
	RequirePersonFactor PersonFactorPolicy `yaml:"require-person-factor" json:"require_person_factor" mapstructure:"require-person-factor"`
	PosturePolicy       string             `yaml:"posture-policy" json:"posture_policy" mapstructure:"posture-policy"`
	AllowTo             []string           `yaml:"allow-to" json:"allow_to" mapstructure:"allow-to"`
	// NonceTTL bounds how long an issued challenge may be answered.
	NonceTTL time.Duration `yaml:"nonce-ttl" json:"nonce_ttl" mapstructure:"nonce-ttl"`
}

const (
	// DefaultListenerPort is the admission listener's default port.
	DefaultListenerPort = 4433
	// DefaultLeaseTTL is the default lease lifetime.
	DefaultLeaseTTL = 8 * time.Hour
	// DefaultRenewWindow is the default window before expiry in which a
	// renewal is accepted.
	DefaultRenewWindow = 30 * time.Minute
	// DefaultPosturePolicy is the OPA policy name evaluated on admission.
	DefaultPosturePolicy = "vpn_posture"
	// DefaultNonceTTL bounds a challenge's life.
	DefaultNonceTTL = 2 * time.Minute
	// MinLeaseTTL and MaxLeaseTTL are the lease bounds.
	MinLeaseTTL = 5 * time.Minute
	MaxLeaseTTL = 24 * time.Hour
)

// WithDefaults returns the configuration with every zero field defaulted.
func (c Config) WithDefaults() Config {
	if c.Listener.Port == 0 {
		c.Listener.Port = DefaultListenerPort
	}
	if len(c.DataPlanes) == 0 {
		c.DataPlanes = []DataPlaneKind{DataPlaneMASQUE}
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = DefaultLeaseTTL
	}
	if c.RenewWindow == 0 {
		c.RenewWindow = DefaultRenewWindow
	}
	if c.PosturePolicy == "" {
		c.PosturePolicy = DefaultPosturePolicy
	}
	if c.NonceTTL == 0 {
		c.NonceTTL = DefaultNonceTTL
	}
	if !c.RequirePersonFactor.OnAdmit && !c.RequirePersonFactor.OnRenew {
		c.RequirePersonFactor.OnAdmit = true
	}
	return c
}

// Validate refuses a configuration the service cannot run. It is applied to
// the defaulted configuration.
func (c Config) Validate() error {
	if c.Listener.Port <= 0 || c.Listener.Port > 65535 {
		return &ErrInvalidConfig{Field: "listener.port", Reason: "must be 1-65535"}
	}
	if len(c.DataPlanes) == 0 {
		return &ErrInvalidConfig{Field: "data-planes", Reason: "at least one data plane is required"}
	}
	seen := map[DataPlaneKind]bool{}
	for _, k := range c.DataPlanes {
		if !k.Known() {
			return &ErrInvalidConfig{Field: "data-planes", Reason: "data plane " + string(k) + " is not offered by this build"}
		}
		if seen[k] {
			return &ErrInvalidConfig{Field: "data-planes", Reason: "data plane " + string(k) + " listed twice"}
		}
		seen[k] = true
	}
	if c.Pool == "" {
		return &ErrInvalidConfig{Field: "pool", Reason: "the remote-access IPAM pool is required"}
	}
	if c.LeaseTTL < MinLeaseTTL || c.LeaseTTL > MaxLeaseTTL {
		return &ErrInvalidConfig{Field: "lease-ttl", Reason: "must be within [5m, 24h]"}
	}
	if c.RenewWindow <= 0 || c.RenewWindow >= c.LeaseTTL {
		return &ErrInvalidConfig{Field: "renew-window", Reason: "must be positive and shorter than lease-ttl"}
	}
	if c.NonceTTL <= 0 || c.NonceTTL > c.LeaseTTL {
		return &ErrInvalidConfig{Field: "nonce-ttl", Reason: "must be positive and no longer than lease-ttl"}
	}
	if c.PosturePolicy == "" {
		return &ErrInvalidConfig{Field: "posture-policy", Reason: "required"}
	}
	if len(c.AllowTo) == 0 {
		return &ErrInvalidConfig{Field: "allow-to", Reason: "at least one reachable zone is required"}
	}
	for _, z := range c.AllowTo {
		if z == "" {
			return &ErrInvalidConfig{Field: "allow-to", Reason: "empty zone name"}
		}
	}
	return nil
}

// Offers reports whether kind is configured on this service.
func (c Config) Offers(kind DataPlaneKind) bool {
	for _, k := range c.DataPlanes {
		if k == kind {
			return true
		}
	}
	return false
}

// allows reports whether zone is in the allow-to set.
func (c Config) allows(zone string) bool {
	for _, z := range c.AllowTo {
		if z == zone {
			return true
		}
	}
	return false
}
