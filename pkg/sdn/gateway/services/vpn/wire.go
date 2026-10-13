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
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// The admission wire contract (docs/vpn/api.md §5): the JSON the gateway's
// admission listener and the client agent (pkg/vpn/agent) exchange. The
// gateway owns it, so the listener and the agent cannot drift apart.

// Admission listener routes.
const (
	PathChallenges = "/api/v1/vpn/challenges"
	PathAdmissions = "/api/v1/vpn/admissions"
	pathLeases     = "/api/v1/vpn/leases/"
)

// LeasePath is the route that revokes lease id (DELETE).
func LeasePath(id LeaseID) string {
	return pathLeases + url.PathEscape(string(id))
}

// LeaseRenewPath is the route that renews lease id (POST).
func LeaseRenewPath(id LeaseID) string {
	return LeasePath(id) + "/renew"
}

// ChallengeWire is the response to POST PathChallenges: the single-use nonce
// the quote and the person factor are bound to, and the data planes the
// gateway offers, preferred first.
type ChallengeWire struct {
	Nonce      []byte          `json:"nonce"`
	DataPlanes []DataPlaneKind `json:"data_planes"`
}

// PCRWire is one quoted PCR; Value is hex.
type PCRWire struct {
	Index     int                    `json:"index"`
	Value     string                 `json:"value"`
	Algorithm manifest.HashAlgorithm `json:"algorithm,omitempty"`
}

// AttestationWire is the TPM quote over the challenge nonce.
type AttestationWire struct {
	Quote              []byte                 `json:"quote"`
	Signature          []byte                 `json:"signature"`
	SignatureAlgorithm string                 `json:"signature_algorithm,omitempty"`
	PCRs               []PCRWire              `json:"pcrs"`
	PCRDigest          []byte                 `json:"pcr_digest,omitempty"`
	HashAlgorithm      manifest.HashAlgorithm `json:"hash_algorithm,omitempty"`
	AKPublicKey        []byte                 `json:"ak_public_key"`
	IDevIDCertificate  []byte                 `json:"idevid_certificate,omitempty"`
	FirmwareVersion    string                 `json:"firmware_version,omitempty"`
	Timestamp          time.Time              `json:"timestamp"`
}

// AttestationFromHost encodes a host attestation for the wire. The nonce is
// not repeated: it travels once, at the top of the request.
func AttestationFromHost(att *manifest.HostAttestation) *AttestationWire {
	if att == nil {
		return nil
	}
	pcrs := make([]PCRWire, 0, len(att.PCRs))
	for _, p := range att.PCRs {
		pcrs = append(pcrs, PCRWire{Index: p.Index, Value: hex.EncodeToString(p.Value), Algorithm: p.Algorithm})
	}
	return &AttestationWire{
		Quote:              att.QuoteData,
		Signature:          att.Signature,
		SignatureAlgorithm: att.SignatureAlgorithm,
		PCRs:               pcrs,
		PCRDigest:          att.PCRDigest,
		HashAlgorithm:      att.HashAlgorithm,
		AKPublicKey:        att.AKPublicKey,
		IDevIDCertificate:  att.IDevIDCertificate,
		FirmwareVersion:    att.FirmwareVersion,
		Timestamp:          att.Timestamp,
	}
}

// HostAttestation decodes the wire form, binding it to the request's nonce.
// A PCR value that is not hex is an ErrInvalidRequest.
func (w *AttestationWire) HostAttestation(nonce []byte) (*manifest.HostAttestation, error) {
	if w == nil {
		return nil, nil
	}
	pcrs := make([]manifest.PCRValue, 0, len(w.PCRs))
	for _, p := range w.PCRs {
		value, err := hex.DecodeString(p.Value)
		if err != nil {
			return nil, &ErrInvalidRequest{Field: "attestation.pcrs[" + strconv.Itoa(p.Index) + "].value", Reason: "not hex"}
		}
		pcrs = append(pcrs, manifest.PCRValue{Index: p.Index, Value: value, Algorithm: p.Algorithm})
	}
	return &manifest.HostAttestation{
		QuoteData:          w.Quote,
		Signature:          w.Signature,
		SignatureAlgorithm: w.SignatureAlgorithm,
		PCRs:               pcrs,
		PCRDigest:          w.PCRDigest,
		Nonce:              nonce,
		Timestamp:          w.Timestamp,
		AKPublicKey:        w.AKPublicKey,
		IDevIDCertificate:  w.IDevIDCertificate,
		HashAlgorithm:      w.HashAlgorithm,
		FirmwareVersion:    w.FirmwareVersion,
	}, nil
}

// PersonFactorWire is the presence proof over the challenge nonce.
type PersonFactorWire struct {
	Kind         PersonFactorKind `json:"kind"`
	Assertion    []byte           `json:"assertion"`
	CredentialID string           `json:"credential_id"`
}

// PersonFactorToWire encodes a person factor; nil stays nil.
func PersonFactorToWire(f *PersonFactor) *PersonFactorWire {
	if f == nil {
		return nil
	}
	return &PersonFactorWire{Kind: f.Kind, Assertion: f.Assertion, CredentialID: f.CredentialID}
}

// PersonFactor decodes the wire form; nil stays nil.
func (w *PersonFactorWire) PersonFactor() *PersonFactor {
	if w == nil {
		return nil
	}
	return &PersonFactor{Kind: w.Kind, Assertion: w.Assertion, CredentialID: w.CredentialID}
}

// PeerWire carries the client key of the requested data plane. MASQUE needs
// none: the listener binds the lease to the admitted client certificate.
type PeerWire struct {
	WireGuardPublicKey []byte `json:"wireguard_public_key,omitempty"`
}

// AdmissionRequestWire is the body of POST PathAdmissions.
type AdmissionRequestWire struct {
	DeviceID     string            `json:"device_id"`
	Nonce        []byte            `json:"nonce"`
	Attestation  *AttestationWire  `json:"attestation"`
	Posture      *PostureReport    `json:"posture"`
	PersonFactor *PersonFactorWire `json:"person_factor,omitempty"`
	DataPlane    DataPlaneKind     `json:"data_plane"`
	Peer         PeerWire          `json:"peer"`
	Zones        []string          `json:"zones,omitempty"`
}

// WireGuardEndpointWire is what a WireGuard client needs to reach the
// gateway's interface.
type WireGuardEndpointWire struct {
	PublicKey []byte   `json:"public_key"`
	Endpoint  string   `json:"endpoint"`
	Routes    []string `json:"routes"`
}

// MASQUEEndpointWire is the CONNECT-IP URI template and the routes the
// gateway advertises.
type MASQUEEndpointWire struct {
	Template string   `json:"template"`
	Routes   []string `json:"routes"`
}

// EndpointWire carries the endpoint of the lease's data plane; exactly one
// member is set.
type EndpointWire struct {
	WireGuard *WireGuardEndpointWire `json:"wireguard,omitempty"`
	MASQUE    *MASQUEEndpointWire    `json:"masque,omitempty"`
}

// LeaseWire is the admission and renewal response. RenewAtUnix is when the
// renewal window opens: the agent's next re-attestation.
type LeaseWire struct {
	ID            LeaseID        `json:"id"`
	DeviceID      string         `json:"device_id"`
	TenantID      string         `json:"tenant_id"`
	Address       string         `json:"address"`
	Zones         []string       `json:"zones"`
	DataPlane     DataPlaneKind  `json:"data_plane"`
	IssuedAtUnix  int64          `json:"issued_at_unix"`
	ExpiresAtUnix int64          `json:"expires_at_unix"`
	RenewAtUnix   int64          `json:"renew_at_unix"`
	Renewals      int            `json:"renewals"`
	Verdict       VerdictSummary `json:"verdict"`
	Endpoint      EndpointWire   `json:"endpoint"`
}

// LeaseToWire encodes a lease with its data plane's endpoint; renewWindow is
// the service's Config.RenewWindow.
func LeaseToWire(l *Lease, renewWindow time.Duration, endpoint EndpointWire) *LeaseWire {
	return &LeaseWire{
		ID:            l.ID,
		DeviceID:      l.DeviceID,
		TenantID:      l.TenantID,
		Address:       l.Address.String(),
		Zones:         l.Zones,
		DataPlane:     l.DataPlane,
		IssuedAtUnix:  l.IssuedAt.Unix(),
		ExpiresAtUnix: l.ExpiresAt.Unix(),
		RenewAtUnix:   l.ExpiresAt.Add(-renewWindow).Unix(),
		Renewals:      l.Renewals,
		Verdict:       l.Verdict,
		Endpoint:      endpoint,
	}
}

// RefusalClass names why a request was refused, without the detail that
// would tell a probing client which policy or identity list it hit.
type RefusalClass string

// Refusal classes beyond the caller-admission reasons, which ErrPeerRefused
// carries as its class unchanged.
const (
	RefusalAttestationFailed     RefusalClass = "attestation-failed"
	RefusalPostureViolation      RefusalClass = "posture-violation"
	RefusalPostureUnavailable    RefusalClass = "posture-unavailable"
	RefusalPersonFactorRequired  RefusalClass = "person-factor-required"
	RefusalPersonFactorInvalid   RefusalClass = "person-factor-invalid"
	RefusalPoolExhausted         RefusalClass = "pool-exhausted"
	RefusalDataPlaneUnavailable  RefusalClass = "data-plane-unavailable"
	RefusalLeaseStoreUnavailable RefusalClass = "lease-store-unavailable"
	RefusalLeaseExpired          RefusalClass = "lease-expired"
	RefusalLeaseNotFound         RefusalClass = "lease-not-found"
	RefusalPeerNotEnrolled       RefusalClass = "peer-not-enrolled"
	RefusalRenewalNotOpen        RefusalClass = "renewal-not-open"
	RefusalNonceUnknown          RefusalClass = "nonce-unknown"
	RefusalZoneNotAllowed        RefusalClass = "zone-not-allowed"
	RefusalInvalidRequest        RefusalClass = "invalid-request"
	RefusalNotStarted            RefusalClass = "not-started"
	RefusalInternal              RefusalClass = "internal"
)

// RefusalWire is the body of every non-2xx admission listener response.
// Rules is set only for a posture violation.
type RefusalWire struct {
	Reason RefusalClass `json:"reason"`
	Rules  []string     `json:"rules,omitempty"`
}

// refusalRule maps one error type to its refusal and HTTP status.
type refusalRule func(err error) (RefusalWire, int, bool)

// refusalRules is checked in order, so an error that wraps another is
// classified by the outermost type (engineering.md §3).
var refusalRules = []refusalRule{
	func(err error) (RefusalWire, int, bool) {
		var e *ErrPeerRefused
		if !errors.As(err, &e) {
			return RefusalWire{}, 0, false
		}
		if e.Unauthenticated() {
			return RefusalWire{Reason: RefusalClass(e.Reason)}, http.StatusUnauthorized, true
		}
		return RefusalWire{Reason: RefusalClass(e.Reason)}, http.StatusForbidden, true
	},
	func(err error) (RefusalWire, int, bool) {
		var e *ErrPostureViolation
		if !errors.As(err, &e) {
			return RefusalWire{}, 0, false
		}
		return RefusalWire{Reason: RefusalPostureViolation, Rules: e.Violations}, http.StatusForbidden, true
	},
	classify[ErrAttestationFailed](RefusalAttestationFailed, http.StatusForbidden),
	classify[ErrPeerNotEnrolled](RefusalPeerNotEnrolled, http.StatusForbidden),
	classify[ErrZoneNotAllowed](RefusalZoneNotAllowed, http.StatusForbidden),
	classify[ErrPersonFactorRequired](RefusalPersonFactorRequired, http.StatusUnauthorized),
	classify[ErrPersonFactorInvalid](RefusalPersonFactorInvalid, http.StatusUnauthorized),
	classify[ErrNonceUnknown](RefusalNonceUnknown, http.StatusUnauthorized),
	classify[ErrPostureUnavailable](RefusalPostureUnavailable, http.StatusServiceUnavailable),
	classify[ErrPoolExhausted](RefusalPoolExhausted, http.StatusServiceUnavailable),
	classify[ErrDataPlaneUnavailable](RefusalDataPlaneUnavailable, http.StatusServiceUnavailable),
	classify[ErrLeaseStoreUnavailable](RefusalLeaseStoreUnavailable, http.StatusServiceUnavailable),
	classify[ErrNotStarted](RefusalNotStarted, http.StatusServiceUnavailable),
	classify[ErrLeaseExpired](RefusalLeaseExpired, http.StatusGone),
	classify[ErrLeaseNotFound](RefusalLeaseNotFound, http.StatusNotFound),
	classify[ErrRenewalNotOpen](RefusalRenewalNotOpen, http.StatusConflict),
	classify[ErrInvalidRequest](RefusalInvalidRequest, http.StatusBadRequest),
}

// classify builds the rule for an error type whose refusal has no detail.
func classify[T any, P interface {
	*T
	error
}](class RefusalClass, status int) refusalRule {
	return func(err error) (RefusalWire, int, bool) {
		var e P
		if !errors.As(err, &e) {
			return RefusalWire{}, 0, false
		}
		return RefusalWire{Reason: class}, status, true
	}
}

// RefusalOf maps an admission, renewal or revocation error to the refusal
// the listener sends and its HTTP status. An error of no known type is an
// internal error, so a new failure mode never leaks its text to the client.
func RefusalOf(err error) (RefusalWire, int) {
	for _, rule := range refusalRules {
		if refusal, status, ok := rule(err); ok {
			return refusal, status
		}
	}
	return RefusalWire{Reason: RefusalInternal}, http.StatusInternalServerError
}
