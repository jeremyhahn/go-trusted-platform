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

package backends

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Ceremony backend typed errors.

// ErrCeremonyBackendClientNil indicates the backend was constructed without a
// QuicBaaS SDK client.
var ErrCeremonyBackendClientNil = errors.New("ceremony backend: quicbaas client is nil")

// ErrCeremonyTransportUnavailable indicates the ceremony transport client could
// not be resolved from the QuicBaaS SDK.
var ErrCeremonyTransportUnavailable = errors.New("ceremony backend: ceremony transport client not available")

// ErrCeremonyAdminIssuerNil indicates Initialize was called on a backend
// constructed without an AdminBundleIssuer. Init is refused before the
// ceremony runs, because an init without an admin bundle locks the operator
// out of the platform it just initialized.
type ErrCeremonyAdminIssuerNil struct{}

// Error returns a human-readable description.
func (e *ErrCeremonyAdminIssuerNil) Error() string {
	return "ceremony backend: no admin bundle issuer configured"
}

// ErrCeremonyAdminBundle indicates minting the admin bundle failed. The
// ceremony has not run, so the platform is still uninitialized.
type ErrCeremonyAdminBundle struct {
	Cause error
}

// Error returns a human-readable description.
func (e *ErrCeremonyAdminBundle) Error() string {
	return "ceremony backend: issue admin bundle: " + e.Cause.Error()
}

// Unwrap returns the underlying failure.
func (e *ErrCeremonyAdminBundle) Unwrap() error {
	return e.Cause
}

// ErrAdminBundleIncomplete indicates an AdminBundleIssuer returned no error
// but also no certificate or no key.
type ErrAdminBundleIncomplete struct{}

// Error returns a human-readable description.
func (e *ErrAdminBundleIncomplete) Error() string {
	return "admin bundle is missing its certificate or key"
}

// AdminBundle is the one-shot admin client credential returned by init.
type AdminBundle struct {
	// CertPEM is the admin client certificate, signed by the platform CA.
	CertPEM string
	// KeyPEM is the matching private key.
	KeyPEM string
}

// AdminBundleIssuer mints the admin client credential that Initialize
// returns. The platform keeps no copy of the key.
type AdminBundleIssuer interface {
	IssueAdminBundle(ctx context.Context) (*AdminBundle, error)
}

// CeremonyBackend implements daemon.CeremonyBackend by delegating every call
// to the QuicBaaS SDK's BarrierCeremonyService. The underlying transport
// terminates at go-qrdb's ceremony service.
//
// The backend is safe for concurrent use. It holds a reference to the
// QuicBaaS SDK client rather than a cached ceremony transport client so that
// client-side failover / lazy initialisation inside the SDK keeps working.
type CeremonyBackend struct {
	logger *logging.Logger
	client quicbaassdk.Client
	admin  AdminBundleIssuer
}

// Compile-time assertion that CeremonyBackend satisfies daemon.CeremonyBackend.
var _ daemon.CeremonyBackend = (*CeremonyBackend)(nil)

// NewCeremonyBackend constructs a new ceremony backend bound to the given
// QuicBaaS SDK client. admin mints the admin bundle that Initialize returns.
//
// Passing a nil client is allowed so that the daemon can be partially wired
// during bootstrap. Calls will return ErrCeremonyBackendClientNil until the
// backend is replaced with a live one. A nil admin issuer makes Initialize
// return ErrCeremonyAdminIssuerNil; the other calls do not need it.
func NewCeremonyBackend(logger *logging.Logger, client quicbaassdk.Client, admin AdminBundleIssuer) *CeremonyBackend {
	return &CeremonyBackend{logger: logger, client: client, admin: admin}
}

// transport resolves the ceremony transport client from the QuicBaaS SDK.
// Returned errors are typed for uniform translation by transport adapters.
func (b *CeremonyBackend) transport() (quicbaassdk.QRDBCeremonyClient, error) {
	if b == nil || b.client == nil {
		return nil, ErrCeremonyBackendClientNil
	}
	mgmt := b.client.BarrierCeremonyMgmt()
	if mgmt == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	c, err := mgmt.Ceremony()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return c, nil
}

// parseExpiresAt converts the upstream RFC3339 string to time.Time. Empty or
// unparseable timestamps yield the zero time without erroring; callers decide
// whether the absence is fatal.
func parseExpiresAt(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		// Some servers emit RFC3339 without nanoseconds; fall back to the
		// plain format before giving up.
		if t2, err2 := time.Parse(time.RFC3339, s); err2 == nil {
			return t2
		}
		return time.Time{}
	}
	return t
}

// thresholdQuorum returns M from an "M-of-N" threshold spec: the number of
// officer shares that reconstruct the secret, which is what the ceremony's
// Threshold field means. N is the officer count. A spec that does not match,
// including the empty one, yields zero, the ceremony's single-admin mode.
func thresholdQuorum(spec string) int {
	quorum, _, found := strings.Cut(spec, "-of-")
	if !found {
		return 0
	}
	m, err := strconv.Atoi(quorum)
	if err != nil || m < 0 {
		return 0
	}
	return m
}

// ceremonyOfficers maps the service-layer officers onto the SDK ceremony
// request. It returns nil for none, so a single-admin init carries no list.
func ceremonyOfficers(officers []daemon.CeremonyOfficer) []quicbaassdk.QRDBCeremonyOfficerRequest {
	if len(officers) == 0 {
		return nil
	}
	out := make([]quicbaassdk.QRDBCeremonyOfficerRequest, 0, len(officers))
	for _, officer := range officers {
		out = append(out, quicbaassdk.QRDBCeremonyOfficerRequest{
			Username: officer.Username,
			CSRPEM:   officer.CSRPEM,
		})
	}
	return out
}

// mapCeremonyState translates the upstream state string to the service-layer
// enumeration using a map-based dispatch.
func mapCeremonyState(s string) daemon.CeremonyStateValue {
	v, ok := ceremonyStateMap[s]
	if !ok {
		return daemon.CeremonyStateUnknown
	}
	return v
}

// ceremonyStateMap routes upstream state strings to the typed service values.
// Keys cover both go-qrdb's canonical spellings and common aliases.
var ceremonyStateMap = map[string]daemon.CeremonyStateValue{
	"":              daemon.CeremonyStateUnknown,
	"unknown":       daemon.CeremonyStateUnknown,
	"uninitialized": daemon.CeremonyStateUninitialized,
	"uninit":        daemon.CeremonyStateUninitialized,
	"in_progress":   daemon.CeremonyStateInProgress,
	"inprogress":    daemon.CeremonyStateInProgress,
	"in-progress":   daemon.CeremonyStateInProgress,
	"complete":      daemon.CeremonyStateComplete,
	"completed":     daemon.CeremonyStateComplete,
	"finalized":     daemon.CeremonyStateComplete,
}

// Initialize delegates to go-qrdb's ceremony.Initialize and returns the
// admin bundle with the result.
//
// The bundle is minted before the ceremony runs. Minting changes nothing on
// the platform, so if it fails, init can simply be retried. Once the ceremony
// has succeeded, the result always carries the bundle.
func (b *CeremonyBackend) Initialize(ctx context.Context, req *daemon.CeremonyInitRequest) (*daemon.CeremonyInitResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	if b.admin == nil {
		return nil, &ErrCeremonyAdminIssuerNil{}
	}
	bundle, err := b.admin.IssueAdminBundle(ctx)
	if err != nil {
		return nil, &ErrCeremonyAdminBundle{Cause: err}
	}
	if bundle == nil || bundle.CertPEM == "" || bundle.KeyPEM == "" {
		return nil, &ErrCeremonyAdminBundle{Cause: &ErrAdminBundleIncomplete{}}
	}

	initReq := &quicbaassdk.QRDBCeremonyInitializeRequest{
		SOPin:                  req.SOPIN,
		UserPin:                req.UserPIN,
		CredentialSealStrategy: req.CredentialSealStrategy,
		Threshold:              thresholdQuorum(req.Threshold),
		Hostname:               req.Hostname,
		SANs:                   req.SANs,
		Officers:               ceremonyOfficers(req.Officers),
	}

	resp, err := c.CeremonyInitialize(ctx, initReq)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}

	return &daemon.CeremonyInitResult{
		// The ceremony ID is the SPKI pin, by design rather than as a
		// placeholder: a cluster runs exactly one bootstrap ceremony, and
		// the pin names the CA key that ceremony minted, so it identifies
		// the ceremony uniquely and stays stable across restarts. go-qrdb
		// assigns no other identifier (CeremonyInitializeResponse carries
		// none), and Status reports the same value, so the IDs agree.
		CeremonyID:    resp.SPKIPin,
		State:         mapCeremonyState(resp.State),
		InitializedAt: time.Now().UTC(),
		AdminCertPEM:  bundle.CertPEM,
		AdminKeyPEM:   bundle.KeyPEM,
		SPKIPin:       resp.SPKIPin,
	}, nil
}

// Status delegates to go-qrdb's ceremony.Status.
func (b *CeremonyBackend) Status(ctx context.Context) (*daemon.CeremonyStatusInfo, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	resp, err := c.CeremonyStatus(ctx)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return &daemon.CeremonyStatusInfo{
		CeremonyID: resp.SPKIPin,
		State:      mapCeremonyState(resp.State),
	}, nil
}

// ClaimCertBegin delegates to go-qrdb's ceremony.ClaimCertBegin.
//
// The AuthenticatorType / Slot / CredentialID fields carried by the service
// request will be propagated once the upstream request struct carries them.
// Today the ceremony signature verification is backend-agnostic (signature
// over a nonce), so the routing happens client-side.
func (b *CeremonyBackend) ClaimCertBegin(ctx context.Context, req *daemon.CeremonyClaimCertBeginRequest) (*daemon.CeremonyClaimCertBeginResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}

	resp, err := c.CeremonyClaimCertBegin(ctx, &quicbaassdk.QRDBClaimCertBeginRequest{
		Username: req.Username,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}

	expiresAt := parseExpiresAt(resp.ExpiresAt)
	return &daemon.CeremonyClaimCertBeginResult{
		Nonce:       resp.NonceHex,
		ChallengeID: resp.NonceHex,
		ExpiresAt:   expiresAt,
	}, nil
}

// ClaimCertComplete delegates to go-qrdb's ceremony.ClaimCertComplete.
func (b *CeremonyBackend) ClaimCertComplete(ctx context.Context, req *daemon.CeremonyClaimCertCompleteRequest) (*daemon.CeremonyClaimCertCompleteResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	resp, err := c.CeremonyClaimCertComplete(ctx, &quicbaassdk.QRDBClaimCertCompleteRequest{
		Username:  req.Username,
		NonceHex:  req.Nonce,
		Signature: req.Signature,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return &daemon.CeremonyClaimCertCompleteResult{
		CertificatePEM: resp.CertPEM,
		ChainPEM:       resp.CACertPEM,
	}, nil
}

// ClaimShareBegin delegates to go-qrdb's ceremony.BeginClaimShare.
func (b *CeremonyBackend) ClaimShareBegin(ctx context.Context, req *daemon.CeremonyClaimShareBeginRequest) (*daemon.CeremonyClaimShareBeginResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	resp, err := c.CeremonyBeginClaimShare(ctx, &quicbaassdk.QRDBBeginClaimShareRequest{
		Username: req.Username,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return &daemon.CeremonyClaimShareBeginResult{
		Nonce:     resp.NonceHex,
		ExpiresAt: parseExpiresAt(resp.ExpiresAt),
	}, nil
}

// ClaimShareComplete delegates to go-qrdb's ceremony.CompleteClaimShare.
func (b *CeremonyBackend) ClaimShareComplete(ctx context.Context, req *daemon.CeremonyClaimShareCompleteRequest) (*daemon.CeremonyClaimShareResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	resp, err := c.CeremonyCompleteClaimShare(ctx, &quicbaassdk.QRDBCompleteClaimShareRequest{
		Username:  req.Username,
		NonceHex:  req.Nonce,
		Signature: req.Signature,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return &daemon.CeremonyClaimShareResult{
		Share: resp.ShareJSON,
		Index: int32(resp.ShareIndex),
	}, nil
}

// SignCSR delegates to go-qrdb's ceremony.SignCSR.
func (b *CeremonyBackend) SignCSR(ctx context.Context, req *daemon.CeremonySignCSRRequest) (*daemon.CeremonySignCSRResult, error) {
	c, err := b.transport()
	if err != nil {
		return nil, err
	}
	resp, err := c.CeremonySignCSR(ctx, &quicbaassdk.QRDBSignCSRInitRequest{
		Username: req.Username,
		SOPin:    req.SOPIN,
		CSRPEM:   req.CSRPEM,
		Role:     string(req.Role),
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrCeremonyTransportUnavailable
	}
	return &daemon.CeremonySignCSRResult{
		CertificatePEM: resp.CertPEM,
	}, nil
}
