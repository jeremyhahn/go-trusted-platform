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

// Package adminclaim implements the platform-admin claim ceremony: the
// one-time flow by which the human operator of a freshly provisioned node
// takes possession of the `admin` identity that qrdb firstboot created in
// the system tenant, and binds their own authenticator to it.
//
// # Why this exists
//
// Every node comes up with a passwordless, certificate-based system admin
// (bundle at <quicbaas data-dir>/admin/{admin.crt,admin.key}) holding the
// Admin role. Until an operator claims it, nobody can sign in to the
// console as the system admin, and the platform's administration surfaces
// have no authenticated principal to gate on.
//
// # System-level enrollment is certificate-only
//
// Per docs/08-bootstrap-auth-contract.md §"Admin enrollment" (amended
// 2026-09-01), the system admin — like every Security Officer and
// custodian — enrolls by CERTIFICATE, always, with no invite tokens. That
// rule is not configurable: these identities guard barrier material and a
// mailed token is not an acceptable bootstrap anchor for them.
//
// This package does NOT introduce an alternative bootstrap. The
// certificate remains the sole anchor: it is what the operator proves
// possession of, and nothing else grants a claim. Adding a passkey
// afterwards is ORDINARY FACTOR ENROLLMENT on an identity that is already
// bootstrapped — the same authfactors seam any user's second factor goes
// through — not a second way to become the admin. The tenant-admin
// invitation path added in the same amendment applies to TENANT admins and
// has no counterpart here.
//
// # Flow
//
//  1. challenge — the operator asks for a nonce.
//  2. verify    — the operator returns the nonce signed by admin.key,
//     together with admin.crt (or presents admin.crt in the TLS
//     handshake, where the handshake itself is the proof). The
//     platform validates the certificate against the QuicBaaS CA
//     anchor and issues a single-use, short-lived claim token.
//  3. passkey/begin + passkey/finish — with the claim token, the operator
//     registers their authenticator against the SDK WebAuthn ceremony
//     (Security().Auth().FIDO2()), which write-through enrolls it as a
//     fido2 auth factor for the admin identity.
//
// Afterwards the operator signs in to the console with that passkey, and
// the flow is closed FOR AS LONG AS AN AUTHENTICATOR REMAINS ENROLLED: a
// second claim is refused, so a stolen copy of the bootstrap certificate
// cannot displace the operator's passkey while they hold it.
//
// It is deliberately NOT irreversible. Removing the last factor re-opens
// the ceremony, and that is the recovery path for a lost authenticator —
// an irreversible marker would brick the deployment's admin identity the
// first time someone loses a security key, which is a worse failure than a
// re-claim that still demands the node's root-only private key. Removing a
// factor is itself an authenticated admin action.
//
// # Why the platform proves possession itself
//
// The SDK's unified mTLS login trusts a caller-supplied lookup key on the
// in-process embedded transport (the transport platformd runs). A
// certificate fingerprint is not a secret, so accepting one over REST
// would authenticate anybody who can read a public certificate. The
// platform is therefore the trust boundary for this flow and performs its
// own chain, identity and signature checks before it touches the SDK.
package adminclaim

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	quicbaasstore "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

const (
	// challengeTTL bounds how long a possession nonce stays redeemable.
	// The operator signs it with a local command, so a short window costs
	// nothing and keeps the pre-auth surface small.
	challengeTTL = 2 * time.Minute

	// claimTokenTTL bounds how long a proved claim stays open for the
	// passkey ceremony. It has to survive a human walking to the console
	// and touching a security key.
	claimTokenTTL = 10 * time.Minute

	// factorFIDO2 is the SDK factor name a WebAuthn credential enrolls
	// under. It is the marker that distinguishes an operator-enrolled
	// authenticator from the mtls factor firstboot created.
	factorFIDO2 = "fido2"

	// EventReclaim is the audit event type of a claim that completed on an
	// identity which previously carried a revoked fido2 factor. The owner
	// ruling on #169 keeps the claim re-claimable, so detection is the
	// control: a re-claim must never read as a first claim.
	EventReclaim = "adminclaim.reclaim"

	// EventReclaimStatusUnknown is the audit event type of a claim whose
	// factor history the SDK did not report, so a re-claim cannot be
	// ruled out. It is raised at the same severity as EventReclaim.
	EventReclaimStatusUnknown = "adminclaim.reclaim_status_unknown"
)

// FIDO2Ceremony is the narrow slice of the SDK WebAuthn relying-party
// client this package drives. Declaring it here keeps the dependency
// explicit and testable; it is satisfied directly by
// quicbaas.SDK().Security().Auth().FIDO2().
type FIDO2Ceremony interface {
	BeginRegistration(ctx context.Context, req *quicbaassdk.FIDO2BeginRegistrationRequest) (*quicbaassdk.FIDO2BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, req *quicbaassdk.FIDO2FinishRegistrationRequest) (*quicbaassdk.FIDO2FinishRegistrationResponse, error)
}

// FactorLister is the narrow slice of the SDK auth-factors client this
// package reads. Satisfied by
// quicbaas.SDK().Security().Auth().Factors().
//
// The platform only LISTS through this surface. It never calls Add for the
// passkey: the WebAuthn registration ceremony already write-through
// enrolls the fido2 factor, and enrolling it a second time from the client
// would either duplicate or conflict with what the ceremony recorded.
type FactorLister interface {
	List(ctx context.Context, userID string) (*quicbaassdk.AuthFactorListResponse, error)
}

// TokenIssuer mints the console bearer handed back when a claim completes.
type TokenIssuer interface {
	GenerateToken(user *entities.User) (string, error)
}

// ServiceParams are the dependencies of Service.
type ServiceParams struct {
	Logger *logging.Logger
	// Ceremony drives WebAuthn registration through the SDK.
	Ceremony FIDO2Ceremony
	// Factors reports which auth factors the admin identity carries.
	Factors FactorLister
	// Users is the platform-local user store the console authenticates
	// against. The claim materialises the admin there with the admin role
	// so the RBAC route guards resolve it from the issued token.
	Users service.UserServicer
	// TokenIssuer mints the console bearer on a completed claim.
	TokenIssuer TokenIssuer
	// TrustAnchors is the pool the presented admin certificate must chain
	// to — the QuicBaaS CA bundle, not the platform CA.
	TrustAnchors *x509.CertPool
	// TenantID is the platform's adopted operating tenant (the firstboot
	// system tenant). Every SDK ceremony call is scoped to it.
	TenantID string
	// AdminUsername is the firstboot admin's username. Defaults to
	// common.AdminUsername when empty.
	AdminUsername string
	// AdminEmail is the admin account's email, which is the identifier the
	// FIDO2 ceremony enrols the passkey against. It is a DIFFERENT
	// identifier from AdminUsername and the two are not interchangeable:
	// the backbone resolves the account with GetByEmail and documents that
	// "a username is a different identifier and is not accepted"
	// (go-xkms BeginRegistrationRequest.Email).
	//
	// There is deliberately no default. Deriving one — from the username,
	// the hostmaster, or the domain — would let the ceremony enrol the
	// platform's one-time ownership credential against an account nobody
	// named, and this is a trust boundary. Absent, NewService fails closed.
	AdminEmail string
	// MultiInstance reports that this deployment runs more than one
	// platformd instance against one store. The process-local completion
	// lock then serialises one instance only and the SDK factor enrolment
	// is not conditional, so a second instance could enrol a different
	// authenticator for the same one-time ownership transfer. The
	// ceremony is therefore REFUSED when true unless Transactions is set.
	MultiInstance bool
	// Transactions is the store's compare-and-swap client. When set, the
	// claim's completion runs under a store-wide lease, so exactly one
	// instance at a time can read the factor history and enrol (#172),
	// and a multi-instance deployment is served. Challenges and claim
	// tokens stay process-local: a token proved on one instance is
	// refused by another, so the ceremony runs against one instance.
	// Wire it only once ProbeTransactions succeeds.
	Transactions TransactionExecutor
}

// Service holds the admin-claim business logic. The REST handler owns
// nothing but HTTP binding.
type Service struct {
	logger        *logging.Logger
	ceremony      FIDO2Ceremony
	factors       FactorLister
	users         service.UserServicer
	tokenIssuer   TokenIssuer
	trustAnchors  *x509.CertPool
	tenantID      string
	adminUsername string
	adminEmail    string
	challenges    *secretStore
	claims        *secretStore
	// refuseMultiInstance closes the ceremony on a multi-instance
	// deployment with no store-wide completion lease.
	refuseMultiInstance bool
	// completion is the store-wide completion lease, nil when no
	// transaction client is wired.
	completion *completionLock
	// completing serialises the claim's one-time completion; see
	// FinishPasskey.
	completing sync.Mutex
}

// NewService constructs the claim service, failing closed on any missing
// dependency: a claim flow that cannot verify a certificate, cannot run
// the ceremony, or cannot record the result must not be reachable at all.
func NewService(params ServiceParams) (*Service, error) {
	if params.Logger == nil {
		return nil, ErrDependencyRequired{Name: "logger"}
	}
	if params.Ceremony == nil {
		return nil, ErrDependencyRequired{Name: "FIDO2 ceremony client"}
	}
	if params.Factors == nil {
		return nil, ErrDependencyRequired{Name: "auth factors client"}
	}
	if params.Users == nil {
		return nil, ErrDependencyRequired{Name: "user service"}
	}
	if params.TokenIssuer == nil {
		return nil, ErrDependencyRequired{Name: "token issuer"}
	}
	if params.TrustAnchors == nil {
		return nil, ErrDependencyRequired{Name: "admin trust anchor"}
	}
	if params.TenantID == "" {
		return nil, ErrDependencyRequired{Name: "tenant id"}
	}
	if params.AdminEmail == "" {
		return nil, ErrDependencyRequired{Name: "admin email"}
	}
	adminUsername := params.AdminUsername
	if adminUsername == "" {
		adminUsername = common.AdminUsername
	}
	svc := &Service{
		logger:              params.Logger,
		ceremony:            params.Ceremony,
		factors:             params.Factors,
		users:               params.Users,
		tokenIssuer:         params.TokenIssuer,
		trustAnchors:        params.TrustAnchors,
		tenantID:            params.TenantID,
		adminUsername:       adminUsername,
		adminEmail:          params.AdminEmail,
		challenges:          newSecretStore(challengeTTL),
		claims:              newSecretStore(claimTokenTTL),
		refuseMultiInstance: params.MultiInstance && params.Transactions == nil,
	}
	if params.Transactions != nil {
		svc.completion = newCompletionLock(params.Transactions, params.TenantID, adminUsername)
	}
	return svc, nil
}

// tenantContext scopes an SDK call to the platform's operating tenant. The
// SDK ceremony surfaces carry no tenant field — on the embedded transport
// the tenant rides the context, and an unscoped call fails closed.
func (s *Service) tenantContext(ctx context.Context) context.Context {
	return sdktransport.ContextWithTenant(ctx, s.tenantID)
}

// Claimed reports whether the admin identity CURRENTLY carries an
// operator-enrolled authenticator. It is deliberately a statement about
// live state, not history: revoking the last factor makes the node
// claimable again, which is how an operator recovers from a lost
// authenticator. See the package doc.
//
// It never guesses: an SDK failure is returned to the caller so the
// endpoint can fail closed rather than report an unclaimed node.
func (s *Service) Claimed(ctx context.Context) (bool, error) {
	history, err := s.factorHistory(ctx)
	if err != nil {
		return false, err
	}
	return history.claimed, nil
}

// claimHistory is what one SDK factor listing says about the admin
// identity's fido2 factors.
type claimHistory struct {
	// claimed is true while a non-revoked fido2 factor exists.
	claimed bool
	// known is false when the SDK answered without error but returned no
	// listing at all, which proves nothing about the identity's history.
	known bool
	// revoked holds the fido2 enrollments revoked before now: the
	// authenticators a claim completing over this history replaces.
	revoked []quicbaassdk.AuthFactorEntry
}

// factorHistory reads the admin identity's factors once through the SDK
// and classifies its fido2 enrollments.
func (s *Service) factorHistory(ctx context.Context) (claimHistory, error) {
	resp, err := s.factors.List(s.tenantContext(ctx), s.adminUsername)
	if err != nil {
		return claimHistory{}, err
	}
	if resp == nil {
		return claimHistory{}, nil
	}
	history := claimHistory{known: true}
	for _, e := range resp.Enrollments {
		if !strings.EqualFold(e.FactorName, factorFIDO2) {
			continue
		}
		if e.RevokedAt != nil {
			history.revoked = append(history.revoked, e)
			continue
		}
		history.claimed = true
	}
	return history, nil
}

// Challenge issues a possession nonce for the operator to sign.
func (s *Service) Challenge(ctx context.Context) (string, time.Time, error) {
	if s.refuseMultiInstance {
		return "", time.Time{}, ErrMultiInstanceUnsupported{}
	}
	if _, err := s.refuseIfClaimed(ctx); err != nil {
		return "", time.Time{}, err
	}
	return s.challenges.issue(s.adminUsername)
}

// ProveRequest carries an operator's proof of possession. Exactly one of
// the two proofs is used, decided by the transport, never by the caller:
// when the TLS handshake already presented a verified admin certificate
// that IS the proof; otherwise the signed challenge is required.
type ProveRequest struct {
	Challenge      string `json:"challenge"`
	CertificatePEM string `json:"certificate_pem"`
	Signature      []byte `json:"signature"`
}

// Prove validates an operator's possession of the firstboot admin
// credential and, on success, opens a single-use claim.
//
// peerCertificates is the verified client chain from the TLS handshake, if
// any. When it contains the admin certificate the handshake has already
// proved possession of the private key and no signature is needed. With no
// client certificate the request must carry the certificate and a
// signature over a challenge this server issued.
func (s *Service) Prove(
	ctx context.Context,
	req ProveRequest,
	peerCertificates []*x509.Certificate,
) (string, time.Time, error) {
	if s.refuseMultiInstance {
		return "", time.Time{}, ErrMultiInstanceUnsupported{}
	}

	if _, err := s.refuseIfClaimed(ctx); err != nil {
		return "", time.Time{}, err
	}
	if cert := s.adminPeerCertificate(peerCertificates); cert != nil {
		s.logger.Info("adminclaim: possession proved by mTLS handshake")
		return s.claims.issue(s.adminUsername)
	}

	if _, ok := s.challenges.redeem(req.Challenge); !ok {
		return "", time.Time{}, ErrChallengeUnknown{}
	}
	cert, err := parseCertificatePEM([]byte(req.CertificatePEM))
	if err != nil {
		return "", time.Time{}, err
	}
	if err := verifyAdminCertificate(cert, s.trustAnchors, s.adminUsername, s.tenantID); err != nil {
		return "", time.Time{}, err
	}
	// The signature covers the raw challenge string exactly as it was
	// issued, so the operator signs bytes they received rather than a
	// re-encoding either side could disagree on.
	if err := verifyChallengeSignature(cert, []byte(req.Challenge), req.Signature); err != nil {
		return "", time.Time{}, err
	}
	s.logger.Info("adminclaim: possession proved by signed challenge")
	return s.claims.issue(s.adminUsername)
}

// adminPeerCertificate returns the handshake's LEAF certificate when it is
// the system admin's, or nil otherwise.
//
// Only peers[0] is considered, and that restriction is the whole security
// property. `r.TLS.PeerCertificates` is the entire Certificate message the
// client sent — leaf first, then whatever chain it chose to attach — but
// TLS proves possession of the private key for the **leaf alone**, via
// CertificateVerify. A client holding any acceptable certificate could
// otherwise present its own as the leaf and attach a copy of the (public,
// freely readable) admin certificate behind it, and a scan of the whole
// list would hand it a claim token with no signature at all.
func (s *Service) adminPeerCertificate(peers []*x509.Certificate) *x509.Certificate {
	if len(peers) == 0 {
		return nil
	}
	leaf := peers[0]
	if err := verifyAdminCertificate(leaf, s.trustAnchors, s.adminUsername, s.tenantID); err != nil {
		return nil
	}
	return leaf
}

// BeginPasskey starts the WebAuthn registration ceremony for the admin
// identity. The claim token is checked but NOT spent — finish still needs
// it — so an abandoned begin leaves the claim usable until it expires.
func (s *Service) BeginPasskey(
	ctx context.Context, claimToken string) (*quicbaassdk.FIDO2BeginRegistrationResponse, error) {

	if s.refuseMultiInstance {
		return nil, ErrMultiInstanceUnsupported{}
	}
	if _, ok := s.claims.peek(claimToken); !ok {
		return nil, ErrClaimTokenInvalid{}
	}
	if _, err := s.refuseIfClaimed(ctx); err != nil {
		return nil, err
	}
	return s.ceremony.BeginRegistration(s.tenantContext(ctx),
		&quicbaassdk.FIDO2BeginRegistrationRequest{
			Email:       s.adminEmail,
			DisplayName: s.adminUsername,
		})
}

// FinishPasskey completes the ceremony, materialises the platform-local
// admin user with the admin role, and returns a console bearer. The claim
// token is spent here, whatever the outcome of the ceremony, so a failed
// attestation cannot be retried against the same proof.
func (s *Service) FinishPasskey(
	ctx context.Context,
	claimToken string,
	req *quicbaassdk.FIDO2FinishRegistrationRequest,
) (string, error) {

	// One completion at a time. "Is it claimed?" followed by "enrol this
	// authenticator" is a check-then-act, and the thing being protected is
	// a one-time ownership transfer: two callers holding different valid
	// claim tokens could otherwise both observe an unclaimed identity and
	// both enrol, letting a copied bootstrap key race the legitimate
	// operator and keep admin access. Serialising makes the second caller
	// observe the first's enrolment and get ErrAlreadyClaimed.
	//
	// The mutex is process-local. Across several platformd instances
	// sharing one store the store-wide completion lease does the same job
	// (#172): it is taken after the token is redeemed, so an unproved
	// caller never writes to the store, and before the factor history is
	// read, so only its holder can observe an unclaimed identity and
	// enrol. Without the lease such a deployment is refused outright.
	if s.refuseMultiInstance {
		return "", ErrMultiInstanceUnsupported{}
	}

	s.completing.Lock()
	defer s.completing.Unlock()

	if _, ok := s.claims.redeem(claimToken); !ok {
		return "", ErrClaimTokenInvalid{}
	}
	if s.completion != nil {
		release, err := s.completion.acquire(ctx)
		if err != nil {
			return "", err
		}
		defer func() {
			// Released whatever the outcome: the factor history, not the
			// lease, is what keeps a claimed identity closed. A release
			// that fails leaves the lease to expire.
			if err := release(context.WithoutCancel(ctx)); err != nil {
				s.logger.Warn("adminclaim: completion lease not released; it expires on its own",
					"error", err)
			}
		}()
		// The holder's work ends well inside the lease, so the lease is
		// never taken over while this instance can still enrol.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, completionDeadline)
		defer cancel()
	}
	// The listing that refuses a claimed identity is also the factor
	// history the audit record is decided by, read once and before the
	// enrolment adds the new passkey to it. A listing that fails refuses
	// the claim, so no claim completes without that decision made.
	history, err := s.refuseIfClaimed(ctx)
	if err != nil {
		return "", err
	}
	// Materialise the platform-local admin BEFORE the enrolment commits.
	// The SDK enrolment is the irreversible step: once the factor exists
	// the ceremony is closed forever, so anything that can fail must fail
	// before it, or the operator is stranded with a claimed identity and
	// no local record to sign in against. The record on its own grants
	// nothing — every login path demands a factor — so writing it early
	// is safe.
	user, err := s.materialiseAdmin(ctx)
	if err != nil {
		return "", err
	}
	credential, err := s.ceremony.FinishRegistration(s.tenantContext(ctx), req)
	if err != nil {
		return "", err
	}
	// Fail closed: an error-free response is not attestation. The SDK
	// reports its verdict on Success, and a nil response proves nothing.
	if credential == nil || !credential.Success {
		return "", ErrCeremonyRejected{}
	}
	s.recordClaim(ctx, history, credential.CredentialID)
	// A failure here costs the operator only this response: the passkey is
	// enrolled, so they sign in to the console with it as normal.
	return s.tokenIssuer.GenerateToken(user)
}

// reclaimDetails is the machine-readable body of a re-claim security
// record, carried as JSON in SecurityLogEntry.Details.
type reclaimDetails struct {
	Event        string           `json:"event"`
	Identity     string           `json:"identity"`
	Email        string           `json:"email"`
	TenantID     string           `json:"tenant_id"`
	ClaimedAt    string           `json:"claimed_at"`
	CredentialID string           `json:"credential_id"`
	Replaced     []replacedFactor `json:"replaced_factors"`
}

// replacedFactor names one revoked fido2 enrollment a re-claim replaces.
type replacedFactor struct {
	EnrollmentID string `json:"enrollment_id"`
	EnrolledAt   string `json:"enrolled_at"`
	RevokedAt    string `json:"revoked_at"`
}

// recordClaim writes the audit record of a completed claim. A first claim
// keeps its routine record. A claim completing over a revoked fido2
// factor is a re-claim and is raised as a high-severity security event of
// its own type, naming the factors it replaces; so is a claim whose
// factor history the SDK did not report, because a re-claim cannot be
// ruled out (detection over denial, per the #169 ruling).
func (s *Service) recordClaim(ctx context.Context, history claimHistory, credentialID string) {
	if history.known && len(history.revoked) == 0 {
		s.logger.Info("adminclaim: system admin claimed",
			"credential_id", credentialID,
			"tenant_id", s.tenantID)
		return
	}
	event := EventReclaim
	description := "system admin re-claimed: a new passkey was enrolled on an " +
		"identity whose previous FIDO2 factor was revoked"
	if !history.known {
		event = EventReclaimStatusUnknown
		description = "system admin claimed with unknown factor history: " +
			"the SDK returned no factor listing, so a re-claim cannot be ruled out"
	}
	claimedAt := time.Now().UTC()
	replaced := make([]replacedFactor, 0, len(history.revoked))
	for _, e := range history.revoked {
		replaced = append(replaced, replacedFactor{
			EnrollmentID: e.EnrollmentID,
			EnrolledAt:   e.EnrolledAt.UTC().Format(time.RFC3339Nano),
			RevokedAt:    e.RevokedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	details, err := json.Marshal(reclaimDetails{
		Event:        event,
		Identity:     s.adminUsername,
		Email:        s.adminEmail,
		TenantID:     s.tenantID,
		ClaimedAt:    claimedAt.Format(time.RFC3339Nano),
		CredentialID: credentialID,
		Replaced:     replaced,
	})
	if err != nil {
		// Unreachable for a struct of strings; still never drop the event.
		details = []byte(event)
	}
	s.logger.Security(ctx, logging.SecurityLogEntry{
		Timestamp:   claimedAt,
		Severity:    logging.SeverityHigh,
		Category:    logging.CategoryAccessControl,
		Description: description,
		Details:     string(details),
		Source:      logging.SourceAuthentication,
	})
}

// materialiseAdmin creates or updates the platform-local record for the
// system admin, carrying the admin role and the operating tenant.
//
// The platform user store is separate from the QuicBaaS IAM store: the
// console authenticates against platform-issued tokens, whose roles claim
// is derived from THIS record. Without it the claimed admin would sign in
// with no roles and every gated surface would refuse them.
func (s *Service) materialiseAdmin(ctx context.Context) (*entities.User, error) {
	userID := util.NewID([]byte(s.adminUsername))
	user, err := s.users.Get(ctx, userID)
	switch {
	case err != nil && !isNotFoundError(err):
		// A read that FAILED is not a read that found nothing. Treating
		// the two alike would let a transient store error replace an
		// existing admin record with a fresh minimal one — silently
		// dropping whatever it carried — in the middle of a
		// security-sensitive ceremony. Fail closed instead.
		return nil, err
	case err != nil || user == nil:
		user = entities.NewUser(s.adminUsername)
	}
	user.TenantID = s.tenantID
	user.DisplayName = s.adminUsername
	if !hasRole(user, common.ROLE_ADMIN) {
		user.AddRole(entities.NewRole(common.ROLE_ADMIN))
	}
	user.UpdatedAt = time.Now().UTC()
	if err := s.users.Save(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

func hasRole(user *entities.User, name string) bool {
	for _, role := range user.Roles {
		if role != nil && role.Name == name {
			return true
		}
	}
	return false
}

// refuseIfClaimed closes every step of the flow while an authenticator is
// enrolled. It fails closed on an SDK error: unable to tell, unable to
// claim. On success it returns the factor history it read, which
// FinishPasskey uses to decide the claim's audit record.
func (s *Service) refuseIfClaimed(ctx context.Context) (claimHistory, error) {
	history, err := s.factorHistory(ctx)
	if err != nil {
		return claimHistory{}, err
	}
	if history.claimed {
		return claimHistory{}, ErrAlreadyClaimed{}
	}
	return history, nil
}

// PeerCertificates extracts the client chain a request presented in the
// TLS handshake, or nil when it presented none.
//
// The slice is the whole Certificate message: the leaf first, then
// whatever chain the client chose to attach. Only the LEAF is proved —
// Go's TLS server validates CertificateVerify against it — which is why
// adminPeerCertificate looks at peers[0] and nothing else. Chain and
// identity are then checked independently against this deployment's own
// admin trust anchor, so a certificate the TLS stack happened to accept
// for some other reason grants nothing.
func PeerCertificates(r *http.Request) []*x509.Certificate {
	if r == nil || r.TLS == nil {
		return nil
	}
	return r.TLS.PeerCertificates
}

// isNotFoundError reports whether err means "no such record", as opposed
// to "the read failed". The platform user store surfaces absence through
// several error types depending on which backend is wired, so the check
// mirrors the one the WebAuthn handler uses against the same store.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, datastore.ErrRecordNotFound) {
		return true
	}
	var kvNotFound kvstore.ErrNotFound
	if errors.As(err, &kvNotFound) {
		return true
	}
	var kvNotFoundByIndex kvstore.ErrNotFoundByIndex
	if errors.As(err, &kvNotFoundByIndex) {
		return true
	}
	var storeNotFound quicbaasstore.ErrNotFound
	return errors.As(err, &storeNotFound)
}
