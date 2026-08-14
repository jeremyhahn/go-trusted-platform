package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Stable machine-readable deny reasons set on AuthDecision.Reason. Audit
// consumers and tests match these exactly; log detail stays server-side.
const (
	// ReasonTokenAuthNotConfigured denies token-mode requests on a chain
	// without a configured TokenAuthenticator (defense in depth: the engine
	// already rejects such configurations at construction time).
	ReasonTokenAuthNotConfigured = "token_auth_not_configured"
	// ReasonClientCertRequired denies mTLS requests without a peer
	// certificate.
	ReasonClientCertRequired = "client_cert_required"
	// ReasonMTLSAuthFailed denies requests whose client certificate failed
	// adapter authentication (chain, validity, revocation).
	ReasonMTLSAuthFailed = "mtls_authentication_failed"
	// ReasonIDevIDRequired denies requests whose certificate is not a valid
	// TCG IDevID on routes that require one.
	ReasonIDevIDRequired = "idevid_required"
	// ReasonZoneMissing denies requests whose certificate carries no
	// readable network zone on routes that enforce zones.
	ReasonZoneMissing = "zone_missing"
	// ReasonZoneNotAllowed denies requests whose client zone is not in the
	// route's AllowedZones set.
	ReasonZoneNotAllowed = "zone_not_allowed"
	// ReasonZoneMatrixDenied denies requests whose client zone has no
	// allowed path to the route's BackendZone in the zone matrix.
	ReasonZoneMatrixDenied = "zone_matrix_denied"
	// ReasonRoleRequired denies requests whose identity lacks a required
	// role.
	ReasonRoleRequired = "role_required"
	// ReasonTokenMissing denies token-path requests without a Bearer
	// Authorization header.
	ReasonTokenMissing = "token_missing"
	// ReasonTokenInvalid denies token-path requests whose token failed
	// validation (signature, issuer, audience, expiry, DPoP binding, or
	// liveness).
	ReasonTokenInvalid = "token_invalid"
	// ReasonTokenScopeDenied denies token-path requests whose validated
	// token lacks a required scope.
	ReasonTokenScopeDenied = "token_scope_denied"
	// ReasonZoneRequiresMTLS denies token principals on zone-enforcing
	// routes that assign no Auth.TokenZone: without a certificate zone or an
	// operator-assigned token zone, zone policy cannot be evaluated.
	ReasonZoneRequiresMTLS = "zone_requires_mtls"
	// ReasonAttestationStale denies requests whose device attestation is a
	// definitive fail: no manifest, manifest older than the accepted age, or
	// verification rejected by platformd.
	ReasonAttestationStale = "attestation_stale"
	// ReasonAttestationUnavailable denies requests whose attestation state
	// could not be established (no device identity, or the attestation
	// backend is unreachable). Fail closed.
	ReasonAttestationUnavailable = "attestation_unavailable"
	// ReasonOPADenied denies requests the route's OPA policy did not allow.
	ReasonOPADenied = "opa_denied"
	// ReasonOPAError denies requests whose OPA policy evaluation failed.
	ReasonOPAError = "opa_error"
)

// authMethodMTLS is the AuthMethod recorded for mutual-TLS identities.
const authMethodMTLS = "mtls"

// MTLSAuthenticator validates a client certificate and extracts its
// identity. It is the seam to *auth.MTLSAdapter (pkg/auth), accepted as an
// interface so the chain composes against behavior, not the adapter's CA
// dependency graph.
type MTLSAuthenticator interface {
	Authenticate(ctx context.Context, clientCert *x509.Certificate) (*auth.Identity, error)
}

// Compile-time proof that the production adapter satisfies the seam.
var _ MTLSAuthenticator = (*auth.MTLSAdapter)(nil)

// ZoneExtractor extracts the platform network zone from a client
// certificate.
type ZoneExtractor interface {
	ExtractZone(cert *x509.Certificate) (string, error)
}

// MatrixProvider returns the current inter-zone allow matrix. It is a
// function so callers (e.g. gatewayd) can hot-swap the matrix on zone
// configuration reload without rebuilding the chain.
type MatrixProvider func() zone.Matrix

// AuthChainConfig configures NewAuthChain. MTLS is required; ZoneExtractor
// and Matrix must be provided together to enable the zone capability. Token,
// Attestation, and Policy are optional collaborators: each one that is set
// enables the matching chain capability, and the engine's fail-closed
// composition checks reject any route configuration that demands a
// capability the chain does not report.
type AuthChainConfig struct {
	MTLS          MTLSAuthenticator
	ZoneExtractor ZoneExtractor
	Matrix        MatrixProvider
	Logger        *slog.Logger

	// Token enables the bearer-token path for token and mtls-or-token
	// routes.
	Token TokenAuthenticator

	// Attestation enables attestation-freshness gating for routes that set
	// RequireAttestation.
	Attestation AttestationGate

	// Policy enables per-route OPA policy evaluation for routes that set
	// OPAPolicy.
	Policy PolicyEvaluator
}

// Chain is the production AuthChain for the mutual-TLS path. Every check is
// fail-closed: any missing or invalid credential produces a deny decision
// with a stable machine-readable reason, never an implicit allow.
type Chain struct {
	mtls        MTLSAuthenticator
	zones       ZoneExtractor
	matrix      MatrixProvider
	logger      *slog.Logger
	token       TokenAuthenticator
	attestation AttestationGate
	policy      PolicyEvaluator
}

// NewAuthChain builds the production auth chain. It returns
// ErrMTLSAuthenticatorRequired without an mTLS authenticator and
// ErrZoneConfigIncomplete when only one of ZoneExtractor and Matrix is set.
func NewAuthChain(cfg AuthChainConfig) (*Chain, error) {
	if cfg.MTLS == nil {
		return nil, ErrMTLSAuthenticatorRequired
	}
	if (cfg.ZoneExtractor == nil) != (cfg.Matrix == nil) {
		return nil, ErrZoneConfigIncomplete
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Chain{
		mtls:        cfg.MTLS,
		zones:       cfg.ZoneExtractor,
		matrix:      cfg.Matrix,
		logger:      logger,
		token:       cfg.Token,
		attestation: cfg.Attestation,
		policy:      cfg.Policy,
	}, nil
}

// Capabilities implements CapabilityReporter. Token, attestation, and OPA
// capabilities are enabled by their optional collaborators; the engine
// rejects configurations that demand an absent capability at construction
// time.
func (c *Chain) Capabilities() ChainCapabilities {
	return ChainCapabilities{
		MTLS:        true,
		Zones:       c.zones != nil && c.matrix != nil,
		Token:       c.token != nil,
		Attestation: c.attestation != nil,
		OPA:         c.policy != nil,
	}
}

// Authenticate implements AuthChain. It evaluates the route's auth
// requirements against the request's TLS state and returns a deny decision
// with a stable reason on the first failing check. Errors are reserved for
// programming mistakes (nil request or route).
//
// Credential selection: mtls routes require a certificate, token routes
// require a bearer token, and mtls-or-token routes take the mutual-TLS path
// whenever a client certificate is present — mTLS is the stronger,
// hardware-anchored credential, so when BOTH credentials arrive the
// certificate wins and the bearer token is ignored (and never forwarded).
// After either path establishes an identity, the shared trusted-computing
// gates run in order: attestation freshness, then OPA policy (which sees the
// attestation outcome in its input).
func (c *Chain) Authenticate(ctx context.Context, r *http.Request, route *CompiledRoute) (*AuthDecision, error) {
	if r == nil {
		return nil, ErrNilRequest
	}
	if route == nil {
		return nil, ErrNilRoute
	}
	req := route.cfg.Auth
	// The engine never calls the chain for public routes; allow defensively.
	if req.Mode == AuthModePublic {
		return &AuthDecision{Allowed: true}, nil
	}
	hasCert := r.TLS != nil && len(r.TLS.PeerCertificates) > 0

	var (
		identity *ClientIdentity
		decision *AuthDecision
		// attestSubject is the attestation-store host identifier: the leaf
		// certificate CN for mTLS callers (manifests are keyed by the IDevID
		// CN), empty for token principals.
		attestSubject string
	)
	if req.Mode == AuthModeMTLS || (req.Mode == AuthModeMTLSOrToken && hasCert) {
		if !hasCert {
			return deny(ReasonClientCertRequired), nil
		}
		leaf := r.TLS.PeerCertificates[0]
		identity, decision = c.authenticateMTLS(ctx, leaf, route, &req)
		if decision != nil {
			return decision, nil
		}
		attestSubject = leaf.Subject.CommonName
	} else {
		identity, decision = c.authenticateToken(ctx, r, route)
		if decision != nil {
			return decision, nil
		}
	}

	if d := c.checkAttestation(ctx, attestSubject, route.cfg.ID, &req, identity); d != nil {
		return d, nil
	}
	if d := c.checkPolicy(ctx, r, route, identity); d != nil {
		return d, nil
	}
	return &AuthDecision{Allowed: true, Identity: identity}, nil
}

// authenticateMTLS runs the mutual-TLS path: adapter authentication, IDevID
// validation, zone enforcement, and role checks. It returns the
// authenticated identity or a deny decision; exactly one is non-nil.
func (c *Chain) authenticateMTLS(ctx context.Context, leaf *x509.Certificate, route *CompiledRoute, req *AuthRequirements) (*ClientIdentity, *AuthDecision) {
	ident, err := c.mtls.Authenticate(ctx, leaf)
	if err != nil {
		c.logger.Warn("proxy: mtls authentication failed",
			"route", route.cfg.ID, "subject", leaf.Subject.String(), "error", err)
		return nil, deny(ReasonMTLSAuthFailed)
	}

	if req.RequireIDevID {
		if err := auth.ValidateIDevID(ctx, leaf); err != nil {
			c.logger.Warn("proxy: idevid validation failed",
				"route", route.cfg.ID, "subject", leaf.Subject.String(), "error", err)
			return nil, deny(ReasonIDevIDRequired)
		}
	}

	clientZone, decision := c.checkZone(leaf, req, route.cfg.ID)
	if decision != nil {
		return nil, decision
	}

	roles := rolesFromIdentity(ident)
	if !hasAllRoles(roles, req.RequiredRoles) {
		return nil, deny(ReasonRoleRequired)
	}

	return &ClientIdentity{
		ID:              ident.ID,
		DeviceID:        ident.SerialNumber,
		Zone:            clientZone,
		AuthMethod:      authMethodMTLS,
		CertFingerprint: fingerprintHex(leaf),
		Roles:           roles,
		subjectDN:       leaf.Subject.String(),
		uriSAN:          firstURISAN(leaf),
	}, nil
}

// checkZone extracts the client zone and enforces AllowedZones and the
// BackendZone matrix when the route demands them. When the route has no zone
// requirements the zone is extracted best-effort for identity enrichment
// only. A non-nil decision is a deny.
func (c *Chain) checkZone(leaf *x509.Certificate, req *AuthRequirements, routeID string) (string, *AuthDecision) {
	required := len(req.AllowedZones) > 0 || req.BackendZone != ""
	if c.zones == nil {
		// The engine rejects zone-requiring routes on a chain without the
		// zone capability at construction; deny defensively regardless.
		if required {
			return "", deny(ReasonZoneMissing)
		}
		return "", nil
	}
	clientZone, err := c.zones.ExtractZone(leaf)
	if err != nil || clientZone == "" {
		if !required {
			if err != nil {
				c.logger.Debug("proxy: zone extraction failed on zone-free route",
					"route", routeID, "error", err)
			}
			return "", nil
		}
		if err != nil {
			c.logger.Warn("proxy: zone extraction failed",
				"route", routeID, "subject", leaf.Subject.String(), "error", err)
		}
		return "", deny(ReasonZoneMissing)
	}
	if len(req.AllowedZones) > 0 && !containsString(req.AllowedZones, clientZone) {
		return "", deny(ReasonZoneNotAllowed)
	}
	if req.BackendZone != "" {
		verdict := c.matrix().Allowed(zone.Zone(clientZone), zone.Zone(req.BackendZone))
		if !verdict.Allowed {
			return "", deny(ReasonZoneMatrixDenied)
		}
	}
	return clientZone, nil
}

// deny builds a fail-closed deny decision with a stable reason.
func deny(reason string) *AuthDecision {
	return &AuthDecision{Allowed: false, Reason: reason}
}

// rolesFromIdentity maps the mTLS adapter identity onto proxy roles. The
// "roles" attribute, when present, is a comma-separated role list; absent
// that, the "organizational_unit" attribute (certificate OU, the
// conventional role carrier for certificate-based RBAC) is a single role.
func rolesFromIdentity(ident *auth.Identity) []string {
	if ident == nil || ident.Attributes == nil {
		return nil
	}
	if raw, ok := ident.Attributes["roles"]; ok && raw != "" {
		parts := strings.Split(raw, ",")
		roles := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				roles = append(roles, p)
			}
		}
		return roles
	}
	if ou, ok := ident.Attributes["organizational_unit"]; ok && ou != "" {
		return []string{ou}
	}
	return nil
}

// hasAllRoles reports whether every required role is held.
func hasAllRoles(held, required []string) bool {
	for _, want := range required {
		if !containsString(held, want) {
			return false
		}
	}
	return true
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// fingerprintHex returns the lowercase SHA-256 hex fingerprint of the raw
// certificate.
func fingerprintHex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// firstURISAN returns the first URI SAN of the certificate, or empty.
func firstURISAN(cert *x509.Certificate) string {
	if len(cert.URIs) == 0 {
		return ""
	}
	return cert.URIs[0].String()
}

// PolicyZoneExtractor extracts the platform network zone from the canonical
// OIDTPNetworkZone X.509 extension (1.3.6.1.4.1.29377.101.21) using the same
// quicbaas SDK parser pkg/sdn/policy.X509PolicyExtractor.ExtractZone uses.
// It deliberately does not adapt X509PolicyExtractor itself: importing
// pkg/sdn/policy drags the full SDN runtime (OVS, device DAO, datastore)
// into the proxy, while the canonical parse both packages share lives
// upstream in the quicbaas SDK re-export.
type PolicyZoneExtractor struct{}

// NewPolicyZoneExtractor returns the production ZoneExtractor.
func NewPolicyZoneExtractor() *PolicyZoneExtractor {
	return &PolicyZoneExtractor{}
}

// ExtractZone implements ZoneExtractor. It returns ErrNilLeafCertificate for
// a nil certificate and ErrZoneExtensionMissing when the certificate carries
// no OIDTPNetworkZone extension.
func (PolicyZoneExtractor) ExtractZone(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", ErrNilLeafCertificate
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(quicbaasca.OIDTPNetworkZone) {
			return quicbaasca.ParseNetworkZoneExtension(ext)
		}
	}
	return "", ErrZoneExtensionMissing
}

var (
	_ AuthChain          = (*Chain)(nil)
	_ CapabilityReporter = (*Chain)(nil)
	_ ZoneExtractor      = (*PolicyZoneExtractor)(nil)
)
