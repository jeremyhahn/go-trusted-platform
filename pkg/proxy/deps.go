package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
)

// AuthDecision is the result of an AuthChain evaluation for one request.
type AuthDecision struct {
	Allowed  bool
	Reason   string
	Identity *ClientIdentity
}

// ClientIdentity describes the authenticated caller as established by the
// auth chain.
type ClientIdentity struct {
	ID              string
	DeviceID        string
	Zone            string
	AuthMethod      string
	CertFingerprint string
	Attested        bool
	Roles           []string

	// subjectDN and uriSAN carry certificate detail for the
	// X-Forwarded-Client-Cert header. They are unexported so only the
	// in-package auth chain, which validated the certificate, can set them;
	// external AuthChain implementations produce an XFCC without Subject/URI
	// elements.
	subjectDN string
	uriSAN    string
}

// AuthChain authenticates a request against a route's auth requirements.
// Phase 2 supplies the trusted-computing implementation; the engine treats a
// returned error as a fail-closed deny.
type AuthChain interface {
	Authenticate(ctx context.Context, r *http.Request, route *CompiledRoute) (*AuthDecision, error)
}

// ChainCapabilities declares which auth mechanisms an AuthChain can enforce.
// New and Reload reject configurations whose routes demand a capability the
// injected chain does not report, so misconfiguration is impossible rather
// than runtime-denied.
type ChainCapabilities struct {
	// MTLS reports mutual-TLS client authentication support.
	MTLS bool
	// Token reports bearer-token validation support (a TokenAuthenticator
	// is configured on the chain).
	Token bool
	// Attestation reports attestation-freshness gating support (an
	// AttestationGate is configured on the chain).
	Attestation bool
	// OPA reports OPA policy evaluation support (a PolicyEvaluator is
	// configured on the chain).
	OPA bool
	// Zones reports zone extraction plus zone-matrix enforcement support.
	Zones bool
}

// CapabilityReporter is implemented by auth chains that can report their
// capabilities. Chains that do not implement it are assumed fully capable;
// the injector vouches for them.
type CapabilityReporter interface {
	Capabilities() ChainCapabilities
}

// chainCapabilities resolves the capabilities of an injected chain, assuming
// full capability for chains that do not report.
func chainCapabilities(a AuthChain) ChainCapabilities {
	if r, ok := a.(CapabilityReporter); ok {
		return r.Capabilities()
	}
	return ChainCapabilities{MTLS: true, Token: true, Attestation: true, OPA: true, Zones: true}
}

// TrustResolver resolves a client TLS configuration for a backend trust
// class. Phase 2 adapts the platform trust resolver behind this interface.
type TrustResolver interface {
	ClientTLSConfig(ctx context.Context, trustClass, endpoint string) (*tls.Config, error)
}

// AuditSink receives one audit event per routing/authentication decision.
type AuditSink interface {
	Record(ctx context.Context, ev AuditEvent)
}

// Deps carries the injected collaborators for an Engine. Auth is required
// whenever any route is non-public; Trust is required whenever any pool sets
// a TLS trust class; ServerTLS is required whenever any route is non-public.
// A nil Audit is replaced with a no-op sink and a nil Logger with
// slog.Default().
type Deps struct {
	Auth      AuthChain
	Trust     TrustResolver
	Audit     AuditSink
	ServerTLS *tls.Config
	Logger    *slog.Logger
}

// withDefaults fills the optional collaborators that have safe defaults.
func (d Deps) withDefaults() Deps {
	if d.Audit == nil {
		d.Audit = noopSink{}
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return d
}

// checkFailClosed enforces the fail-closed composition rules of New and
// Reload against an already validated configuration.
func checkFailClosed(cfg *Config, deps Deps) error {
	needsAuth := false
	for i := range cfg.Routes {
		if cfg.Routes[i].Auth.Mode != AuthModePublic {
			needsAuth = true
			break
		}
	}
	if needsAuth && deps.Auth == nil {
		return ErrAuthChainRequired
	}
	if needsAuth && deps.ServerTLS == nil {
		return ErrTLSRequiredForAuth
	}
	if needsAuth {
		if err := checkRouteCapabilities(cfg, deps); err != nil {
			return err
		}
	}
	for i := range cfg.Pools {
		if cfg.Pools[i].TLS.TrustClass != "" && deps.Trust == nil {
			return ErrTrustResolverRequired
		}
	}
	return nil
}

// checkRouteCapabilities rejects routes whose effective (defaults-merged)
// auth requirements demand a capability the injected chain does not report.
// All errors wrap typed sentinels in a route ConfigError.
func checkRouteCapabilities(cfg *Config, deps Deps) error {
	caps := chainCapabilities(deps.Auth)
	for i := range cfg.Routes {
		rc := &cfg.Routes[i]
		if rc.Auth.Mode == AuthModePublic {
			continue
		}
		a := rc.Auth
		mergeAuthDefaults(&a, cfg.Defaults)
		wantsMTLS := a.Mode == AuthModeMTLS || a.Mode == AuthModeMTLSOrToken
		wantsToken := a.Mode == AuthModeToken || a.Mode == AuthModeMTLSOrToken
		switch {
		case wantsMTLS && !caps.MTLS:
			return &ConfigError{Kind: "route", ID: rc.ID, Err: ErrMTLSAuthNotConfigured}
		case wantsToken && !caps.Token:
			return &ConfigError{Kind: "route", ID: rc.ID, Err: ErrTokenAuthNotConfigured}
		case a.RequireAttestation && !caps.Attestation:
			return &ConfigError{Kind: "route", ID: rc.ID, Err: ErrAttestationGateNotConfigured}
		case a.OPAPolicy != "" && !caps.OPA:
			return &ConfigError{Kind: "route", ID: rc.ID, Err: ErrOPANotConfigured}
		case (len(a.AllowedZones) > 0 || a.BackendZone != "") && !caps.Zones:
			return &ConfigError{Kind: "route", ID: rc.ID, Err: ErrZoneEnforcementNotConfigured}
		}
	}
	return nil
}
