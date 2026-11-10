package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeTokenAuth is a configurable TokenAuthenticator that records the last
// request it received.
type fakeTokenAuth struct {
	principal *TokenPrincipal
	err       error

	mu      sync.Mutex
	lastReq *TokenAuthRequest
	calls   int
}

func (f *fakeTokenAuth) Authorize(ctx context.Context, req *TokenAuthRequest) (*TokenPrincipal, error) {
	f.mu.Lock()
	f.lastReq = req
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.principal, nil
}

func (f *fakeTokenAuth) last() *TokenAuthRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func (f *fakeTokenAuth) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeGate is a configurable AttestationGate that records the last query.
type fakeGate struct {
	err error

	mu         sync.Mutex
	lastDevice string
	lastMaxAge time.Duration
	calls      int
}

func (f *fakeGate) Fresh(ctx context.Context, deviceID string, maxAge time.Duration) error {
	f.mu.Lock()
	f.lastDevice = deviceID
	f.lastMaxAge = maxAge
	f.calls++
	f.mu.Unlock()
	return f.err
}

// fakeEvaluator is a configurable PolicyEvaluator that records its input.
type fakeEvaluator struct {
	allowed    bool
	violations []string
	err        error

	mu         sync.Mutex
	lastPolicy string
	lastInput  map[string]any
}

func (f *fakeEvaluator) Evaluate(ctx context.Context, policy string, input map[string]any) (bool, []string, error) {
	f.mu.Lock()
	f.lastPolicy = policy
	f.lastInput = input
	f.mu.Unlock()
	if f.err != nil {
		return false, nil, f.err
	}
	return f.allowed, f.violations, nil
}

// phase3Chain builds a zone-capable chain with the given optional
// collaborators.
func phase3Chain(t *testing.T, token TokenAuthenticator, gate AttestationGate, policy PolicyEvaluator) *Chain {
	t.Helper()
	c, err := NewAuthChain(AuthChainConfig{
		MTLS:          &fakeMTLSAuth{},
		ZoneExtractor: NewPolicyZoneExtractor(),
		Matrix:        testMatrix,
		Logger:        testLogger(),
		Token:         token,
		Attestation:   gate,
		Policy:        policy,
	})
	if err != nil {
		t.Fatalf("NewAuthChain: %v", err)
	}
	return c
}

// tokenRequest builds a TLS request carrying a bearer token and optional
// DPoP proof.
func tokenRequest(token, dpop string) *http.Request {
	r := tlsRequest(nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if dpop != "" {
		r.Header.Set("DPoP", dpop)
	}
	return r
}

func TestChainTokenPathAllow(t *testing.T) {
	authn := &fakeTokenAuth{principal: &TokenPrincipal{
		Subject:  "svc-1",
		TenantID: "default",
		Scopes:   []string{"proxy:read"},
		Roles:    []string{"reader"},
	}}
	c := phase3Chain(t, authn, nil, nil)
	r := tokenRequest("tok-abc", "proof-xyz")
	route := chainRoute(AuthRequirements{
		Mode:           AuthModeToken,
		RequiredScopes: []string{"proxy:read", "proxy:list"},
	})

	d, err := c.Authenticate(context.Background(), r, route)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed {
		t.Fatalf("decision = %+v, want allow", d)
	}
	id := d.Identity
	if id.ID != "svc-1" || id.AuthMethod != "token" || id.DeviceID != "" || id.Attested {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Roles) != 1 || id.Roles[0] != "reader" {
		t.Errorf("roles = %v, want [reader]", id.Roles)
	}

	req := authn.last()
	if req.Token != "tok-abc" {
		t.Errorf("token = %q", req.Token)
	}
	if req.DPoPProof != "proof-xyz" {
		t.Errorf("dpop = %q", req.DPoPProof)
	}
	if req.HTM != http.MethodGet {
		t.Errorf("htm = %q", req.HTM)
	}
	if req.HTU != "https://svc.example.com/api" {
		t.Errorf("htu = %q", req.HTU)
	}
	if len(req.RequiredScopes) != 2 || req.RequiredScopes[0] != "proxy:read" {
		t.Errorf("scopes = %v", req.RequiredScopes)
	}
}

func TestChainTokenPathDenyReasons(t *testing.T) {
	tests := []struct {
		name   string
		chain  *Chain
		req    *http.Request
		auth   AuthRequirements
		reason string
	}{
		{
			"authenticator not configured",
			newTestChain(t, &fakeMTLSAuth{}),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken},
			ReasonTokenAuthNotConfigured,
		},
		{
			"missing bearer",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			tokenRequest("", ""),
			AuthRequirements{Mode: AuthModeToken},
			ReasonTokenMissing,
		},
		{
			"non-bearer scheme",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			func() *http.Request {
				r := tlsRequest(nil)
				r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
				return r
			}(),
			AuthRequirements{Mode: AuthModeToken},
			ReasonTokenMissing,
		},
		{
			"invalid token",
			phase3Chain(t, &fakeTokenAuth{err: errors.New("bad signature")}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken},
			ReasonTokenInvalid,
		},
		{
			"scope denied",
			phase3Chain(t, &fakeTokenAuth{err: fmt.Errorf("adapter: %w", ErrTokenScopeDenied)}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken, RequiredScopes: []string{"proxy:admin"}},
			ReasonTokenScopeDenied,
		},
		{
			"idevid on token path",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeMTLSOrToken, RequireIDevID: true},
			ReasonIDevIDRequired,
		},
		{
			"zone requires mtls",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken, AllowedZones: []string{"control-plane"}},
			ReasonZoneRequiresMTLS,
		},
		{
			"token zone not allowed",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken, AllowedZones: []string{"control-plane"}, TokenZone: "public"},
			ReasonZoneNotAllowed,
		},
		{
			"token zone matrix denied",
			phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "s"}}, nil, nil),
			tokenRequest("tok", ""),
			AuthRequirements{Mode: AuthModeToken, BackendZone: "internal", TokenZone: "public"},
			ReasonZoneMatrixDenied,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := tc.chain.Authenticate(context.Background(), tc.req, chainRoute(tc.auth))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if d.Allowed || d.Reason != tc.reason {
				t.Errorf("decision = %+v, want deny %q", d, tc.reason)
			}
		})
	}
}

func TestChainTokenZoneAllowed(t *testing.T) {
	tests := []struct {
		name string
		auth AuthRequirements
		zone string
	}{
		{
			"matrix allowed",
			AuthRequirements{Mode: AuthModeToken, AllowedZones: []string{"control-plane"}, BackendZone: "internal", TokenZone: "control-plane"},
			"control-plane",
		},
		{
			"enrichment on zone-free route",
			AuthRequirements{Mode: AuthModeToken, TokenZone: "edge"},
			"edge",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := phase3Chain(t, &fakeTokenAuth{principal: &TokenPrincipal{Subject: "svc"}}, nil, nil)
			d, err := c.Authenticate(context.Background(), tokenRequest("tok", ""), chainRoute(tc.auth))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if !d.Allowed || d.Identity.Zone != tc.zone {
				t.Fatalf("decision = %+v, want allow with zone %s", d, tc.zone)
			}
		})
	}
}

func TestChainMTLSWinsWhenBothCredentialsPresent(t *testing.T) {
	authn := &fakeTokenAuth{principal: &TokenPrincipal{Subject: "token-svc"}}
	c := phase3Chain(t, authn, nil, nil)
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "device-1"})
	r := tlsRequest(leaf)
	r.Header.Set("Authorization", "Bearer tok")

	d, err := c.Authenticate(context.Background(), r, chainRoute(AuthRequirements{Mode: AuthModeMTLSOrToken}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed || d.Identity.AuthMethod != authMethodMTLS || d.Identity.ID != "device-1" {
		t.Fatalf("decision = %+v, want mtls identity device-1", d)
	}
	if authn.callCount() != 0 {
		t.Error("token authenticator must not be consulted when a certificate is present")
	}
}

func TestChainMTLSOrTokenFallsBackToToken(t *testing.T) {
	authn := &fakeTokenAuth{principal: &TokenPrincipal{Subject: "token-svc"}}
	c := phase3Chain(t, authn, nil, nil)
	d, err := c.Authenticate(context.Background(), tokenRequest("tok", ""), chainRoute(AuthRequirements{Mode: AuthModeMTLSOrToken}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Allowed || d.Identity.AuthMethod != authMethodToken {
		t.Fatalf("decision = %+v, want token identity", d)
	}
}

func TestChainAttestationGate(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "node-02"})

	t.Run("fresh marks identity attested", func(t *testing.T) {
		gate := &fakeGate{}
		c := phase3Chain(t, nil, gate, nil)
		route := chainRoute(AuthRequirements{
			Mode:               AuthModeMTLS,
			RequireAttestation: true,
			AttestationMaxAge:  10 * time.Minute,
		})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !d.Allowed || !d.Identity.Attested {
			t.Fatalf("decision = %+v, want allow with Attested", d)
		}
		if gate.lastDevice != "node-02" {
			t.Errorf("gate device = %q, want leaf CN node-02", gate.lastDevice)
		}
		if gate.lastMaxAge != 10*time.Minute {
			t.Errorf("gate maxAge = %v", gate.lastMaxAge)
		}
	})

	t.Run("default max age applied", func(t *testing.T) {
		gate := &fakeGate{}
		c := phase3Chain(t, nil, gate, nil)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true})
		if _, err := c.Authenticate(context.Background(), tlsRequest(leaf), route); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if gate.lastMaxAge != DefaultAttestationMaxAge {
			t.Errorf("gate maxAge = %v, want %v", gate.lastMaxAge, DefaultAttestationMaxAge)
		}
	})

	t.Run("stale verdict", func(t *testing.T) {
		gate := &fakeGate{err: fmt.Errorf("gate: %w", ErrAttestationStale)}
		c := phase3Chain(t, nil, gate, nil)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonAttestationStale {
			t.Errorf("decision = %+v, want %q", d, ReasonAttestationStale)
		}
	})

	t.Run("indeterminate error", func(t *testing.T) {
		gate := &fakeGate{err: errors.New("platformd unreachable")}
		c := phase3Chain(t, nil, gate, nil)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonAttestationUnavailable {
			t.Errorf("decision = %+v, want %q", d, ReasonAttestationUnavailable)
		}
	})

	t.Run("no gate configured denies defensively", func(t *testing.T) {
		c := newTestChain(t, &fakeMTLSAuth{})
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonAttestationUnavailable {
			t.Errorf("decision = %+v, want %q", d, ReasonAttestationUnavailable)
		}
	})

	t.Run("token principal has no device identity", func(t *testing.T) {
		gate := &fakeGate{}
		authn := &fakeTokenAuth{principal: &TokenPrincipal{Subject: "svc"}}
		c := phase3Chain(t, authn, gate, nil)
		route := chainRoute(AuthRequirements{Mode: AuthModeToken, RequireAttestation: true})
		d, err := c.Authenticate(context.Background(), tokenRequest("tok", ""), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonAttestationUnavailable {
			t.Errorf("decision = %+v, want %q", d, ReasonAttestationUnavailable)
		}
		if gate.calls != 0 {
			t.Error("gate must not be queried without a device identity")
		}
	})

	t.Run("empty leaf cn denies unavailable", func(t *testing.T) {
		gate := &fakeGate{}
		c := phase3Chain(t, nil, gate, nil)
		anon := newLeafCert(t, ca, leafSpec{cn: ""})
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, RequireAttestation: true})
		d, err := c.Authenticate(context.Background(), tlsRequest(anon), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonAttestationUnavailable {
			t.Errorf("decision = %+v, want %q", d, ReasonAttestationUnavailable)
		}
		if gate.calls != 0 {
			t.Error("gate must not be queried with an empty CN")
		}
	})
}

func TestChainOPAPolicy(t *testing.T) {
	ca := newTestCA(t)
	leaf := newLeafCert(t, ca, leafSpec{cn: "device-9", zone: "control-plane"})

	t.Run("allow", func(t *testing.T) {
		eval := &fakeEvaluator{allowed: true}
		c := phase3Chain(t, nil, nil, eval)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, OPAPolicy: "proxy_authz"})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !d.Allowed {
			t.Fatalf("decision = %+v, want allow", d)
		}
		if eval.lastPolicy != "proxy_authz" {
			t.Errorf("policy = %q", eval.lastPolicy)
		}
	})

	t.Run("deny with violations", func(t *testing.T) {
		eval := &fakeEvaluator{allowed: false, violations: []string{"client zone is quarantined"}}
		c := phase3Chain(t, nil, nil, eval)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, OPAPolicy: "proxy_authz"})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonOPADenied {
			t.Errorf("decision = %+v, want %q", d, ReasonOPADenied)
		}
	})

	t.Run("evaluation error", func(t *testing.T) {
		eval := &fakeEvaluator{err: errors.New("policy not found")}
		c := phase3Chain(t, nil, nil, eval)
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, OPAPolicy: "proxy_authz"})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonOPAError {
			t.Errorf("decision = %+v, want %q", d, ReasonOPAError)
		}
	})

	t.Run("no evaluator denies defensively", func(t *testing.T) {
		c := newTestChain(t, &fakeMTLSAuth{})
		route := chainRoute(AuthRequirements{Mode: AuthModeMTLS, OPAPolicy: "proxy_authz"})
		d, err := c.Authenticate(context.Background(), tlsRequest(leaf), route)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if d.Allowed || d.Reason != ReasonOPAError {
			t.Errorf("decision = %+v, want %q", d, ReasonOPAError)
		}
	})

	t.Run("input document", func(t *testing.T) {
		eval := &fakeEvaluator{allowed: true}
		gate := &fakeGate{}
		c := phase3Chain(t, nil, gate, eval)
		route := chainRoute(AuthRequirements{
			Mode:               AuthModeMTLS,
			RequireAttestation: true,
			BackendZone:        "internal",
			OPAPolicy:          "proxy_authz",
		})
		r := tlsRequest(leaf)
		if _, err := c.Authenticate(context.Background(), r, route); err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		client := eval.lastInput["client"].(map[string]any)
		if client["id"] != "device-9" || client["zone"] != "control-plane" || client["attested"] != true ||
			client["auth_method"] != authMethodMTLS {
			t.Errorf("client input = %+v", client)
		}
		if _, has := client["roles"]; has {
			t.Errorf("client input carries roles; OPA answers evidence questions only (#926): %+v", client)
		}
		routeDoc := eval.lastInput["route"].(map[string]any)
		if routeDoc["id"] != "api" || routeDoc["backend_zone"] != "internal" || routeDoc["path_prefix"] != "/" {
			t.Errorf("route input = %+v", routeDoc)
		}
		reqDoc := eval.lastInput["request"].(map[string]any)
		if reqDoc["method"] != http.MethodGet || reqDoc["path"] != "/api" || reqDoc["host"] != "svc.example.com" {
			t.Errorf("request input = %+v", reqDoc)
		}
	})
}

func TestRequestHTU(t *testing.T) {
	tlsReq := tlsRequest(nil)
	if got := requestHTU(tlsReq); got != "https://svc.example.com/api" {
		t.Errorf("tls htu = %q", got)
	}

	plain := httptest.NewRequest(http.MethodPost, "http://svc.example.com/v1/thing?q=1#frag", nil)
	if got := requestHTU(plain); got != "http://svc.example.com/v1/thing" {
		t.Errorf("plain htu = %q, want query and fragment stripped", got)
	}

	// The proxy is the trust boundary: inbound forwarding headers are
	// unauthenticated and must not influence the DPoP binding.
	spoofed := tlsRequest(nil)
	spoofed.Header.Set("X-Forwarded-Proto", "http")
	spoofed.Header.Set("X-Forwarded-Host", "evil.example.org")
	if got := requestHTU(spoofed); got != "https://svc.example.com/api" {
		t.Errorf("spoofed htu = %q, want forwarding headers ignored", got)
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"", ""},
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER abc", "abc"},
		{"Bearer  padded ", "padded"},
		{"Basic dXNlcg==", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
	}
	for _, tc := range tests {
		if got := bearerToken(tc.header); got != tc.want {
			t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestValidateTokenPathFields(t *testing.T) {
	base := func(auth AuthRequirements) *Config {
		return &Config{
			Listeners: []ListenerConfig{{ID: "l", Address: ":0"}},
			Pools:     []BackendPoolConfig{{ID: "p", Backends: []BackendConfig{{URL: "http://b"}}}},
			Routes:    []RouteConfig{{ID: "r", PathPrefix: "/", PoolID: "p", Auth: auth}},
		}
	}
	tests := []struct {
		name    string
		auth    AuthRequirements
		wantErr error
	}{
		{"token zone on mtls route", AuthRequirements{Mode: AuthModeMTLS, TokenZone: "edge"}, ErrTokenModeRequired},
		{"scopes on mtls route", AuthRequirements{Mode: AuthModeMTLS, RequiredScopes: []string{"a:b"}}, ErrTokenModeRequired},
		{"idevid on token route", AuthRequirements{Mode: AuthModeToken, RequireIDevID: true}, ErrIDevIDRequiresMTLS},
		{"token zone on token route", AuthRequirements{Mode: AuthModeToken, TokenZone: "edge"}, nil},
		{"scopes on mtls-or-token route", AuthRequirements{Mode: AuthModeMTLSOrToken, RequiredScopes: []string{"a:b"}}, nil},
		{"idevid on mtls-or-token route", AuthRequirements{Mode: AuthModeMTLSOrToken, RequireIDevID: true}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.auth).Validate()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Validate = %v, want %v", err, tc.wantErr)
			}
		})
	}
}
