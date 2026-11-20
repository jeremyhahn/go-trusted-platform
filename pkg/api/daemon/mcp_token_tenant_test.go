package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// tenantTokenService answers ValidateToken only; the embedded interface is
// nil, so any other call panics and shows the wrapper reached past it.
// tenantTokenService is a service.QuicBaaS that answers ValidateToken only;
// the embedded interface is nil, so any other call panics and shows the
// adapter reached past it.
type tenantTokenService struct {
	service.QuicBaaS
	resp *service.ValidateTokenResponse
	err  error
}

func (s tenantTokenService) ValidateToken(context.Context, *service.ValidateTokenRequest) (*service.ValidateTokenResponse, error) {
	return s.resp, s.err
}

// tenantRecordingPEP allows every check and records the tenant it was sent.
type tenantRecordingPEP struct {
	called bool
	tenant string
}

func (p *tenantRecordingPEP) Check(_ context.Context, req *iam.CheckRequest) (*iam.CheckResponse, error) {
	p.called = true
	p.tenant = req.TenantID
	return &iam.CheckResponse{Allowed: true}, nil
}

func (p *tenantRecordingPEP) CheckBatch(context.Context, *iam.CheckBatchRequest) (*iam.CheckBatchResponse, error) {
	return &iam.CheckBatchResponse{}, nil
}

func jwtWithClaims(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig"))
}

// TestMCPTokenValidatorCarriesVerifiedTenant drives the daemon's MCP token
// path from a stub service.QuicBaaS through quicbaasServiceAdapter (which
// reads the tenant from the verified token) and quicbaasServiceWrapper into
// the MCP auth adapter: an accepted token's tenant reaches the PEP; an
// accepted token naming no tenant, a rejected token and a validation error
// are refused before it (#2080 Codex, SPEC row 123).
func TestMCPTokenValidatorCarriesVerifiedTenant(t *testing.T) {
	ctx := context.Background()
	tenantToken := jwtWithClaims(t, map[string]interface{}{"sub": "u1", "tenant_id": "tenant-a"})
	bareToken := jwtWithClaims(t, map[string]interface{}{"sub": "u1"})

	// newAdapter builds the production chain the daemon wires for MCP:
	// service.QuicBaaS -> quicbaasServiceAdapter -> quicbaasServiceWrapper
	// -> mcp.QuicBaaSAuthAdapter, with a PEP that records its tenant.
	newAdapter := func(svc tenantTokenService) (*mcp.QuicBaaSAuthAdapter, *tenantRecordingPEP) {
		w := &quicbaasServiceWrapper{service: &quicbaasServiceAdapter{svc: svc}}
		pep := &tenantRecordingPEP{}
		return mcp.NewQuicBaaSAuthAdapter(&mcp.QuicBaaSAuthConfig{TokenValidator: w, PEPClient: pep}), pep
	}

	t.Run("accepted token with a tenant reaches the PEP with it", func(t *testing.T) {
		adapter, pep := newAdapter(tenantTokenService{resp: &service.ValidateTokenResponse{
			Valid: true, UserID: "u1", Roles: []string{"viewer"},
		}})
		valid, err := adapter.ValidateToken(ctx, tenantToken)
		if err != nil || !valid {
			t.Fatalf("ValidateToken = %v, %v; want valid", valid, err)
		}
		allowed, err := adapter.CheckPermission(ctx, tenantToken, "vtpm", "read")
		if err != nil || !allowed {
			t.Fatalf("CheckPermission = %v, %v; want allowed", allowed, err)
		}
		if !pep.called || pep.tenant != "tenant-a" {
			t.Fatalf("PEP called=%v tenant=%q, want tenant-a", pep.called, pep.tenant)
		}
	})

	t.Run("accepted token with no tenant is refused before the PEP", func(t *testing.T) {
		adapter, pep := newAdapter(tenantTokenService{resp: &service.ValidateTokenResponse{
			Valid: true, UserID: "u1",
		}})
		valid, err := adapter.ValidateToken(ctx, bareToken)
		var authErr *mcp.QuicBaaSAuthError
		if valid || !errors.As(err, &authErr) || authErr.Code != mcp.QuicBaaSAuthErrorMissingTenant {
			t.Fatalf("ValidateToken = %v, %v; want missing-tenant refusal", valid, err)
		}
		allowed, err := adapter.CheckPermission(ctx, bareToken, "vtpm", "read")
		if allowed || !errors.As(err, &authErr) || authErr.Code != mcp.QuicBaaSAuthErrorMissingTenant {
			t.Fatalf("CheckPermission = %v, %v; want missing-tenant refusal", allowed, err)
		}
		if pep.called {
			t.Fatal("PEP consulted for a token naming no tenant")
		}
	})

	t.Run("rejected token is refused before the PEP", func(t *testing.T) {
		adapter, pep := newAdapter(tenantTokenService{resp: &service.ValidateTokenResponse{Valid: false}})
		valid, err := adapter.ValidateToken(ctx, tenantToken)
		if err != nil || valid {
			t.Fatalf("ValidateToken = %v, %v; want invalid", valid, err)
		}
		allowed, err := adapter.CheckPermission(ctx, tenantToken, "vtpm", "read")
		if allowed || err == nil {
			t.Fatalf("CheckPermission = %v, %v; want refusal", allowed, err)
		}
		if pep.called {
			t.Fatal("PEP consulted for a rejected token")
		}
	})

	t.Run("validation error is refused before the PEP", func(t *testing.T) {
		adapter, pep := newAdapter(tenantTokenService{err: errors.New("quicbaas down")})
		valid, err := adapter.ValidateToken(ctx, tenantToken)
		var authErr *mcp.QuicBaaSAuthError
		if valid || !errors.As(err, &authErr) || authErr.Code != mcp.QuicBaaSAuthErrorTokenValidation {
			t.Fatalf("ValidateToken = %v, %v; want token-validation error", valid, err)
		}
		allowed, err := adapter.CheckPermission(ctx, tenantToken, "vtpm", "read")
		if allowed || err == nil {
			t.Fatalf("CheckPermission = %v, %v; want refusal", allowed, err)
		}
		if pep.called {
			t.Fatal("PEP consulted after a validation error")
		}
	})
}

// TestVerifiedTokenTenant reads the tenant claim of a token the QuicBaaS
// service has already verified; an opaque token or one naming no tenant
// yields no tenant.
func TestVerifiedTokenTenant(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"tenant claim", jwtWithClaims(t, map[string]interface{}{"sub": "u1", "tenant_id": "tenant-a"}), "tenant-a"},
		{"no tenant claim", jwtWithClaims(t, map[string]interface{}{"sub": "u1"}), ""},
		{"non-string tenant claim", jwtWithClaims(t, map[string]interface{}{"tenant_id": 7}), ""},
		{"opaque token", "opaque-quicbaas-token", ""},
		{"bad payload", "a.!!!.c", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifiedTokenTenant(tc.token); got != tc.want {
				t.Fatalf("verifiedTokenTenant = %q, want %q", got, tc.want)
			}
		})
	}
}
