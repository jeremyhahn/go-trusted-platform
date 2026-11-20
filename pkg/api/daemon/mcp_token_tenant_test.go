package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// tenantTokenService answers ValidateToken only; the embedded interface is
// nil, so any other call panics and shows the wrapper reached past it.
type tenantTokenService struct {
	quicbaas.ServiceInterface
	resp *quicbaas.ValidateTokenResponse
}

func (s tenantTokenService) ValidateToken(context.Context, *quicbaas.ValidateTokenRequest) (*quicbaas.ValidateTokenResponse, error) {
	return s.resp, nil
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
// validator path (quicbaasServiceWrapper): the tenant the verified token
// names reaches the MCP result; a token naming none leaves it empty so the
// MCP permission check refuses it (#2080 Codex, SPEC row 123).
func TestMCPTokenValidatorCarriesVerifiedTenant(t *testing.T) {
	ctx := context.Background()

	t.Run("verified tenant reaches the MCP result", func(t *testing.T) {
		w := &quicbaasServiceWrapper{service: tenantTokenService{resp: &quicbaas.ValidateTokenResponse{
			Valid: true, UserID: "u1", TenantID: "tenant-a", Roles: []string{"viewer"},
		}}}
		got, err := w.ValidateToken(ctx, "tok")
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if got.TenantID != "tenant-a" {
			t.Fatalf("TenantID = %q, want tenant-a", got.TenantID)
		}

		pep := &tenantRecordingPEP{}
		adapter := mcp.NewQuicBaaSAuthAdapter(&mcp.QuicBaaSAuthConfig{TokenValidator: w, PEPClient: pep})
		allowed, err := adapter.CheckPermission(ctx, "tok", "vtpm", "read")
		if err != nil || !allowed {
			t.Fatalf("CheckPermission = %v, %v; want allowed", allowed, err)
		}
		if pep.tenant != "tenant-a" {
			t.Fatalf("PEP tenant = %q, want tenant-a", pep.tenant)
		}
	})

	t.Run("token with no tenant stays tenantless", func(t *testing.T) {
		w := &quicbaasServiceWrapper{service: tenantTokenService{resp: &quicbaas.ValidateTokenResponse{
			Valid: true, UserID: "u1",
		}}}
		got, err := w.ValidateToken(ctx, "tok")
		if err != nil {
			t.Fatalf("ValidateToken: %v", err)
		}
		if got.TenantID != "" {
			t.Fatalf("TenantID = %q, want empty", got.TenantID)
		}

		pep := &tenantRecordingPEP{}
		adapter := mcp.NewQuicBaaSAuthAdapter(&mcp.QuicBaaSAuthConfig{TokenValidator: w, PEPClient: pep})
		allowed, err := adapter.CheckPermission(ctx, "tok", "vtpm", "read")
		var authErr *mcp.QuicBaaSAuthError
		if allowed || !errors.As(err, &authErr) || authErr.Code != mcp.QuicBaaSAuthErrorMissingTenant {
			t.Fatalf("CheckPermission = %v, %v; want missing-tenant refusal", allowed, err)
		}
		if pep.called {
			t.Fatal("PEP consulted for a token naming no tenant")
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
