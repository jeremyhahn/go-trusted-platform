package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// daemonKeys2151KMS is the KMS client behind the mounted router in
// TestDaemonREST_KMSKeysKeepMetadataAndListSemantics.
type daemonKeys2151KMS struct {
	kmsclient.Client
	genReq    *kmsclient.GenerateKeyRequest
	updateReq *kmsclient.UpdateKeyMetadataRequest
}

func (f *daemonKeys2151KMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.genReq = req
	return &kmsclient.GenerateKeyResponse{KeyID: "gen-1", Version: 1, Algorithm: req.Algorithm}, nil
}

func (f *daemonKeys2151KMS) UpdateKeyMetadata(_ context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	f.updateReq = req
	return &kmsclient.KeyMetadataResponse{KeyID: req.KeyID}, nil
}

func (f *daemonKeys2151KMS) ListKeys(context.Context) (*kmsclient.ListKeysResponse, error) {
	return &kmsclient.ListKeysResponse{Keys: []kmsclient.KeyInfo{
		{KeyID: "c", Name: "c", Algorithm: kmsclient.AlgorithmRSA2048, Version: 1},
		{KeyID: "a", Name: "a", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
		{KeyID: "b", Name: "b", Algorithm: kmsclient.AlgorithmAES256GCM, Version: 1},
	}}, nil
}

// TestDaemonREST_KMSKeysKeepMetadataAndListSemantics drives the KMS router
// mounted on the daemon REST listener: generation records description and
// tags, and the key list keeps the facade's pagination (#2151 Codex round 2).
func TestDaemonREST_KMSKeysKeepMetadataAndListSemantics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	cfg.PlatformTenantID = probePlatformTenant
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	guard := restapi.NewScopeGuard(tenantScopedTokenValidator{tenant: probePlatformTenant, scopes: kmsCatalogScopes(t)}, nil, nil)
	fake := &daemonKeys2151KMS{}
	s.SetKMSRouter(fake, nil, nil, nil, guard)
	s.SetKMSHandlers(routeTableKMS{})

	serve := func(method, target, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer t")
		w := httptest.NewRecorder()
		if serveProbe(s, w, req) {
			t.Fatalf("%s %s reached a legacy handler", method, target)
		}
		return w
	}

	w := serve(http.MethodPost, "/api/v1/kms/keys",
		`{"name":"k1","algorithm":"AES-256-GCM","description":"payroll","tags":{"team":"ops"}}`)
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NotNil(t, fake.updateReq, "POST /api/v1/kms/keys dropped description and tags")
	require.Equal(t, "gen-1", fake.updateReq.KeyID)
	require.Equal(t, "payroll", fake.updateReq.Description)
	require.Equal(t, map[string]string{"team": "ops"}, fake.updateReq.Tags)

	w = serve(http.MethodGet, "/api/v1/kms/keys?limit=1", "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var reply struct {
		Payload struct {
			Keys []struct {
				KeyID string `json:"key_id"`
			} `json:"keys"`
			NextCursor string `json:"next_cursor"`
			HasMore    bool   `json:"has_more"`
			TotalCount int    `json:"total_count"`
		} `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &reply), w.Body.String())
	require.Len(t, reply.Payload.Keys, 1, w.Body.String())
	require.Equal(t, "a", reply.Payload.Keys[0].KeyID)
	require.Equal(t, "1", reply.Payload.NextCursor)
	require.True(t, reply.Payload.HasMore)
	require.Equal(t, 3, reply.Payload.TotalCount)
}

// TestDaemonREST_KMSGenerateKeyAcceptsTheFacadeKeySpec drives the facade's
// snake_case key_spec request through the mounted KMS router (#2151 Codex
// round 2).
func TestDaemonREST_KMSGenerateKeyAcceptsTheFacadeKeySpec(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	cfg.PlatformTenantID = probePlatformTenant
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	guard := restapi.NewScopeGuard(tenantScopedTokenValidator{tenant: probePlatformTenant, scopes: kmsCatalogScopes(t)}, nil, nil)
	fake := &daemonKeys2151KMS{}
	s.SetKMSRouter(fake, nil, nil, nil, guard)
	s.SetKMSHandlers(routeTableKMS{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/kms/keys", strings.NewReader(
		`{"name":"k","key_spec":{"algorithm":"AES-256-GCM","usage":["ENCRYPT","DECRYPT"],"exportable":true,"deletion_protection":true}}`))
	req.Header.Set("Authorization", "Bearer t")
	w := httptest.NewRecorder()
	if serveProbe(s, w, req) {
		t.Fatal("POST /api/v1/kms/keys reached a legacy handler")
	}
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	require.NotNil(t, fake.genReq)
	require.Equal(t, kmsclient.AlgorithmAES256GCM, fake.genReq.Algorithm)
	require.True(t, fake.genReq.Exportable)
	require.True(t, fake.genReq.DeletionProtection)
}
