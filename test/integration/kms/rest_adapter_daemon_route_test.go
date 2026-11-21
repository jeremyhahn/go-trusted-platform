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

//go:build integration

package kms

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// daemonRouteKMS is the kmsclient.Client behind the webservice KMS router;
// only GenerateKey is implemented, any other call panics on the nil embed.
type daemonRouteKMS struct {
	kmsclient.Client
	got  *kmsclient.GenerateKeyRequest
	resp *kmsclient.GenerateKeyResponse
	err  error
	meta []*kmsclient.UpdateKeyMetadataRequest
}

func (f *daemonRouteKMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.got = req
	return f.resp, f.err
}

func (f *daemonRouteKMS) UpdateKeyMetadata(_ context.Context, req *kmsclient.UpdateKeyMetadataRequest) (*kmsclient.KeyMetadataResponse, error) {
	f.meta = append(f.meta, req)
	return &kmsclient.KeyMetadataResponse{}, nil
}

// daemonRouteToken is the bearer every daemonRouteAdapter request carries;
// daemonRouteValidator grants it the KMS scopes in a tenant, the way the
// daemon's guard verifies a tenant operator.
const daemonRouteToken = "daemon-route-token"

type daemonRouteValidator struct{}

func (daemonRouteValidator) ValidateToken(_ context.Context, token string) (bool, error) {
	return token == daemonRouteToken, nil
}

func (daemonRouteValidator) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	if token != daemonRouteToken {
		return nil, errors.New("unknown token")
	}
	return &platformtoken.AuthorizedContext{
		Subject: "kms-it", TenantID: "tenant-kms-it",
		Scopes: []string{"kms:read", "kms:write", "kms:delete"},
	}, nil
}

// bearerTransport adds the daemon route token to every request.
type bearerTransport struct{ next http.RoundTripper }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+daemonRouteToken)
	return b.next.RoundTrip(r)
}

// daemonRouteAdapter builds the daemon REST server as the daemon wires it
// (SetKMSRouter before SetKMSHandlers, daemon.go) and points a RESTAdapter
// at it. The legacy KMSService is a nil embed, so reaching it panics.
func daemonRouteAdapter(t *testing.T, fake *daemonRouteKMS) *RESTAdapter {
	t.Helper()
	cfg := daemon.DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := daemon.NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	s, err := daemon.NewRESTServer(cfg, svc, slog.Default())
	if err != nil {
		t.Fatalf("NewRESTServer: %v", err)
	}
	s.SetKMSRouter(fake, nil, nil, nil, restapi.NewScopeGuard(daemonRouteValidator{}, nil, nil))
	s.SetKMSHandlers(struct{ restapi.KMSService }{})
	srv := httptest.NewServer(s.Router())
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Transport = bearerTransport{next: client.Transport}
	return &RESTAdapter{baseURL: srv.URL, httpClient: client}
}

// TestRESTAdapterKeyGenerateThroughTheDaemonRoute drives KeyGenerate through
// the route the daemon serves on POST /api/v1/kms/keys: the webservice KMS
// handler, which reads the flat body and answers the webservice envelope
// (#2030 Codex F4/F5).
func TestRESTAdapterKeyGenerateThroughTheDaemonRoute(t *testing.T) {
	opts := KeyGenerateOptions{KeyID: "gen-key-1", Algorithm: "AES-256-GCM", Purpose: "encrypt"}

	t.Run("success", func(t *testing.T) {
		fake := &daemonRouteKMS{resp: &kmsclient.GenerateKeyResponse{
			KeyID: "gen-key-1", Version: 3, Algorithm: kmsclient.AlgorithmAES256GCM,
			Exportable: true, DeletionProtection: true,
		}}
		r := daemonRouteAdapter(t, fake)
		res, err := r.KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.KeyID != "gen-key-1" || res.Version != 3 || res.Algorithm != "AES-256-GCM" {
			t.Fatalf("result key_id=%q version=%d algorithm=%q, want gen-key-1/3/AES-256-GCM", res.KeyID, res.Version, res.Algorithm)
		}
		if !res.Exportable || !res.DeletionProtection {
			t.Fatalf("result exportable=%v deletion_protection=%v, want true/true", res.Exportable, res.DeletionProtection)
		}
		if fake.got == nil {
			t.Fatal("the KMS client saw no GenerateKey request")
		}
		if fake.got.Name != "gen-key-1" || fake.got.Algorithm != kmsclient.AlgorithmAES256GCM {
			t.Fatalf("KMS request name=%q algorithm=%v, want gen-key-1/AES-256-GCM", fake.got.Name, fake.got.Algorithm)
		}
		hasEncrypt := false
		for _, u := range fake.got.Usage {
			if u == kmsclient.KeyUsageEncrypt {
				hasEncrypt = true
			}
		}
		if !hasEncrypt {
			t.Fatalf("KMS request usage=%v, want it to contain encrypt", fake.got.Usage)
		}
	})

	t.Run("the server's algorithm wins", func(t *testing.T) {
		fake := &daemonRouteKMS{resp: &kmsclient.GenerateKeyResponse{
			KeyID: "gen-key-1", Version: 1, Algorithm: kmsclient.AlgorithmRSA2048,
		}}
		res, err := daemonRouteAdapter(t, fake).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.Algorithm != "RSA-2048" {
			t.Fatalf("result algorithm=%q, want RSA-2048 (the server's key type)", res.Algorithm)
		}
	})

	t.Run("unknown algorithm is an error", func(t *testing.T) {
		fake := &daemonRouteKMS{resp: &kmsclient.GenerateKeyResponse{
			KeyID: "gen-key-1", Version: 1, Algorithm: kmsclient.KeyAlgorithm(99),
		}}
		if res, err := daemonRouteAdapter(t, fake).KeyGenerate(context.Background(), opts); err == nil {
			t.Fatalf("KeyGenerate with an UNKNOWN algorithm = %+v, want error", res)
		}
	})

	t.Run("empty key id is an error", func(t *testing.T) {
		fake := &daemonRouteKMS{resp: &kmsclient.GenerateKeyResponse{
			Version: 1, Algorithm: kmsclient.AlgorithmAES256GCM,
		}}
		if res, err := daemonRouteAdapter(t, fake).KeyGenerate(context.Background(), opts); err == nil {
			t.Fatalf("KeyGenerate with no key_id = %+v, want error", res)
		}
	})
}
