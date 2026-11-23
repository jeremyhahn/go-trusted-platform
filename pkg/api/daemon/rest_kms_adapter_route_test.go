//go:build integration

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

package daemon_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	kmsclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	integrationkms "github.com/jeremyhahn/go-trusted-platform/test/integration/kms"
)

// routeTableGenerateKMS answers GenerateKey with resp and records the request
// the webservice KMS handler sent; any other call panics on the nil embed.
type routeTableGenerateKMS struct {
	kmsclient.Client
	got  *kmsclient.GenerateKeyRequest
	resp *kmsclient.GenerateKeyResponse
}

func (f *routeTableGenerateKMS) GenerateKey(_ context.Context, req *kmsclient.GenerateKeyRequest) (*kmsclient.GenerateKeyResponse, error) {
	f.got = req
	return f.resp, nil
}

// throwawayMTLSEnv points the integration helpers' mTLS variables at a
// self-signed pair in t.TempDir(), so helpers.NewHTTPClient can build its
// client. The httptest server is plain http, so the pair is never used.
func throwawayMTLSEnv(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "route-table-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	t.Setenv(helpers.EnvClientCert, certPath)
	t.Setenv(helpers.EnvClientKey, keyPath)
	t.Setenv(helpers.EnvCACert, certPath)
}

// adapterOnDaemonRoutes serves the daemon's full REST route table, with fake
// behind the webservice KMS router, and returns the integration REST adapter
// pointed at it.
func adapterOnDaemonRoutes(t *testing.T, fake kmsclient.Client) *integrationkms.RESTAdapter {
	t.Helper()
	throwawayMTLSEnv(t)
	srv := httptest.NewServer(daemon.DaemonRouteTableWithKMS(t, fake))
	t.Cleanup(srv.Close)
	return integrationkms.NewRESTAdapterWithConfig(srv.URL, 10*time.Second)
}

// TestRESTAdapterKeyGenerate_ThroughTheDaemonRouteTable drives the integration
// adapter's KeyGenerate through the daemon's real route table (ruling 1048):
// POST /api/v1/kms/keys is answered by the webservice KMS handler, mounted
// before the legacy handlers, whose route-table stub panics if reached.
func TestRESTAdapterKeyGenerate_ThroughTheDaemonRouteTable(t *testing.T) {
	opts := integrationkms.KeyGenerateOptions{KeyID: "gen-key-1", Algorithm: "AES-256-GCM", Purpose: "encrypt"}

	t.Run("decodes the webservice 201 envelope", func(t *testing.T) {
		fake := &routeTableGenerateKMS{resp: &kmsclient.GenerateKeyResponse{
			KeyID:              "gen-key-1",
			Version:            3,
			Algorithm:          kmsclient.AlgorithmAES256GCM,
			Exportable:         true,
			DeletionProtection: true,
		}}
		res, err := adapterOnDaemonRoutes(t, fake).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.KeyID != "gen-key-1" {
			t.Errorf("KeyID = %q, want gen-key-1", res.KeyID)
		}
		if res.Version != 3 {
			t.Errorf("Version = %d, want 3", res.Version)
		}
		if !res.Exportable || !res.DeletionProtection {
			t.Errorf("Exportable = %v, DeletionProtection = %v, want both true", res.Exportable, res.DeletionProtection)
		}
		if fake.got == nil {
			t.Fatal("the webservice KMS handler never called GenerateKey")
		}
		if fake.got.Name != "gen-key-1" {
			t.Errorf("request Name = %q, want gen-key-1", fake.got.Name)
		}
		if fake.got.Algorithm != kmsclient.AlgorithmAES256GCM {
			t.Errorf("request Algorithm = %v, want %v", fake.got.Algorithm, kmsclient.AlgorithmAES256GCM)
		}
	})

	t.Run("the algorithm is the server's", func(t *testing.T) {
		fake := &routeTableGenerateKMS{resp: &kmsclient.GenerateKeyResponse{
			KeyID:     "gen-key-1",
			Version:   1,
			Algorithm: kmsclient.AlgorithmRSA2048,
		}}
		res, err := adapterOnDaemonRoutes(t, fake).KeyGenerate(context.Background(), opts)
		if err != nil {
			t.Fatalf("KeyGenerate: %v", err)
		}
		if res.Algorithm != "RSA-2048" {
			t.Errorf("Algorithm = %q, want the server's RSA-2048, not the requested AES-256-GCM", res.Algorithm)
		}
	})

	t.Run("an empty key ID from the server is an error", func(t *testing.T) {
		fake := &routeTableGenerateKMS{resp: &kmsclient.GenerateKeyResponse{
			Version:   1,
			Algorithm: kmsclient.AlgorithmAES256GCM,
		}}
		if _, err := adapterOnDaemonRoutes(t, fake).KeyGenerate(context.Background(), opts); err == nil {
			t.Fatal("KeyGenerate accepted a response with no key ID")
		}
	})
}
