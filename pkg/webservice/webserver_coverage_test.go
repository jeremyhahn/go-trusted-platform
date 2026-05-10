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

package webservice

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newMinimalServer creates a minimal WebServerV1 for unit testing
// without needing a real CA.
func newMinimalServer(t *testing.T) *WebServerV1 {
	t.Helper()
	logger := newTestLogger()
	return &WebServerV1{
		logger:      logger,
		router:      mux.NewRouter(),
		routerMutex: &sync.Mutex{},
		closeChan:   make(chan bool, 1),
		httpServer:  &http.Server{},
		config:      &v1.Config{},
	}
}

func TestEndpoints_EmptyRouter(t *testing.T) {
	server := newMinimalServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/endpoints", nil)

	server.endpoints(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestEndpoints_WithRoutes(t *testing.T) {
	server := newMinimalServer(t)

	server.router.HandleFunc("/api/v1/test", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")
	server.router.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {}).Methods("GET")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/endpoints", nil)

	server.endpoints(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "/api/v1/test")
	assert.Contains(t, rec.Body.String(), "/api/v1/health")
}

func TestShutdown(t *testing.T) {
	server := newMinimalServer(t)

	// Bind to an ephemeral port so Shutdown has something to stop
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server.httpServer.Handler = server.router

	doneCh := make(chan struct{})
	go func() {
		server.httpServer.Serve(ln)
		close(doneCh)
	}()

	// Shutdown should not panic and should stop the server
	server.Shutdown()

	select {
	case <-doneCh:
		// Server stopped successfully
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

// NewMutalTLSClient test

func TestNewMutalTLSClient_CreatesClient(t *testing.T) {
	logger := newTestLogger()

	attrs := &xkmssdk.KeyAttributes{
		CN: "test-client",
	}

	client := NewMutalTLSClient(logger, nil, attrs)

	assert.NotNil(t, client.logger)
	assert.Nil(t, client.ca)
}

// Signer.Sign test with mock CA

type mockCASigner struct {
	signFunc func(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

func (m *mockCASigner) Sign(randReader io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if m.signFunc != nil {
		return m.signFunc(randReader, digest, opts)
	}
	return []byte("signed-data"), nil
}

func (m *mockCASigner) Public() crypto.PublicKey {
	return nil
}

func createTestSigner(t *testing.T) (*Signer, *mockCASigner) {
	t.Helper()
	logger := logging.DefaultLogger()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	caSigner := &mockCASigner{}

	signer := &Signer{
		logger: logger,
		cert:   cert,
		cn:     "test",
	}

	return signer, caSigner
}

func TestSigner_Sign_Success(t *testing.T) {
	signer, caSigner := createTestSigner(t)

	signer.ca = &mockCAForSigner{
		signer: caSigner,
	}

	digest := []byte("test-digest-data")
	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, []byte("signed-data"), signature)
}

func TestSigner_Sign_CASignerError(t *testing.T) {
	signer, _ := createTestSigner(t)

	signer.ca = &mockCAForSigner{
		signerErr: errors.New("ca signer unavailable"),
	}

	digest := []byte("test-digest-data")
	_, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ca signer unavailable")
}

// certificate method test

func TestCertificate_Success(t *testing.T) {
	logger := logging.DefaultLogger()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	client := MutualTLSClient{
		logger: logger,
		ca: &mockCAForCert{
			cert: cert,
		},
	}

	attrs := &xkmssdk.KeyAttributes{CN: "client-cert"}
	tlsCert, err := client.certificate(attrs)
	require.NoError(t, err)
	require.NotNil(t, tlsCert)
	assert.Equal(t, cert.Raw, tlsCert.Certificate[0])
}

func TestCertificate_Error(t *testing.T) {
	logger := logging.DefaultLogger()

	client := MutualTLSClient{
		logger: logger,
		ca: &mockCAForCert{
			certErr: errors.New("certificate not found"),
		},
	}

	attrs := &xkmssdk.KeyAttributes{CN: "nonexistent"}
	_, err := client.certificate(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate not found")
}
