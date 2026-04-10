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

package provisioning

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, privateKey
}

// startTLSTestServer creates an httptest TLS server configured with a test
// TLS bundle and returns the server along with the CA pool that clients
// should use to verify the server certificate.
func startTLSTestServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()

	bundle := testutil.GenerateTestTLSBundle(t)

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{bundle.ServerCert},
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server, bundle.CAPool
}

func TestNewClient_Success(t *testing.T) {
	cert, key := generateTestCertificate(t, "test-device")
	caPool := x509.NewCertPool()
	caPool.AddCert(cert)

	config := &ClientConfig{
		ServerURL:   "https://server.example.com:8443",
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
		Timeout:     10 * time.Second,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_NilConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	client, err := NewClient(nil, logger)
	assert.ErrorIs(t, err, ErrInvalidResponse)
	assert.Nil(t, client)
}

func TestNewClient_MissingCertificate(t *testing.T) {
	caPool := x509.NewCertPool()

	config := &ClientConfig{
		ServerURL:  "https://server.example.com:8443",
		CACertPool: caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	assert.ErrorIs(t, err, ErrMissingCertificate)
	assert.Nil(t, client)
}

func TestNewClient_MissingPrivateKey(t *testing.T) {
	cert, _ := generateTestCertificate(t, "test-device")
	caPool := x509.NewCertPool()
	caPool.AddCert(cert)

	config := &ClientConfig{
		ServerURL:   "https://server.example.com:8443",
		Certificate: cert,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	assert.ErrorIs(t, err, ErrMissingPrivateKey)
	assert.Nil(t, client)
}

func TestNewClient_MissingCABundle(t *testing.T) {
	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   "https://server.example.com:8443",
		Certificate: cert,
		PrivateKey:  key,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	assert.ErrorIs(t, err, ErrMissingCABundle)
	assert.Nil(t, client)
}

func TestFetchProfile_Success(t *testing.T) {
	// Create test server
	expectedProfile := ProfileResponse{
		SerialNumber: "TEST-SERIAL-001",
		ProductionNetwork: NetworkConfig{
			VLAN:    100,
			UseDHCP: true,
			Gateway: "192.168.1.1",
			DNS:     []string{"8.8.8.8"},
		},
		ACLs: []ACLConfig{
			{
				Name:     "allow-https",
				Priority: 100,
				Match:    map[string]string{"tcp_dst": "443"},
				Action:   "allow",
			},
		},
	}

	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/device/profile", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expectedProfile); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))

	// Create client with test server's CA
	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
		Timeout:     5 * time.Second,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, err := client.FetchProfile(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedProfile.SerialNumber, profile.SerialNumber)
	assert.Equal(t, expectedProfile.ProductionNetwork.VLAN, profile.ProductionNetwork.VLAN)
	assert.Equal(t, expectedProfile.ProductionNetwork.UseDHCP, profile.ProductionNetwork.UseDHCP)
}

func TestFetchProfile_ServerError(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error": "profile not found"}`))
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, err := client.FetchProfile(ctx)
	assert.ErrorIs(t, err, ErrServerError)
	assert.Nil(t, profile)
}

func TestFetchProfile_InvalidJSON(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{invalid json}`))
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, err := client.FetchProfile(ctx)
	assert.ErrorIs(t, err, ErrInvalidResponse)
	assert.Nil(t, profile)
}

func TestActivate_Success(t *testing.T) {
	expectedResponse := ActivateResponse{
		Status:         "activated",
		VLAN:           100,
		TransitionedAt: time.Now().UTC(),
	}

	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/device/activate", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(expectedResponse); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := client.Activate(ctx)
	require.NoError(t, err)
	assert.Equal(t, "activated", resp.Status)
	assert.Equal(t, uint16(100), resp.VLAN)
}

func TestActivate_ServerError(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"error": "internal error"}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := client.Activate(ctx)
	assert.ErrorIs(t, err, ErrServerError)
	assert.Nil(t, resp)
}

func TestActivate_InvalidJSON(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{bad json response}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	resp, err := client.Activate(ctx)
	assert.ErrorIs(t, err, ErrInvalidResponse)
	assert.Nil(t, resp)
}

func TestFetchProfileAndActivate_Success(t *testing.T) {
	callCount := 0

	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1/device/profile":
			assert.Equal(t, http.MethodGet, r.Method)
			if err := json.NewEncoder(w).Encode(ProfileResponse{
				SerialNumber: "TEST-001",
				ProductionNetwork: NetworkConfig{
					VLAN:     200,
					UseDHCP:  false,
					StaticIP: "203.0.113.10/24",
					Gateway:  "203.0.113.1",
				},
			}); err != nil {
				t.Errorf("encode profile response: %v", err)
			}
		case "/api/v1/device/activate":
			assert.Equal(t, http.MethodPost, r.Method)
			if err := json.NewEncoder(w).Encode(ActivateResponse{
				Status:         "activated",
				VLAN:           200,
				TransitionedAt: time.Now().UTC(),
			}); err != nil {
				t.Errorf("encode activate response: %v", err)
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, activateResp, err := client.FetchProfileAndActivate(ctx)
	require.NoError(t, err)

	assert.Equal(t, 2, callCount, "should call both profile and activate endpoints")
	assert.Equal(t, "TEST-001", profile.SerialNumber)
	assert.Equal(t, uint16(200), profile.ProductionNetwork.VLAN)
	assert.Equal(t, "activated", activateResp.Status)
}

func TestFetchProfileAndActivate_ProfileFetchFails(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, activateResp, err := client.FetchProfileAndActivate(ctx)
	assert.Error(t, err)
	assert.Nil(t, profile)
	assert.Nil(t, activateResp)
}

func TestFetchProfileAndActivate_ActivationFails(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/api/v1/device/profile":
			if err := json.NewEncoder(w).Encode(ProfileResponse{
				SerialNumber: "TEST-001",
				ProductionNetwork: NetworkConfig{
					VLAN: 100,
				},
			}); err != nil {
				t.Errorf("encode profile response: %v", err)
			}
		case "/api/v1/device/activate":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	profile, activateResp, err := client.FetchProfileAndActivate(ctx)
	assert.Error(t, err)
	assert.NotNil(t, profile, "profile should be returned even if activation fails")
	assert.Nil(t, activateResp)
}

func TestClient_ContextCancellation(t *testing.T) {
	server, caPool := startTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))

	cert, key := generateTestCertificate(t, "test-device")

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
		Timeout:     5 * time.Second,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	profile, err := client.FetchProfile(ctx)
	assert.Error(t, err)
	assert.Nil(t, profile)
}

func TestClient_Close(t *testing.T) {
	cert, key := generateTestCertificate(t, "test-device")
	caPool := x509.NewCertPool()
	caPool.AddCert(cert)

	config := &ClientConfig{
		ServerURL:   "https://server.example.com:8443",
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  caPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

// TestMTLSVerification tests that the client properly presents the IDevID certificate
func TestMTLSVerification(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)

	// Create server with client cert verification
	clientCert, clientKey := generateTestCertificate(t, "test-device-idevid")

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(clientCert) // Trust client cert

	var receivedCert *x509.Certificate

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			receivedCert = r.TLS.PeerCertificates[0]
		}
		if err := json.NewEncoder(w).Encode(ProfileResponse{
			SerialNumber: "TEST-001",
		}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{bundle.ServerCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    clientCAPool,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	config := &ClientConfig{
		ServerURL:   server.URL,
		Certificate: clientCert,
		PrivateKey:  clientKey,
		CACertPool:  bundle.CAPool,
	}

	logger := logging.DefaultLogger()
	client, err := NewClient(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = client.FetchProfile(ctx)
	require.NoError(t, err)

	// Verify the server received our client certificate
	require.NotNil(t, receivedCert, "server should have received client certificate")
	assert.Equal(t, "test-device-idevid", receivedCert.Subject.CommonName)
}

func TestDefaultClientConfig(t *testing.T) {
	config := DefaultClientConfig()
	assert.NotNil(t, config)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, "", config.ServerURL)
	assert.Nil(t, config.Certificate)
	assert.Nil(t, config.PrivateKey)
	assert.Nil(t, config.CACertPool)
}
