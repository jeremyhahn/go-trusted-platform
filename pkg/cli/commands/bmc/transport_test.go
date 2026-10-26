package bmc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeClientKeyPair writes a self-signed ECDSA client certificate and its
// key as PEM files and returns their paths with the parsed certificate.
func writeClientKeyPair(t *testing.T) (certPath, keyPath string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xc0de),
		Subject:      pkix.Name{CommonName: "platformctl"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath, cert
}

// clearPlatformTLSEnv keeps the developer's PLATFORM_* variables out of the
// client construction under test.
func clearPlatformTLSEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envPlatformCACert, "")
	t.Setenv(envPlatformClientCert, "")
	t.Setenv(envPlatformClientKey, "")
}

func TestNewBMCHTTPClient_MutualTLSHandshake(t *testing.T) {
	clearPlatformTLSEnv(t)
	certPath, keyPath, clientCert := writeClientKeyPair(t)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"code":200,"payload":{"cn":"`+r.TLS.PeerCertificates[0].Subject.CommonName+`"}}`)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))

	client, err := newBMCHTTPClient(&bmcFlags{caCert: caPath, clientCert: certPath, clientKey: keyPath})
	require.NoError(t, err)

	var got struct {
		CN string `json:"cn"`
	}
	require.NoError(t, doGet(context.Background(), client, srv.URL, &got))
	assert.Equal(t, "platformctl", got.CN)
}

func TestNewBMCHTTPClient_ClientCertFromEnvWithoutCA(t *testing.T) {
	clearPlatformTLSEnv(t)
	certPath, keyPath, _ := writeClientKeyPair(t)
	t.Setenv(envPlatformClientCert, certPath)
	t.Setenv(envPlatformClientKey, keyPath)

	client, err := newBMCHTTPClient(&bmcFlags{})
	require.NoError(t, err)
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "transport %T", client.Transport)
	require.Len(t, tr.TLSClientConfig.Certificates, 1)
	assert.Nil(t, tr.TLSClientConfig.RootCAs, "system roots stay in use without a CA bundle")
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
}

func TestNewBMCHTTPClient_ClientCertLoadFailed(t *testing.T) {
	clearPlatformTLSEnv(t)
	certPath, keyPath := writeCertFiles(t)

	_, err := newBMCHTTPClient(&bmcFlags{clientCert: certPath, clientKey: keyPath})

	var loadErr ErrClientCertLoadFailed
	require.ErrorAs(t, err, &loadErr)
	assert.Equal(t, certPath, loadErr.CertPath)
	assert.Equal(t, keyPath, loadErr.KeyPath)
	require.Error(t, errors.Unwrap(err))
	assert.Contains(t, err.Error(), "failed to load client certificate")
}

func TestNewBMCHTTPClient_ClientCertWithoutKeyIgnored(t *testing.T) {
	clearPlatformTLSEnv(t)
	certPath, _, _ := writeClientKeyPair(t)

	client, err := newBMCHTTPClient(&bmcFlags{clientCert: certPath})
	require.NoError(t, err)
	assert.Nil(t, client.Transport, "a certificate without a key presents no client identity")
}

func TestDecodeResponse(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}
	tests := []struct {
		name     string
		body     string
		want     payload
		wantErr  error
		wantCode int
	}{
		{name: "envelope payload", body: `{"code":200,"success":true,"payload":{"name":"bmc-1"}}`, want: payload{Name: "bmc-1"}},
		{name: "envelope without payload", body: `{"code":200,"success":true}`},
		{name: "envelope error", body: `{"code":409,"error":"busy"}`, wantErr: ErrUnexpectedStatus{}, wantCode: 409},
		{name: "envelope payload of wrong type", body: `{"code":200,"payload":"bmc-1"}`, wantErr: ErrResponseDecodeFailed{}},
		{name: "bare body", body: `{"name":"bmc-2"}`, want: payload{Name: "bmc-2"}},
		{name: "not JSON", body: `<html>`, wantErr: ErrResponseDecodeFailed{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got payload
			err := decodeResponse([]byte(tc.body), &got)
			switch want := tc.wantErr.(type) {
			case nil:
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			case ErrUnexpectedStatus:
				require.ErrorAs(t, err, &want)
				assert.Equal(t, tc.wantCode, want.StatusCode)
				assert.Equal(t, "busy", want.Body)
			case ErrResponseDecodeFailed:
				require.ErrorAs(t, err, &want)
				require.Error(t, want.Cause)
			}
		})
	}
}

// httpVerb runs one of the daemon-mode request helpers against url.
type httpVerb func(client *http.Client, url string, dest interface{}) error

var httpVerbs = map[string]httpVerb{
	http.MethodGet: func(c *http.Client, url string, dest interface{}) error {
		return doGet(context.Background(), c, url, dest)
	},
	http.MethodPost: func(c *http.Client, url string, dest interface{}) error {
		return doPost(context.Background(), c, url, map[string]string{"k": "v"}, dest)
	},
	http.MethodDelete: func(c *http.Client, url string, dest interface{}) error {
		return doDelete(context.Background(), c, url, dest)
	},
}

func TestHTTPVerbs_RequestBuildFailed(t *testing.T) {
	for method, verb := range httpVerbs {
		t.Run(method, func(t *testing.T) {
			err := verb(http.DefaultClient, "://no-scheme", nil)
			var buildErr ErrRequestBuildFailed
			require.ErrorAs(t, err, &buildErr)
			require.Error(t, buildErr.Cause)
		})
	}
}

func TestHTTPVerbs_TruncatedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "64")
		_, _ = io.WriteString(w, `{"code":200`)
	}))
	t.Cleanup(srv.Close)

	for method, verb := range httpVerbs {
		t.Run(method, func(t *testing.T) {
			var dest map[string]any
			err := verb(srv.Client(), srv.URL, &dest)
			var decodeErr ErrResponseDecodeFailed
			require.ErrorAs(t, err, &decodeErr)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		})
	}
}

func TestHTTPVerbs_EmptyBodyLeavesDestUntouched(t *testing.T) {
	var gotMethod atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod.Store(r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	for method, verb := range httpVerbs {
		t.Run(method, func(t *testing.T) {
			dest := map[string]any{"kept": true}
			require.NoError(t, verb(srv.Client(), srv.URL, &dest))
			assert.Equal(t, map[string]any{"kept": true}, dest)
			assert.Equal(t, method, gotMethod.Load())
		})
	}
}

func TestDoPost_PayloadEncodeFailed(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Store(true) }))
	t.Cleanup(srv.Close)

	err := doPost(context.Background(), srv.Client(), srv.URL, make(chan int), nil)

	var encErr ErrRequestEncodeFailed
	require.ErrorAs(t, err, &encErr)
	assert.False(t, called.Load(), "nothing is sent when the payload cannot be encoded")
}

// failingWriter rejects every write, as a closed stdout does.
type failingWriter struct{}

var errWriteClosed = errors.New("write: broken pipe")

func (failingWriter) Write([]byte) (int, error) { return 0, errWriteClosed }

func TestEncodeJSON(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, encodeJSON(&buf, map[string]int{"slot": 2}))
	assert.Equal(t, "{\n  \"slot\": 2\n}\n", buf.String())
}

func TestEncodeJSON_WriteFailed(t *testing.T) {
	err := encodeJSON(failingWriter{}, map[string]int{"slot": 2})

	var outErr ErrOutputWriteFailed
	require.ErrorAs(t, err, &outErr)
	require.ErrorIs(t, err, errWriteClosed)
	assert.Equal(t, "bmc: failed to write output: write: broken pipe", err.Error())
}
