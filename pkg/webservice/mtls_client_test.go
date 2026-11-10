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
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMutualTLSClientGet_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	// Create a test server
	expectedBody := "test response body"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedBody))
	}))
	defer server.Close()

	// Create client without custom transport (for testing plain HTTP)
	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL)

	require.NoError(t, err)
	assert.Equal(t, expectedBody, string(body))
}

func TestMutualTLSClientGet_ServerErrorResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL)

	// HTTP errors don't cause an error return from Get
	require.NoError(t, err)
	assert.Equal(t, "server error", string(body))
}

func TestMutualTLSClientGet_InvalidURL(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get("://invalid-url")

	assert.Error(t, err)
	assert.Nil(t, body)
}

func TestNewMutalTLSClient_WithRootCAsPool(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	pool := x509.NewCertPool()

	// Construct with a non-nil pool; verify the TLS transport carries it.
	client := NewMutalTLSClient(context.Background(), logger, nil, nil, pool)

	tr, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.http.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig must not be nil when RootCAs pool is provided")
	}
	assert.Equal(t, pool, tr.TLSClientConfig.RootCAs, "RootCAs must match the provided pool")
	// GetClientCertificate must be wired even when ca is nil (it will error at handshake time,
	// but the function pointer must be non-nil so the transport uses it).
	assert.NotNil(t, tr.TLSClientConfig.GetClientCertificate)
}

func TestNewMutalTLSClient_NilRootCAsUsesSystemRoots(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	// Construct with a nil pool; verify RootCAs remains nil (system roots).
	client := NewMutalTLSClient(context.Background(), logger, nil, nil, nil)

	tr, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.http.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig must not be nil")
	}
	// A nil RootCAs means the OS trust store is used.
	assert.Nil(t, tr.TLSClientConfig.RootCAs, "RootCAs must be nil when no pool is provided")
	// MinVersion must not forbid TLS 1.2 connections (zero value = stdlib default).
	assert.Less(t, tr.TLSClientConfig.MinVersion, uint16(tls.VersionTLS13), "MinVersion must not be forced to TLS 1.3")
}
