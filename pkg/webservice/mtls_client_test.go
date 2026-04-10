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

func TestMutualTLSClientGet_ConnectionError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get("http://localhost:99999/nonexistent")

	assert.Error(t, err)
	assert.Nil(t, body)
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

func TestMutualTLSClientGet_EmptyResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL)

	require.NoError(t, err)
	assert.Empty(t, body)
}

func TestMutualTLSClientGet_LargeResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	// Create a large response body
	largeBody := make([]byte, 1024*1024) // 1MB
	for i := range largeBody {
		largeBody[i] = byte('a' + (i % 26))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(largeBody)
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL)

	require.NoError(t, err)
	assert.Len(t, body, len(largeBody))
}

func TestMutualTLSClientGet_JSONResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	expectedJSON := `{"key":"value","number":42}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedJSON))
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL)

	require.NoError(t, err)
	assert.Equal(t, expectedJSON, string(body))
}

func TestMutualTLSClientGet_RedirectFollowed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	finalBody := "final destination"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(finalBody))
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	body, err := client.Get(server.URL + "/redirect")

	require.NoError(t, err)
	assert.Equal(t, finalBody, string(body))
}

func TestMutualTLSClientStruct(t *testing.T) {
	t.Run("struct fields exist", func(t *testing.T) {
		client := MutualTLSClient{}

		// Verify struct can be created with fields
		assert.Nil(t, client.logger)
		assert.Nil(t, client.ca)
	})
}

func TestMutualTLSClientGet_RequestHeaders(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)

	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	client := MutualTLSClient{
		logger: logger,
		http:   *http.DefaultClient,
	}

	_, err := client.Get(server.URL)

	require.NoError(t, err)
	// Verify that basic headers are present
	assert.NotEmpty(t, receivedHeaders.Get("User-Agent"))
}
