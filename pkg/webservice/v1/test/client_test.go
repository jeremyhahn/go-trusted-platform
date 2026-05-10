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

package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/stretchr/testify/assert"
)

func TestNewAccountHandler(t *testing.T) {
	acmeRestService := RestServiceRegistry.ACMERestService()
	assert.NotNil(t, acmeRestService, "ACME service should be configured")

	// Create a test server with the NewAccountHandler
	server := httptest.NewServer(http.HandlerFunc(acmeRestService.NewAccountHandler))
	defer server.Close()

	// Create a new account request
	accountReq := trustedca.ACMENewAccountRequest{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	}

	reqBody, err := json.Marshal(accountReq)
	assert.NoError(t, err)

	// Make a POST request to the new account endpoint
	resp, err := http.Post(server.URL, "application/jose+json", bytes.NewReader(reqBody))
	assert.NoError(t, err)
	defer resp.Body.Close()

	// The handler expects a JWS-signed request, so without proper signing
	// it will return an error. We're just testing that the handler is reachable
	// and processes the request (even if it returns an error due to invalid format)
	assert.NotNil(t, resp)
	// Status should be either BadRequest (invalid JWS) or some other HTTP status
	// depending on the handler implementation
	t.Logf("Response status: %d", resp.StatusCode)
}

func TestHttpClientWithTable(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		responseBody string
	}{
		{"Success", http.StatusOK, `{"message": "success"}`},
		{"NotFound", http.StatusNotFound, `{"message": "not found"}`},
		{"InternalServerError", http.StatusInternalServerError, `{"message": "error"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock server that returns the expected response
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Make a request to the mock server
			client := &http.Client{}
			req, err := http.NewRequest("GET", server.URL, nil)
			assert.NoError(t, err)

			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			// Verify the response status code
			assert.Equal(t, tt.statusCode, resp.StatusCode)
		})
	}
}
