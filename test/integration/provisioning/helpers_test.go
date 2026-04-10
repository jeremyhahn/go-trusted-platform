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

// Package provisioning provides integration tests for the config delivery and
// QR provisioning session lifecycle. Tests exercise the pre-enrollment config
// fetch REST endpoints against a running platformd instance in the devcontainer.
package provisioning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// DefaultTestTimeout is the default timeout for test contexts.
	DefaultTestTimeout = 60 * time.Second

	// ProvisionBasePath is the REST API base path for provisioning endpoints.
	ProvisionBasePath = "/api/v1/provisioning"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrHTTPRequestFailed indicates the HTTP request could not be sent.
type ErrHTTPRequestFailed struct {
	Cause error
}

func (e ErrHTTPRequestFailed) Error() string {
	return fmt.Sprintf("provisioning: http request failed: %v", e.Cause)
}

func (e ErrHTTPRequestFailed) Unwrap() error {
	return e.Cause
}

// ErrHTTPResponseReadFailed indicates the HTTP response body could not be read.
type ErrHTTPResponseReadFailed struct {
	Cause error
}

func (e ErrHTTPResponseReadFailed) Error() string {
	return fmt.Sprintf("provisioning: http response read failed: %v", e.Cause)
}

func (e ErrHTTPResponseReadFailed) Unwrap() error {
	return e.Cause
}

// ErrHTTPUnexpectedStatus indicates the HTTP response had an unexpected status code.
type ErrHTTPUnexpectedStatus struct {
	Expected int
	Actual   int
	Body     string
}

func (e ErrHTTPUnexpectedStatus) Error() string {
	return fmt.Sprintf("provisioning: expected status %d, got %d: %s",
		e.Expected, e.Actual, e.Body)
}

// ErrJSONDecodeFailed indicates JSON decoding failed.
type ErrJSONDecodeFailed struct {
	Cause error
}

func (e ErrJSONDecodeFailed) Error() string {
	return fmt.Sprintf("provisioning: json decode failed: %v", e.Cause)
}

func (e ErrJSONDecodeFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// WebServiceResponse Envelope
// =============================================================================

// webServiceResponse mirrors the server's WebServiceResponse envelope.
type webServiceResponse struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// =============================================================================
// Config Delivery Response Types
// =============================================================================

// nonceResponse represents the nonce issuance response payload.
type nonceResponse struct {
	Nonce string `json:"nonce"`
}

// configResponse represents a resolved config response payload.
type configResponse struct {
	Config interface{} `json:"config"`
	Status string      `json:"status"`
}

// pendingResponse represents a pending session response payload.
type pendingResponse struct {
	SessionID    string `json:"session_id"`
	ProvisionURL string `json:"provision_url"`
	PollInterval int    `json:"poll_interval_seconds"`
}

// pollPendingResponse represents a poll response when session is not yet fulfilled.
type pollPendingResponse struct {
	Status string `json:"status"`
}

// sessionResponse represents a session returned from GetSession/ListSessions.
type sessionResponse struct {
	ID         string `json:"id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	ProfileID  uint64 `json:"profile_id,omitempty"`
	Fulfilled  bool   `json:"fulfilled"`
}

// fulfillStatusResponse represents the fulfill confirmation.
type fulfillStatusResponse struct {
	Status string `json:"status"`
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// testContext returns a context with the default test timeout.
func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTestTimeout)
}

// =============================================================================
// Endpoint Helpers
// =============================================================================

// serverAddr returns the REST API base URL from environment variables or defaults.
func serverAddr() string {
	return helpers.GetRESTEndpoint()
}

// provisionURL constructs the full provisioning endpoint URL for the given
// sub-path. The path should start with "/" (e.g., "/nonce").
func provisionURL(subPath string) string {
	return serverAddr() + ProvisionBasePath + subPath
}

// =============================================================================
// HTTP Client Helpers
// =============================================================================

// tlsClient creates an HTTPS client configured with mTLS credentials.
func tlsClient() *http.Client {
	return helpers.NewHTTPClient(DefaultTestTimeout)
}

// =============================================================================
// REST Request Helpers
// =============================================================================

// doGET performs a GET request and returns the raw response and status code.
func doGET(ctx context.Context, url string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, ErrHTTPRequestFailed{Cause: err}
	}
	req.Header.Set("Accept", "application/json")

	client := tlsClient()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ErrHTTPRequestFailed{Cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, ErrHTTPResponseReadFailed{Cause: err}
	}

	return resp.StatusCode, body, nil
}

// doPOST performs a POST request with a JSON body and returns the raw response
// and status code.
func doPOST(ctx context.Context, url string, payload interface{}) (int, []byte, error) {
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, ErrJSONDecodeFailed{Cause: err}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return 0, nil, ErrHTTPRequestFailed{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := tlsClient()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, ErrHTTPRequestFailed{Cause: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, ErrHTTPResponseReadFailed{Cause: err}
	}

	return resp.StatusCode, body, nil
}

// parseEnvelope decodes the WebServiceResponse envelope from raw JSON bytes.
func parseEnvelope(body []byte) (*webServiceResponse, error) {
	var envelope webServiceResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, ErrJSONDecodeFailed{Cause: err}
	}
	return &envelope, nil
}

// parsePayload decodes the payload field from a WebServiceResponse envelope
// into the given target.
func parsePayload(envelope *webServiceResponse, target interface{}) error {
	if len(envelope.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Payload, target); err != nil {
		return ErrJSONDecodeFailed{Cause: err}
	}
	return nil
}

// =============================================================================
// Nonce Helper
// =============================================================================

// fetchNonce issues a GET request to the nonce endpoint and returns the nonce
// string. Fails the test on error.
func fetchNonce(t *testing.T, ctx context.Context) string {
	t.Helper()

	status, body, err := doGET(ctx, provisionURL("/config/nonce"))
	if err != nil {
		t.Fatalf("fetchNonce: request failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("fetchNonce: expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("fetchNonce: failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("fetchNonce: response indicates failure: %s", envelope.Error)
	}

	var nonce nonceResponse
	if err := parsePayload(envelope, &nonce); err != nil {
		t.Fatalf("fetchNonce: failed to parse nonce payload: %v", err)
	}

	if nonce.Nonce == "" {
		t.Fatal("fetchNonce: nonce is empty")
	}

	return nonce.Nonce
}

// =============================================================================
// Env Check
// =============================================================================

// requireIntegration skips the test when INTEGRATION_TEST is not set.
func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
	}
}
