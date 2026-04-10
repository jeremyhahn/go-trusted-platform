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

package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"io"
	"net/http"
)

// RESTAdapterError represents an error from the REST adapter
type RESTAdapterError struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e *RESTAdapterError) Error() string {
	return fmt.Sprintf("REST adapter error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// RESTAdapter implements AttestationCommands using REST API
type RESTAdapter struct {
	endpoint string
	client   *http.Client
}

// NewRESTAdapter creates a new REST adapter
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		endpoint: GetRESTEndpoint(),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
	}
}

// Setup prepares the adapter for testing
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return &RESTAdapterError{
			Operation: "Setup",
			Message:   "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request and returns the response body
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, &RESTAdapterError{
				Operation: method + " " + path,
				Message:   "failed to marshal request: " + err.Error(),
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "failed to create request: " + err.Error(),
		}
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation: method + " " + path,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &RESTAdapterError{
			Operation:  method + " " + path,
			StatusCode: resp.StatusCode,
			Message:    "request failed",
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM
func (a *RESTAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/vm/%s/quote", opts.VMID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result GenerateVMQuoteResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GenerateVMQuote",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate
func (a *RESTAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/vm/%s/identity", opts.VMID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetVMIdentityResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetVMIdentity",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetVMAttestation generates a full VM attestation
func (a *RESTAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/vm/%s/attest", opts.VMID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result GetVMAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// VerifyVMAttestation verifies a VM attestation
func (a *RESTAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/vm/verify/%s", opts.AttestationID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result VerifyVMAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "VerifyVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations
func (a *RESTAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	path := "/api/v1/attestation/manifest/build"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result BuildManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "BuildManifest",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// SignManifest signs a manifest with the host TPM
func (a *RESTAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/manifest/%s/sign", opts.ManifestID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result SignManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "SignManifest",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// VerifyManifest verifies a signed manifest
func (a *RESTAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/manifest/%s/verify", opts.ManifestID)

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result VerifyManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "VerifyManifest",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetManifest retrieves a manifest by ID
func (a *RESTAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/manifest/%s", opts.ManifestID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetManifest",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target
func (a *RESTAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	path := "/api/v1/attestation/push"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result PushAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "PushAttestation",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// PushAttestationBatch pushes to multiple targets concurrently
func (a *RESTAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	path := "/api/v1/attestation/push/batch"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result PushAttestationBatchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "PushAttestationBatch",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetPushStatus retrieves the status of a push operation
func (a *RESTAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	path := fmt.Sprintf("/api/v1/attestation/push/status/%s", opts.PushID)

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetPushStatusResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetPushStatus",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement
func (a *RESTAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	path := "/api/v1/attestation/workload/chain/extend"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result ExtendWorkloadChainResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "ExtendWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetWorkloadChainHistory retrieves the chain history
func (a *RESTAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	path := "/api/v1/attestation/workload/chain/history"

	params := ""
	if opts.Limit > 0 {
		params += fmt.Sprintf("&limit=%d", opts.Limit)
	}
	if opts.Offset > 0 {
		params += fmt.Sprintf("&offset=%d", opts.Offset)
	}
	if params != "" {
		path += "?" + params[1:]
	}

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetWorkloadChainHistoryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetWorkloadChainHistory",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// VerifyWorkloadChain verifies the chain against expected PCR
func (a *RESTAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	path := "/api/v1/attestation/workload/chain/verify"

	body, err := a.doRequest(ctx, http.MethodPost, path, opts)
	if err != nil {
		return nil, err
	}

	var result VerifyWorkloadChainResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "VerifyWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// GetWorkloadChainStats retrieves chain statistics
func (a *RESTAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	path := "/api/v1/attestation/workload/chain/stats"

	body, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result GetWorkloadChainStatsResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RESTAdapterError{
			Operation: "GetWorkloadChainStats",
			Message:   "failed to parse response: " + err.Error(),
			Body:      string(body),
		}
	}

	return &result, nil
}

// Verify RESTAdapter implements AttestationCommands
var _ AttestationCommands = (*RESTAdapter)(nil)
