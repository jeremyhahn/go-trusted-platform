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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// QUICAdapterError represents an error from the QUIC adapter
type QUICAdapterError struct {
	Operation string
	Message   string
}

func (e *QUICAdapterError) Error() string {
	return fmt.Sprintf("QUIC adapter error [%s]: %s", e.Operation, e.Message)
}

// QUICRequest represents a QUIC protocol request
type QUICRequest struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Body   interface{} `json:"body,omitempty"`
}

// QUICResponse represents a QUIC protocol response
type QUICResponse struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Error  string          `json:"error,omitempty"`
}

// QUICAdapter implements AttestationCommands using QUIC protocol
type QUICAdapter struct {
	endpoint   string
	conn       *quicgo.Conn
	tlsConfig  *tls.Config
	quicConfig *quicgo.Config
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:  GetQUICEndpoint(),
		tlsConfig: helpers.QUICTLSConfig([]string{"attestation-quic"}),
		quicConfig: &quicgo.Config{
			EnableDatagrams: true,
		},
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	conn, err := quicgo.DialAddr(ctx, a.endpoint, a.tlsConfig, a.quicConfig)
	if err != nil {
		return &QUICAdapterError{
			Operation: "Setup",
			Message:   "failed to connect: " + err.Error(),
		}
	}

	a.conn = conn
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.CloseWithError(0, "teardown")
	}
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// doRequest performs a QUIC request and returns the response
func (a *QUICAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	stream, err := a.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to open stream: " + err.Error(),
		}
	}
	defer stream.Close()

	req := QUICRequest{
		Method: method,
		Path:   path,
		Body:   body,
	}

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	if _, err := stream.Write(reqData); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to write request: " + err.Error(),
		}
	}

	if err := stream.Close(); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to close write: " + err.Error(),
		}
	}

	respData, err := io.ReadAll(stream)
	if err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var resp QUICResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   "failed to unmarshal response: " + err.Error(),
		}
	}

	if resp.Error != "" {
		return nil, &QUICAdapterError{
			Operation: method + " " + path,
			Message:   resp.Error,
		}
	}

	return resp.Body, nil
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM
func (a *QUICAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	path := fmt.Sprintf("/attestation/vm/%s/quote", opts.VMID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result GenerateVMQuoteResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GenerateVMQuote",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate
func (a *QUICAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	path := fmt.Sprintf("/attestation/vm/%s/identity", opts.VMID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetVMIdentityResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetVMIdentity",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetVMAttestation generates a full VM attestation
func (a *QUICAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	path := fmt.Sprintf("/attestation/vm/%s/attest", opts.VMID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result GetVMAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyVMAttestation verifies a VM attestation
func (a *QUICAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	path := fmt.Sprintf("/attestation/vm/verify/%s", opts.AttestationID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result VerifyVMAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "VerifyVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations
func (a *QUICAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	body, err := a.doRequest(ctx, "POST", "/attestation/manifest/build", opts)
	if err != nil {
		return nil, err
	}

	var result BuildManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "BuildManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// SignManifest signs a manifest with the host TPM
func (a *QUICAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	path := fmt.Sprintf("/attestation/manifest/%s/sign", opts.ManifestID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result SignManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "SignManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyManifest verifies a signed manifest
func (a *QUICAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	path := fmt.Sprintf("/attestation/manifest/%s/verify", opts.ManifestID)

	body, err := a.doRequest(ctx, "POST", path, opts)
	if err != nil {
		return nil, err
	}

	var result VerifyManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "VerifyManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetManifest retrieves a manifest by ID
func (a *QUICAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	path := fmt.Sprintf("/attestation/manifest/%s", opts.ManifestID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetManifestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target
func (a *QUICAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	body, err := a.doRequest(ctx, "POST", "/attestation/push", opts)
	if err != nil {
		return nil, err
	}

	var result PushAttestationResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "PushAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// PushAttestationBatch pushes to multiple targets concurrently
func (a *QUICAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	body, err := a.doRequest(ctx, "POST", "/attestation/push/batch", opts)
	if err != nil {
		return nil, err
	}

	var result PushAttestationBatchResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "PushAttestationBatch",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetPushStatus retrieves the status of a push operation
func (a *QUICAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	path := fmt.Sprintf("/attestation/push/status/%s", opts.PushID)

	body, err := a.doRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	var result GetPushStatusResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetPushStatus",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement
func (a *QUICAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	body, err := a.doRequest(ctx, "POST", "/attestation/workload/chain/extend", opts)
	if err != nil {
		return nil, err
	}

	var result ExtendWorkloadChainResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "ExtendWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetWorkloadChainHistory retrieves the chain history
func (a *QUICAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	body, err := a.doRequest(ctx, "GET", "/attestation/workload/chain/history", opts)
	if err != nil {
		return nil, err
	}

	var result GetWorkloadChainHistoryResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetWorkloadChainHistory",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// VerifyWorkloadChain verifies the chain against expected PCR
func (a *QUICAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	body, err := a.doRequest(ctx, "POST", "/attestation/workload/chain/verify", opts)
	if err != nil {
		return nil, err
	}

	var result VerifyWorkloadChainResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "VerifyWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// GetWorkloadChainStats retrieves chain statistics
func (a *QUICAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	body, err := a.doRequest(ctx, "GET", "/attestation/workload/chain/stats", nil)
	if err != nil {
		return nil, err
	}

	var result GetWorkloadChainStatsResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &QUICAdapterError{
			Operation: "GetWorkloadChainStats",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &result, nil
}

// Verify QUICAdapter implements AttestationCommands
var _ AttestationCommands = (*QUICAdapter)(nil)
