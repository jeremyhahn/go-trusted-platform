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
	"io"
	"net/http"
	"net/url"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// RESTAdapterError represents an error from the REST adapter
type RESTAdapterError struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
	Err        error
}

func (e *RESTAdapterError) Error() string {
	return fmt.Sprintf("REST adapter error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

func (e *RESTAdapterError) Unwrap() error {
	return e.Err
}

// ErrRESTNoRoute names an operation the platformd REST API serves no route
// for. The adapter reports the gap instead of calling a path the server never
// registered, which could only ever answer 404 (#546).
type ErrRESTNoRoute struct {
	Operation string
}

func (e ErrRESTNoRoute) Error() string {
	return fmt.Sprintf("the platformd REST API serves no route for %s", e.Operation)
}

// The routes below are the ones pkg/webservice/v1/rest/attestation registers;
// pkg/webservice/v1/testdata/routes.golden is the authority for their shape.
const (
	restStatusPath         = "/api/v1/status"
	restManifestBuildPath  = "/api/v1/attestation/manifests/build"
	restManifestVerifyPath = "/api/v1/attestation/manifests/verify"
	restQuoteVerifyPath    = "/api/v1/attestation/quote/verify"
)

// restVMPath is POST /api/v1/attestation/vm/{id}, the CollectVMAttestation route.
func restVMPath(vmID string) string {
	return "/api/v1/attestation/vm/" + url.PathEscape(vmID)
}

// restManifestPath is GET /api/v1/attestation/manifests/{id}.
func restManifestPath(manifestID string) string {
	return "/api/v1/attestation/manifests/" + url.PathEscape(manifestID)
}

// restEnvelope is the restwire.WebServiceResponse envelope every /api/v1
// handler writes, with the payload kept raw: the server encodes it with
// protojson, so it is decoded with protojson too.
type restEnvelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
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

// Setup confirms the daemon's REST listener answers its liveness route.
func (a *RESTAdapter) Setup(ctx context.Context) error {
	return a.call(ctx, "Setup", http.MethodGet, restStatusPath, nil, nil)
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// call sends in to path as protojson and decodes the response envelope's
// payload into out. A nil in sends no body; a nil out checks only the status.
func (a *RESTAdapter) call(ctx context.Context, operation, method, path string, in, out proto.Message) error {
	var reqBody io.Reader
	if in != nil {
		data, err := protojson.Marshal(in)
		if err != nil {
			return &RESTAdapterError{
				Operation: operation,
				Message:   "failed to marshal request",
				Err:       err,
			}
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, reqBody)
	if err != nil {
		return &RESTAdapterError{
			Operation: operation,
			Message:   "failed to create request",
			Err:       err,
		}
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return &RESTAdapterError{
			Operation: operation,
			Message:   method + " " + path + " failed",
			Err:       err,
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &RESTAdapterError{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response",
			Err:        err,
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &RESTAdapterError{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Message:    method + " " + path + " failed",
			Body:       string(respBody),
		}
	}

	if out == nil {
		return nil
	}
	return decodeRESTPayload(operation, resp.StatusCode, respBody, out)
}

// decodeRESTPayload unwraps a success envelope and decodes its payload into out.
func decodeRESTPayload(operation string, statusCode int, body []byte, out proto.Message) error {
	var envelope restEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &RESTAdapterError{
			Operation:  operation,
			StatusCode: statusCode,
			Message:    "failed to parse response envelope",
			Body:       string(body),
			Err:        err,
		}
	}

	if !envelope.Success {
		return &RESTAdapterError{
			Operation:  operation,
			StatusCode: statusCode,
			Message:    "server reported failure: " + envelope.Error,
			Body:       string(body),
		}
	}

	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(envelope.Payload, out); err != nil {
		return &RESTAdapterError{
			Operation:  operation,
			StatusCode: statusCode,
			Message:    "failed to parse response payload",
			Body:       string(body),
			Err:        err,
		}
	}
	return nil
}

// invalidResponse wraps a response that decoded but lacks what the result needs.
func invalidResponse(operation string, err error) error {
	return &RESTAdapterError{
		Operation: operation,
		Message:   err.Error(),
		Err:       err,
	}
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM via POST /api/v1/attestation/vm/{id}.
func (a *RESTAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp := &platformv1.CollectVMAttestationResponse{}
	if err := a.call(ctx, "GenerateVMQuote", http.MethodPost, restVMPath(opts.VMID), req, resp); err != nil {
		return nil, err
	}

	result, err := vmQuoteResult(resp)
	if err != nil {
		return nil, invalidResponse("GenerateVMQuote", err)
	}
	return result, nil
}

// GetVMIdentity has no REST route: platformd serves no VM identity endpoint.
func (a *RESTAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, ErrRESTNoRoute{Operation: "GetVMIdentity"}
}

// GetVMAttestation generates a full VM attestation via POST /api/v1/attestation/vm/{id}.
func (a *RESTAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp := &platformv1.CollectVMAttestationResponse{}
	if err := a.call(ctx, "GetVMAttestation", http.MethodPost, restVMPath(opts.VMID), req, resp); err != nil {
		return nil, err
	}

	result, err := vmAttestationResult(resp)
	if err != nil {
		return nil, invalidResponse("GetVMAttestation", err)
	}
	return result, nil
}

// VerifyVMAttestation verifies a VM attestation via POST /api/v1/attestation/quote/verify.
func (a *RESTAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	resp := &platformv1.VerifyAttestationQuoteResponse{}
	if err := a.call(ctx, "VerifyVMAttestation", http.MethodPost, restQuoteVerifyPath, verifyAttestationQuoteRequest(opts), resp); err != nil {
		return nil, err
	}
	return verifyVMAttestationResult(opts, resp), nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest via POST /api/v1/attestation/manifests/build.
func (a *RESTAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	resp := &platformv1.BuildManifestResponse{}
	if err := a.call(ctx, "BuildManifest", http.MethodPost, restManifestBuildPath, buildManifestRequest(opts), resp); err != nil {
		return nil, err
	}

	result, err := buildManifestResult(resp)
	if err != nil {
		return nil, invalidResponse("BuildManifest", err)
	}
	return result, nil
}

// SignManifest has no REST route: BuildManifest signs as it builds, and
// platformd serves no separate signing endpoint.
func (a *RESTAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, ErrRESTNoRoute{Operation: "SignManifest"}
}

// VerifyManifest fetches the stored manifest and verifies it via
// POST /api/v1/attestation/manifests/verify, which takes the manifest itself.
func (a *RESTAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	getResp := &platformv1.GetManifestResponse{}
	if err := a.call(ctx, "VerifyManifest/GetManifest", http.MethodGet, restManifestPath(opts.ManifestID), nil, getResp); err != nil {
		return nil, err
	}
	manifest, err := storedManifest(getResp)
	if err != nil {
		return nil, invalidResponse("VerifyManifest/GetManifest", err)
	}

	resp := &platformv1.VerifyManifestResponse{}
	if err := a.call(ctx, "VerifyManifest", http.MethodPost, restManifestVerifyPath, verifyManifestRequest(manifest), resp); err != nil {
		return nil, err
	}

	result, err := verifyManifestResult(opts, manifest, resp)
	if err != nil {
		return nil, invalidResponse("VerifyManifest", err)
	}
	return result, nil
}

// GetManifest retrieves a manifest via GET /api/v1/attestation/manifests/{id}.
func (a *RESTAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	resp := &platformv1.GetManifestResponse{}
	if err := a.call(ctx, "GetManifest", http.MethodGet, restManifestPath(opts.ManifestID), nil, resp); err != nil {
		return nil, err
	}

	result, err := getManifestResult(resp)
	if err != nil {
		return nil, invalidResponse("GetManifest", err)
	}
	return result, nil
}

// =============================================================================
// Push Operations: platformd serves no push routes.
// =============================================================================

// PushAttestation has no REST route.
func (a *RESTAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, ErrRESTNoRoute{Operation: "PushAttestation"}
}

// PushAttestationBatch has no REST route.
func (a *RESTAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, ErrRESTNoRoute{Operation: "PushAttestationBatch"}
}

// GetPushStatus has no REST route.
func (a *RESTAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, ErrRESTNoRoute{Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations: platformd serves no workload chain routes.
// =============================================================================

// ExtendWorkloadChain has no REST route.
func (a *RESTAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, ErrRESTNoRoute{Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory has no REST route.
func (a *RESTAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, ErrRESTNoRoute{Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain has no REST route.
func (a *RESTAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, ErrRESTNoRoute{Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats has no REST route.
func (a *RESTAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, ErrRESTNoRoute{Operation: "GetWorkloadChainStats"}
}

// Verify RESTAdapter implements AttestationCommands
var _ AttestationCommands = (*RESTAdapter)(nil)
