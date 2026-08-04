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

package kms

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

// =============================================================================
// Compile-time interface check
// =============================================================================

var _ KMSCommands = (*RESTAdapter)(nil)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements KMSCommands using HTTP/REST calls to platform-api.
// This adapter makes REST API calls to the platform-api server for testing
// the REST transport layer consistency with other protocol adapters.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
// It reads configuration from environment variables with sensible defaults.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// NewRESTAdapterWithConfig creates a REST adapter with explicit configuration.
func NewRESTAdapterWithConfig(baseURL string, timeout time.Duration) *RESTAdapter {
	return &RESTAdapter{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client with base URL from environment or default.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	r.baseURL = "http://" + endpoints.PlatformAPI

	// Check for explicit override via environment variable
	if envURL := os.Getenv("PLATFORM_API_URL"); envURL != "" {
		r.baseURL = envURL
	}

	r.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	// Verify connectivity by checking backend status
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/kms/backend/status", nil)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrRESTUnexpectedStatus{Expected: http.StatusOK, Actual: statusCode}
	}

	return nil
}

// Teardown cleans up REST client resources.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

// doRequest performs an HTTP request with JSON serialization.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, ErrRESTMarshalFailed{Err: err}
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, ErrRESTRequestCreationFailed{Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, ErrRESTRequestFailed{Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, ErrRESTResponseReadFailed{Err: err}
	}

	return respBody, resp.StatusCode, nil
}

// restEnvelope mirrors the platform WebServiceResponse envelope that
// wraps every payload returned by the v1 REST API.
type restEnvelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// handleResponse processes the HTTP response, unwraps the
// WebServiceResponse envelope, and unmarshals the payload into target.
func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}

	if target == nil || len(respBody) == 0 {
		return nil
	}

	var envelope restEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return ErrRESTUnmarshalFailed{Err: err}
	}
	if len(envelope.Payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(envelope.Payload, target); err != nil {
		return ErrRESTUnmarshalFailed{Err: err}
	}

	return nil
}

// parseErrorResponse extracts error information from error responses.
func (r *RESTAdapter) parseErrorResponse(respBody []byte, statusCode int) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &errResp); err != nil {
		return ErrRESTAPIError{StatusCode: statusCode, Message: string(respBody)}
	}

	msg := errResp.Error
	if msg == "" {
		msg = errResp.Message
	}

	return ErrRESTAPIError{StatusCode: statusCode, Message: msg}
}

// =============================================================================
// Key Management Commands
// =============================================================================

// KeyGenerate generates a new cryptographic key via REST API.
func (r *RESTAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	req := &service.GenerateKeyRequest{
		Name:               opts.Name,
		Description:        opts.Description,
		Owner:              opts.Owner,
		Exportable:         opts.Exportable,
		DeletionProtection: opts.DeletionProtection,
		KeyAttributes:      r.algorithmStringToKeyAttributes(opts.Algorithm),
		Usage:              r.purposeToKeyUsage(opts.Purpose),
	}

	restReq := r.convertToGenerateKeyRequest(req)
	// Note: KeyID is not sent in the request; it's either derived from Name
	// or generated by the server and returned in the response

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/keys", restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GenerateKeyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToKeyGenerateResult(&restResp), nil
}

// KeyGet retrieves key information via REST API.
func (r *RESTAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID)
	if version > 0 {
		path += "?version=" + strconv.FormatUint(version, 10)
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.KeyInfoResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToKeyGetResult(&restResp), nil
}

// KeyList lists all keys via REST API.
func (r *RESTAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/kms/keys"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListKeysResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToKeyListResult(&restResp), nil
}

// KeyDelete deletes a key via REST API.
func (r *RESTAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	params := url.Values{}
	if opts.PendingWindowDays > 0 {
		params.Set("pending_window_days", strconv.FormatInt(int64(opts.PendingWindowDays), 10))
	}
	if opts.Force {
		params.Set("force", "true")
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// The current REST contract returns an empty JSON object on success;
	// echo the request key so callers can correlate. Status and
	// DeletionDate are no longer reported on this transport.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID: keyID,
	}, nil
}

// KeyRotate rotates an existing key via REST API.
func (r *RESTAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	// The current REST rotate contract takes no request body and responds
	// with {key_id, new_version} only. retainOldVersion is not expressible
	// on this transport; the versioned key store always retains prior
	// versions.
	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/rotate"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateKeyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// old_version is no longer reported on the wire; versions increment
	// sequentially, so derive it from new_version.
	newVersion := uint64(restResp.NewVersion)
	var oldVersion uint64
	if newVersion > 0 {
		oldVersion = newVersion - 1
	}

	return &KeyRotateResult{
		KeyID:      restResp.KeyID,
		OldVersion: oldVersion,
		NewVersion: newVersion,
	}, nil
}

// KeyVersions lists all versions of a key via REST API.
func (r *RESTAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/versions"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListKeyVersionsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToKeyVersionsResult(keyID, &restResp), nil
}

// KeyStatus updates the status of a key via REST API.
func (r *RESTAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/status"
	status := "DISABLED"
	if enabled {
		status = "ENABLED"
	}
	restReq := resttypes.UpdateKeyStatusRequest{
		Version: int(version),
		Status:  status,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.UpdateKeyStatusResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyStatusResult{
		KeyID:   restResp.KeyID,
		Version: uint64(restResp.Version),
		Status:  restResp.Status,
	}, nil
}

// KeyRevoke revokes a key via REST API.
func (r *RESTAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/revoke"
	restReq := resttypes.RevokeKeyRequest{
		Reason: reason,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		KeyID     string    `json:"key_id"`
		Status    string    `json:"status"`
		RevokedAt time.Time `json:"revoked_at"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     restResp.KeyID,
		Status:    restResp.Status,
		RevokedAt: restResp.RevokedAt,
	}, nil
}

// KeyMetadata retrieves key metadata via REST API.
func (r *RESTAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/metadata"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.KeyMetadataResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &KeyMetadataResult{
		KeyID:              restResp.KeyID,
		Name:               restResp.Name,
		Description:        restResp.Description,
		Algorithm:          restResp.Algorithm,
		Status:             restResp.Status,
		Version:            uint64(restResp.Version),
		Exportable:         restResp.Exportable,
		DeletionProtection: restResp.DeletionProtection,
		Usage:              restResp.Usage,
		Owner:              restResp.Owner,
		CreatedAt:          restResp.CreatedAt,
		UpdatedAt:          restResp.UpdatedAt,
		LastUsedAt:         restResp.LastUsedAt,
		Tags:               restResp.Tags,
	}

	if restResp.RotationPolicy != nil {
		result.RotationPolicy = &RotationPolicy{
			Enabled:         restResp.RotationPolicy.Enabled,
			IntervalSeconds: restResp.RotationPolicy.IntervalSeconds,
			NextRotation:    restResp.RotationPolicy.NextRotation,
			RetainVersions:  int32(restResp.RotationPolicy.RetainVersions),
		}
	}

	return result, nil
}

// KeyMetadataUpdate updates key metadata via REST API.
func (r *RESTAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/metadata"
	restReq := resttypes.UpdateKeyMetadataRequest{
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.KeyMetadataResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyMetadataUpdateResult{
		KeyID:     restResp.KeyID,
		Name:      restResp.Name,
		UpdatedAt: restResp.UpdatedAt,
		Tags:      restResp.Tags,
	}, nil
}

// KeyPolicy retrieves key policy via REST API.
func (r *RESTAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/policy"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.KeyPolicyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyPolicyResult{
		KeyID:             restResp.KeyID,
		Version:           int32(restResp.Version),
		AllowedOperations: restResp.AllowedOperations,
		AllowedPrincipals: restResp.AllowedPrincipals,
		DeniedPrincipals:  restResp.DeniedPrincipals,
		ExpiresAt:         restResp.ExpiresAt,
		RotationRequired:  restResp.RotationRequired,
		MaxUsageCount:     restResp.MaxUsageCount,
		RequireMFA:        restResp.RequireMFA,
		UpdatedAt:         restResp.UpdatedAt,
	}, nil
}

// KeyPolicySet sets key policy via REST API.
func (r *RESTAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/policy"
	restReq := resttypes.SetKeyPolicyRequest{
		Operations:       opts.Operations,
		AllowPrincipals:  opts.AllowPrincipals,
		DenyPrincipals:   opts.DenyPrincipals,
		ExpiresIn:        opts.ExpiresIn,
		RotationRequired: opts.RotationRequired,
		MaxUsageCount:    opts.MaxUsageCount,
		RequireMFA:       opts.RequireMFA,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.SetKeyPolicyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         restResp.KeyID,
		PolicyVersion: int32(restResp.PolicyVersion),
		UpdatedAt:     restResp.UpdatedAt,
	}, nil
}

// KeyAlgorithms lists supported algorithms via REST API.
func (r *RESTAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	path := "/api/v1/kms/algorithms"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListAlgorithmsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyAlgorithmsResult{
		Algorithms: restResp.Algorithms,
	}, nil
}

// =============================================================================
// Crypto Commands
// =============================================================================

// CryptoEncrypt encrypts data via REST API.
func (r *RESTAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/encrypt/%s", opts.KeyID)
	// The current REST contract has no separate nonce field: the nonce
	// travels inside the returned ciphertext envelope.
	restReq := resttypes.EncryptRequest{
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.EncryptResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoEncryptResult{
		KeyID:      restResp.KeyID,
		KeyVersion: uint64(restResp.Version),
		Ciphertext: restResp.Ciphertext,
	}, nil
}

// CryptoDecrypt decrypts data via REST API.
func (r *RESTAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/decrypt/%s", opts.KeyID)
	// The nonce is carried inside the ciphertext envelope on the current
	// contract, so opts.Nonce is not sent separately.
	restReq := resttypes.DecryptRequest{
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Version:    int(opts.KeyVersion),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.DecryptResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// The response carries only the plaintext; echo the key coordinates
	// that were used for the request.
	return &CryptoDecryptResult{
		KeyID:      opts.KeyID,
		KeyVersion: opts.KeyVersion,
		Plaintext:  restResp.Plaintext,
	}, nil
}

// CryptoSign signs data via REST API.
func (r *RESTAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/sign/%s", opts.KeyID)
	restReq := resttypes.SignRequest{
		Data: opts.Message,
		Hash: opts.HashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.SignResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoSignResult{
		KeyID:         restResp.KeyID,
		KeyVersion:    uint64(restResp.Version),
		Signature:     restResp.Signature,
		HashAlgorithm: opts.HashAlgorithm,
	}, nil
}

// CryptoVerify verifies a signature via REST API.
func (r *RESTAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/verify/%s", opts.KeyID)
	restReq := resttypes.VerifyRequest{
		Data:      opts.Message,
		Signature: opts.Signature,
		Hash:      opts.HashAlgorithm,
		Version:   int(opts.KeyVersion),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.VerifyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      opts.KeyID,
		KeyVersion: opts.KeyVersion,
		Valid:      restResp.Valid,
	}, nil
}

// CryptoHash computes a cryptographic hash via REST API.
func (r *RESTAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	path := "/api/v1/kms/hash"
	restReq := resttypes.HashRequest{
		Data: data,
		Hash: algorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.HashResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoHashResult{
		Algorithm: restResp.Hash,
		Hash:      restResp.Digest,
	}, nil
}

// CryptoHMAC generates an HMAC via REST API.
func (r *RESTAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/hmac/%s", opts.KeyID)
	restReq := resttypes.HMACRequest{
		Data: opts.Message,
		Hash: opts.HashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.HMACResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoHMACResult{
		KeyID:         restResp.KeyID,
		HMAC:          restResp.HMAC,
		HashAlgorithm: opts.HashAlgorithm,
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC via REST API.
func (r *RESTAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/hmac/%s/verify", opts.KeyID)
	restReq := resttypes.VerifyHMACRequest{
		Data: opts.Message,
		HMAC: opts.HMAC,
		Hash: opts.HashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.VerifyHMACResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoVerifyHMACResult{
		KeyID:      opts.KeyID,
		KeyVersion: opts.KeyVersion,
		Valid:      restResp.Valid,
	}, nil
}

// CryptoRandom generates random bytes via REST API.
func (r *RESTAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	path := "/api/v1/kms/random"
	restReq := resttypes.GenerateRandomRequest{
		NumBytes: numBytes,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GenerateRandomResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoRandomResult{
		RandomBytes: restResp.Bytes,
	}, nil
}

// =============================================================================
// DEK Commands
// =============================================================================

// DEKCreate creates a new DEK via REST API.
func (r *RESTAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	if opts.Path == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	path := "/api/v1/kms/deks"
	// MaxOperations / MaxBytes / WarningPercent are not expressible on the
	// current REST contract; usage limits are managed server-side.
	restReq := resttypes.CreateDEKRequest{
		Path:        opts.Path,
		Algorithm:   opts.Algorithm,
		Description: opts.Description,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.CreateDEKResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToDEKCreateResult(&restResp), nil
}

// DEKGet retrieves DEK metadata via REST API.
func (r *RESTAdapter) DEKGet(ctx context.Context, dekPath string) (*DEKGetResult, error) {
	if dekPath == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	path := "/api/v1/kms/deks/" + dekPath

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.DEKInfoResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToDEKGetResult(&restResp), nil
}

// DEKList lists DEKs via REST API.
func (r *RESTAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	params := url.Values{}
	if opts.Prefix != "" {
		params.Set("prefix", opts.Prefix)
	}
	if opts.Recursive {
		params.Set("recursive", "true")
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/kms/deks"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListDEKsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return r.convertToDEKListResult(&restResp), nil
}

// DEKDelete deletes a DEK via REST API.
func (r *RESTAdapter) DEKDelete(ctx context.Context, dekPath string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	if dekPath == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	params := url.Values{}
	if opts.Force {
		params.Set("force", "true")
	}
	if opts.MigrateTo != "" {
		params.Set("migrate_to", opts.MigrateTo)
	}

	path := "/api/v1/kms/deks/" + dekPath
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// The current contract returns an empty JSON object; a success status
	// means the DEK was deleted.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	return &DEKDeleteResult{
		Path:    dekPath,
		Deleted: true,
	}, nil
}

// DEKRotate rotates a DEK via REST API.
func (r *RESTAdapter) DEKRotate(ctx context.Context, dekPath string, background bool) (*DEKRotateResult, error) {
	if dekPath == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	// The current REST rotate contract takes no request body and responds
	// with {path, new_version} only; background rotation is not
	// expressible on this transport.
	path := "/api/v1/kms/deks/" + dekPath + "/rotate"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateDEKResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// old_version is no longer reported on the wire; versions increment
	// sequentially, so derive it from new_version.
	newVersion := uint64(restResp.NewVersion)
	var oldVersion uint64
	if newVersion > 0 {
		oldVersion = newVersion - 1
	}

	return &DEKRotateResult{
		Path:       restResp.Path,
		OldVersion: oldVersion,
		NewVersion: newVersion,
	}, nil
}

// DEKStatus retrieves DEK status via REST API.
func (r *RESTAdapter) DEKStatus(ctx context.Context, dekPath string) (*DEKStatusResult, error) {
	if dekPath == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	path := "/api/v1/kms/deks/" + dekPath + "/status"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.DEKStatusResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// Description, BackendType, and the re-encryption progress fields are
	// not part of the current DEK status contract.
	return &DEKStatusResult{
		Path:           restResp.Path,
		Algorithm:      restResp.Algorithm,
		Version:        uint64(restResp.Version),
		Status:         restResp.Status,
		IsDefault:      restResp.IsDefault,
		CreatedAt:      restResp.CreatedAt,
		RotatedAt:      restResp.RotatedAt,
		UsageCount:     restResp.UsageCount,
		BytesUsed:      restResp.BytesUsed,
		MaxUsageCount:  restResp.MaxUsageCount,
		MaxBytesUsed:   restResp.MaxBytesUsed,
		WarningPercent: int32(restResp.WarningPercent),
	}, nil
}

// =============================================================================
// Secrets Commands
// =============================================================================

// SecretsStore stores a secret via REST API.
func (r *RESTAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	if opts.Name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	// The current REST contract stores secrets by path with a value
	// payload; TenantID / KeyID / Algorithm are not expressible on this
	// transport (key selection is managed server-side).
	path := "/api/v1/kms/secrets"
	restReq := resttypes.StoreSecretRequest{
		Path:        opts.Name,
		Value:       resttypes.SecretValue(opts.Data),
		Description: opts.Description,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.StoreSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsStoreResult{
		SecretID: restResp.Path,
		Version:  uint64(restResp.Version),
	}, nil
}

// SecretsGet retrieves a secret via REST API.
func (r *RESTAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.SecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// Algorithm / KeyIdentifier are not reported on the current contract;
	// encryption key selection is managed server-side.
	return &SecretsGetResult{
		SecretID:  restResp.Path,
		Version:   uint64(restResp.Version),
		Data:      restResp.Value,
		Metadata:  restResp.Tags,
		CreatedAt: restResp.CreatedAt,
	}, nil
}

// SecretsList lists secrets via REST API.
func (r *RESTAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/kms/secrets"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListSecretsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// The current contract lists secret paths without pagination metadata.
	result := &SecretsListResult{
		TotalCount: int32(len(restResp.Secrets)),
	}

	for _, s := range restResp.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			Name:           s.Path,
			CurrentVersion: uint64(s.Version),
			UpdatedAt:      s.UpdatedAt,
		})
	}

	return result, nil
}

// SecretsDelete deletes a secret via REST API.
func (r *RESTAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	params := url.Values{}
	if permanent {
		params.Set("permanent", "true")
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// The current contract returns an empty JSON object; a success status
	// means the secret was deleted.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	return &SecretsDeleteResult{
		SecretID: name,
		Deleted:  true,
	}, nil
}

// SecretsRotate rotates a secret via REST API.
func (r *RESTAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	if opts.Name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	// TenantID / KeyID / Algorithm are not expressible on the current REST
	// contract; key selection is managed server-side.
	path := "/api/v1/kms/secrets/" + url.PathEscape(opts.Name) + "/rotate"
	restReq := resttypes.RotateSecretRequest{
		Value: opts.NewData,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// old_version is no longer reported on the wire; versions increment
	// sequentially, so derive it from the new version.
	newVersion := uint64(restResp.Version)
	var oldVersion uint64
	if newVersion > 0 {
		oldVersion = newVersion - 1
	}

	return &SecretsRotateResult{
		SecretID:   restResp.Path,
		OldVersion: oldVersion,
		NewVersion: newVersion,
	}, nil
}

// SecretsVersions lists secret versions via REST API.
func (r *RESTAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/versions"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListSecretVersionsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// CreatedBy / ExpiresAt and pagination metadata are not part of the
	// current secret-versions contract.
	result := &SecretsVersionsResult{
		SecretID: name,
	}

	for _, v := range restResp.Versions {
		result.Versions = append(result.Versions, SecretVersionInfo{
			Version:   uint64(v.Version),
			CreatedAt: v.CreatedAt,
		})
	}

	return result, nil
}

// SecretsVersion retrieves a specific secret version via REST API.
func (r *RESTAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/versions/" + strconv.FormatUint(version, 10)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.SecretVersionResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// CreatedBy / ExpiresAt / Metadata are not part of the current
	// secret-version contract.
	return &SecretsVersionResult{
		SecretID:  restResp.Path,
		Version:   uint64(restResp.Version),
		Data:      restResp.Value,
		CreatedAt: restResp.CreatedAt,
	}, nil
}

// SecretsRollback rolls back a secret to a previous version via REST API.
func (r *RESTAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rollback"
	restReq := resttypes.RollbackSecretRequest{
		Version: int(targetVersion),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RollbackSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsRollbackResult{
		SecretID:   restResp.Path,
		NewVersion: uint64(restResp.Version),
	}, nil
}

// SecretsStatus updates secret status via REST API.
func (r *RESTAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/status"
	restReq := resttypes.UpdateSecretStatusRequest{
		Enabled: enabled,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	// The current contract returns an empty JSON object; report the
	// requested state back to the caller on success.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	status := "DISABLED"
	if enabled {
		status = "ENABLED"
	}

	return &SecretsStatusResult{
		SecretID: name,
		Status:   status,
	}, nil
}

// =============================================================================
// Type Conversion Helpers
// =============================================================================

// unixToTime converts a Unix timestamp (seconds) to time.Time.
func unixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// unixToTimePtr converts a Unix timestamp (seconds) to *time.Time.
// Returns nil if the timestamp is zero.
func unixToTimePtr(unix int64) *time.Time {
	if unix == 0 {
		return nil
	}
	t := time.Unix(unix, 0)
	return &t
}

// algorithmStringToKeyAttributes converts an algorithm string to KeyAttributes.
func (r *RESTAdapter) algorithmStringToKeyAttributes(algorithm string) *xkmssdk.KeyAttributes {
	attrs := &xkmssdk.KeyAttributes{}

	switch algorithm {
	case "AES-128-GCM":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES128GCM
	case "AES-192-GCM":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES192GCM
	case "AES-256-GCM":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricAES256GCM
	case "CHACHA20-POLY1305":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricChaCha20Poly1305
	case "XCHACHA20-POLY1305":
		attrs.SymmetricAlgorithm = xkmssdk.SymmetricXChaCha20Poly1305
	case "RSA-2048":
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 2048}
	case "RSA-3072":
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 3072}
	case "RSA-4096":
		attrs.KeyAlgorithm = x509.RSA
		attrs.RSAAttributes = &xkmssdk.RSAAttributes{KeySize: 4096}
	case "ECDSA-P256":
		attrs.KeyAlgorithm = x509.ECDSA
	case "ECDSA-P384":
		attrs.KeyAlgorithm = x509.ECDSA
	case "ECDSA-P521":
		attrs.KeyAlgorithm = x509.ECDSA
	case "ED25519":
		attrs.KeyAlgorithm = x509.Ed25519
	}

	return attrs
}

// purposeToKeyUsage converts a purpose string to KeyUsage slice.
func (r *RESTAdapter) purposeToKeyUsage(purpose string) []service.KeyUsage {
	switch purpose {
	case "encrypt":
		return []service.KeyUsage{service.KeyUsageEncrypt, service.KeyUsageDecrypt}
	case "sign":
		return []service.KeyUsage{service.KeyUsageSign, service.KeyUsageVerify}
	case "mac":
		return []service.KeyUsage{service.KeyUsageGenerateMAC, service.KeyUsageVerifyMAC}
	case "wrap":
		return []service.KeyUsage{service.KeyUsageWrapKey}
	case "derive":
		return []service.KeyUsage{service.KeyUsageDeriveKey}
	default:
		return nil
	}
}

// convertToGenerateKeyRequest maps the domain generate request onto the
// REST wire contract, including the generate-time protection flags now
// carried end-to-end by the QuicBaaS SDK kms client.
func (r *RESTAdapter) convertToGenerateKeyRequest(req *service.GenerateKeyRequest) *resttypes.GenerateKeyRequest {
	restReq := &resttypes.GenerateKeyRequest{
		Name:               req.Name,
		Description:        req.Description,
		Tags:               req.Tags,
		Owner:              req.Owner,
		Usage:              r.keyUsageToStrings(req.Usage),
		Exportable:         req.Exportable,
		DeletionProtection: req.DeletionProtection,
	}

	if req.KeyAttributes != nil {
		restReq.Algorithm = r.keyAttributesToAlgorithmString(req.KeyAttributes)
		restReq.KeySpec = &resttypes.KMSKeySpec{
			Algorithm: restReq.Algorithm,
			KeySize:   int(r.getKeySize(req.KeyAttributes)),
			Usage:     restReq.Usage,
		}
	}

	return restReq
}

// convertToKeyGenerateResult converts REST response to KeyGenerateResult.
func (r *RESTAdapter) convertToKeyGenerateResult(resp *resttypes.GenerateKeyResponse) *KeyGenerateResult {
	return &KeyGenerateResult{
		Exportable:         resp.Exportable,
		DeletionProtection: resp.DeletionProtection,
		KeyID:              resp.KeyID,
		Version:            uint64(resp.Version),
		Algorithm:          resp.Algorithm,
	}
}

// convertToKeyGetResult converts REST response to KeyGetResult. The
// current contract reports created_at and rotated_at; rotation is the
// only update it reports, so rotated_at is surfaced as UpdatedAt.
// Status / Owner / Exportable / DeletionProtection / LastUsedAt are no
// longer part of the wire.
func (r *RESTAdapter) convertToKeyGetResult(resp *resttypes.KeyInfoResponse) *KeyGetResult {
	return &KeyGetResult{
		KeyID:     resp.KeyID,
		Version:   uint64(resp.Version),
		Algorithm: resp.Algorithm,
		Name:      resp.Name,
		Usage:     resp.Usage,
		CreatedAt: resp.CreatedAt,
		UpdatedAt: resp.RotatedAt,
	}
}

// convertToKeyListResult converts REST response to KeyListResult. The
// current contract returns the full key list without pagination
// metadata, so TotalCount is derived from the returned slice.
func (r *RESTAdapter) convertToKeyListResult(resp *resttypes.ListKeysResponse) *KeyListResult {
	result := &KeyListResult{
		TotalCount: int32(len(resp.Keys)),
	}

	for _, k := range resp.Keys {
		result.Keys = append(result.Keys, KeySummary{
			KeyID:     k.KeyID,
			Version:   uint64(k.Version),
			Algorithm: k.Algorithm,
			CreatedAt: k.CreatedAt,
		})
	}

	return result
}

// convertToKeyVersionsResult converts REST response to
// KeyVersionsResult. The current contract does not echo the key ID or
// pagination metadata, so the request key ID is carried through.
func (r *RESTAdapter) convertToKeyVersionsResult(keyID string, resp *resttypes.ListKeyVersionsResponse) *KeyVersionsResult {
	result := &KeyVersionsResult{
		KeyID: keyID,
	}

	for _, v := range resp.Versions {
		result.Versions = append(result.Versions, KeyVersionInfo{
			Version:    uint64(v.Version),
			Algorithm:  v.Algorithm,
			Status:     v.Status,
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	return result
}

// convertToDEKCreateResult converts REST response to DEKCreateResult.
// The current contract returns only path / version / algorithm.
func (r *RESTAdapter) convertToDEKCreateResult(resp *resttypes.CreateDEKResponse) *DEKCreateResult {
	return &DEKCreateResult{
		Path:      resp.Path,
		Algorithm: resp.Algorithm,
		Version:   uint64(resp.Version),
	}
}

// convertToDEKGetResult converts REST response to DEKGetResult. Usage
// limits (MaxUsageCount / MaxBytesUsed / WarningPercent) are reported by
// the DEK status endpoint on the current contract, not by DEK get.
func (r *RESTAdapter) convertToDEKGetResult(resp *resttypes.DEKInfoResponse) *DEKGetResult {
	return &DEKGetResult{
		Path:        resp.Path,
		Algorithm:   resp.Algorithm,
		Version:     uint64(resp.Version),
		Status:      resp.Status,
		IsDefault:   resp.IsDefault,
		CreatedAt:   resp.CreatedAt,
		RotatedAt:   resp.RotatedAt,
		Description: resp.Description,
		BackendType: resp.BackendType,
		UsageCount:  resp.UsageCount,
		BytesUsed:   resp.BytesUsed,
	}
}

// convertToDEKListResult converts REST response to DEKListResult. The
// current contract returns the full DEK list without pagination
// metadata.
func (r *RESTAdapter) convertToDEKListResult(resp *resttypes.ListDEKsResponse) *DEKListResult {
	result := &DEKListResult{}

	for _, d := range resp.DEKs {
		result.DEKs = append(result.DEKs, DEKSummary{
			Path:      d.Path,
			Algorithm: d.Algorithm,
			Version:   uint64(d.Version),
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: d.CreatedAt,
		})
	}

	return result
}

// =============================================================================
// Algorithm Conversion Helpers
// =============================================================================

// keyAttributesToAlgorithmString converts KeyAttributes to REST algorithm string.
func (r *RESTAdapter) keyAttributesToAlgorithmString(attrs *xkmssdk.KeyAttributes) string {
	if attrs == nil {
		return "UNSPECIFIED"
	}

	// Check symmetric algorithms first
	switch attrs.SymmetricAlgorithm {
	case xkmssdk.SymmetricAES128GCM:
		return "AES-128-GCM"
	case xkmssdk.SymmetricAES192GCM:
		return "AES-192-GCM"
	case xkmssdk.SymmetricAES256GCM:
		return "AES-256-GCM"
	case xkmssdk.SymmetricChaCha20Poly1305:
		return "CHACHA20-POLY1305"
	case xkmssdk.SymmetricXChaCha20Poly1305:
		return "XCHACHA20-POLY1305"
	}

	// Check asymmetric algorithms using x509.PublicKeyAlgorithm constants
	switch attrs.KeyAlgorithm {
	case x509.RSA:
		if attrs.RSAAttributes != nil {
			switch attrs.RSAAttributes.KeySize {
			case 2048:
				return "RSA-2048"
			case 3072:
				return "RSA-3072"
			case 4096:
				return "RSA-4096"
			}
		}
		return "RSA-2048"
	case x509.ECDSA:
		if attrs.ECCAttributes != nil && attrs.ECCAttributes.Curve != nil {
			switch attrs.ECCAttributes.Curve.Params().BitSize {
			case 256:
				return "ECDSA-P256"
			case 384:
				return "ECDSA-P384"
			case 521:
				return "ECDSA-P521"
			}
		}
		return "ECDSA-P256"
	case x509.Ed25519:
		return "ED25519"
	}

	return "UNSPECIFIED"
}

// getKeySize extracts key size from KeyAttributes.
func (r *RESTAdapter) getKeySize(attrs *xkmssdk.KeyAttributes) int32 {
	if attrs == nil {
		return 0
	}
	if attrs.RSAAttributes != nil {
		return int32(attrs.RSAAttributes.KeySize)
	}
	return 0
}

// keyUsageToStrings converts service KeyUsage to REST usage strings,
// skipping usages the current wire vocabulary cannot express.
func (r *RESTAdapter) keyUsageToStrings(usages []service.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		if s := r.keyUsageToString(u); s != "" {
			result = append(result, s)
		}
	}
	return result
}

// keyUsageToString converts service KeyUsage to the current REST usage
// vocabulary (ENCRYPT / DECRYPT / SIGN / VERIFY / WRAP / UNWRAP). MAC
// usages map onto SIGN / VERIFY, the closest expressible intent. An
// empty string is returned for usages the wire cannot express so they
// can be filtered out instead of failing server-side validation.
func (r *RESTAdapter) keyUsageToString(usage service.KeyUsage) string {
	switch usage {
	case service.KeyUsageEncrypt:
		return "ENCRYPT"
	case service.KeyUsageDecrypt:
		return "DECRYPT"
	case service.KeyUsageSign, service.KeyUsageGenerateMAC:
		return "SIGN"
	case service.KeyUsageVerify, service.KeyUsageVerifyMAC:
		return "VERIFY"
	case service.KeyUsageWrapKey:
		return "WRAP"
	default:
		return ""
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTConnectionFailed indicates the REST API connection failed.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST API connection failed to %s: %v", e.URL, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRESTUnexpectedStatus indicates an unexpected HTTP status code.
type ErrRESTUnexpectedStatus struct {
	Expected int
	Actual   int
}

func (e ErrRESTUnexpectedStatus) Error() string {
	return fmt.Sprintf("unexpected HTTP status: expected %d, got %d", e.Expected, e.Actual)
}

// ErrRESTMarshalFailed indicates JSON marshaling failed.
type ErrRESTMarshalFailed struct {
	Err error
}

func (e ErrRESTMarshalFailed) Error() string {
	return fmt.Sprintf("failed to marshal request body: %v", e.Err)
}

func (e ErrRESTMarshalFailed) Unwrap() error {
	return e.Err
}

// ErrRESTUnmarshalFailed indicates JSON unmarshaling failed.
type ErrRESTUnmarshalFailed struct {
	Err error
}

func (e ErrRESTUnmarshalFailed) Error() string {
	return fmt.Sprintf("failed to unmarshal response body: %v", e.Err)
}

func (e ErrRESTUnmarshalFailed) Unwrap() error {
	return e.Err
}

// ErrRESTRequestCreationFailed indicates HTTP request creation failed.
type ErrRESTRequestCreationFailed struct {
	Err error
}

func (e ErrRESTRequestCreationFailed) Error() string {
	return fmt.Sprintf("failed to create HTTP request: %v", e.Err)
}

func (e ErrRESTRequestCreationFailed) Unwrap() error {
	return e.Err
}

// ErrRESTRequestFailed indicates the HTTP request failed.
type ErrRESTRequestFailed struct {
	Err error
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("HTTP request failed: %v", e.Err)
}

func (e ErrRESTRequestFailed) Unwrap() error {
	return e.Err
}

// ErrRESTResponseReadFailed indicates reading the response body failed.
type ErrRESTResponseReadFailed struct {
	Err error
}

func (e ErrRESTResponseReadFailed) Error() string {
	return fmt.Sprintf("failed to read response body: %v", e.Err)
}

func (e ErrRESTResponseReadFailed) Unwrap() error {
	return e.Err
}

// ErrRESTAPIError indicates an error response from the REST API.
type ErrRESTAPIError struct {
	StatusCode int
	Message    string
}

func (e ErrRESTAPIError) Error() string {
	return fmt.Sprintf("REST API error (status %d): %s", e.StatusCode, e.Message)
}

// ErrRESTMissingParameter indicates a required parameter is missing.
type ErrRESTMissingParameter struct {
	Parameter string
}

func (e ErrRESTMissingParameter) Error() string {
	return fmt.Sprintf("missing required parameter: %s", e.Parameter)
}
