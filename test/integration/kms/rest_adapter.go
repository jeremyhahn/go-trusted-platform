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
	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
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

// handleResponse processes the HTTP response and unmarshals into the target.
func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrRESTUnmarshalFailed{Err: err}
		}
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

	var restResp resttypes.GetKeyResponse
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

	var restResp resttypes.DeleteKeyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID:        restResp.KeyID,
		Status:       restResp.Status,
		DeletionDate: unixToTime(restResp.DeletionDate),
	}, nil
}

// KeyRotate rotates an existing key via REST API.
func (r *RESTAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/rotate"
	restReq := resttypes.RotateKeyRequest{
		RetainOldVersion: retainOldVersion,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateKeyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      restResp.KeyID,
		OldVersion: restResp.OldVersion,
		NewVersion: restResp.NewVersion,
		RotatedAt:  unixToTime(restResp.Timestamp),
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

	return r.convertToKeyVersionsResult(&restResp), nil
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
		Version: version,
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
		KeyID:     restResp.KeyID,
		Version:   restResp.Version,
		Status:    restResp.Status,
		UpdatedAt: unixToTime(restResp.Timestamp),
	}, nil
}

// KeyRevoke revokes a key via REST API.
func (r *RESTAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/revoke"
	restReq := struct {
		Reason string `json:"reason,omitempty"`
	}{
		Reason: reason,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		KeyID     string `json:"key_id"`
		Status    string `json:"status"`
		RevokedAt int64  `json:"revoked_at"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     restResp.KeyID,
		Status:    restResp.Status,
		RevokedAt: unixToTime(restResp.RevokedAt),
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

	var restResp struct {
		KeyID              string            `json:"key_id"`
		Name               string            `json:"name"`
		Description        string            `json:"description"`
		Algorithm          string            `json:"algorithm"`
		Status             string            `json:"status"`
		Version            uint64            `json:"version"`
		Exportable         bool              `json:"exportable"`
		DeletionProtection bool              `json:"deletion_protection"`
		Usage              []string          `json:"usage"`
		Owner              string            `json:"owner"`
		CreatedAt          int64             `json:"created_at"`
		UpdatedAt          int64             `json:"updated_at"`
		LastUsedAt         int64             `json:"last_used_at"`
		Tags               map[string]string `json:"tags"`
		RotationPolicy     *struct {
			Enabled         bool  `json:"enabled"`
			IntervalSeconds int64 `json:"interval_seconds"`
			NextRotation    int64 `json:"next_rotation"`
			RetainVersions  int32 `json:"retain_versions"`
		} `json:"rotation_policy,omitempty"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &KeyMetadataResult{
		KeyID:              restResp.KeyID,
		Name:               restResp.Name,
		Description:        restResp.Description,
		Algorithm:          restResp.Algorithm,
		Status:             restResp.Status,
		Version:            restResp.Version,
		Exportable:         restResp.Exportable,
		DeletionProtection: restResp.DeletionProtection,
		Usage:              restResp.Usage,
		Owner:              restResp.Owner,
		CreatedAt:          unixToTime(restResp.CreatedAt),
		UpdatedAt:          unixToTime(restResp.UpdatedAt),
		LastUsedAt:         unixToTime(restResp.LastUsedAt),
		Tags:               restResp.Tags,
	}

	if restResp.RotationPolicy != nil {
		result.RotationPolicy = &RotationPolicy{
			Enabled:         restResp.RotationPolicy.Enabled,
			IntervalSeconds: restResp.RotationPolicy.IntervalSeconds,
			NextRotation:    unixToTime(restResp.RotationPolicy.NextRotation),
			RetainVersions:  restResp.RotationPolicy.RetainVersions,
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
	restReq := struct {
		Name        string            `json:"name,omitempty"`
		Description string            `json:"description,omitempty"`
		Tags        map[string]string `json:"tags,omitempty"`
		RemoveTags  []string          `json:"remove_tags,omitempty"`
	}{
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		KeyID     string            `json:"key_id"`
		Name      string            `json:"name"`
		UpdatedAt int64             `json:"updated_at"`
		Tags      map[string]string `json:"tags"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyMetadataUpdateResult{
		KeyID:     restResp.KeyID,
		Name:      restResp.Name,
		UpdatedAt: unixToTime(restResp.UpdatedAt),
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

	var restResp struct {
		KeyID             string   `json:"key_id"`
		Version           int32    `json:"version"`
		AllowedOperations []string `json:"allowed_operations"`
		AllowedPrincipals []string `json:"allowed_principals"`
		DeniedPrincipals  []string `json:"denied_principals"`
		ExpiresAt         int64    `json:"expires_at"`
		RotationRequired  bool     `json:"rotation_required"`
		MaxUsageCount     uint64   `json:"max_usage_count"`
		RequireMFA        bool     `json:"require_mfa"`
		UpdatedAt         int64    `json:"updated_at"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyPolicyResult{
		KeyID:             restResp.KeyID,
		Version:           restResp.Version,
		AllowedOperations: restResp.AllowedOperations,
		AllowedPrincipals: restResp.AllowedPrincipals,
		DeniedPrincipals:  restResp.DeniedPrincipals,
		ExpiresAt:         unixToTime(restResp.ExpiresAt),
		RotationRequired:  restResp.RotationRequired,
		MaxUsageCount:     restResp.MaxUsageCount,
		RequireMFA:        restResp.RequireMFA,
		UpdatedAt:         unixToTime(restResp.UpdatedAt),
	}, nil
}

// KeyPolicySet sets key policy via REST API.
func (r *RESTAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/policy"
	restReq := struct {
		Operations       []string `json:"operations,omitempty"`
		AllowPrincipals  []string `json:"allow_principals,omitempty"`
		DenyPrincipals   []string `json:"deny_principals,omitempty"`
		ExpiresIn        string   `json:"expires_in,omitempty"`
		RotationRequired bool     `json:"rotation_required,omitempty"`
		MaxUsageCount    uint64   `json:"max_usage_count,omitempty"`
		RequireMFA       bool     `json:"require_mfa,omitempty"`
	}{
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

	var restResp struct {
		KeyID         string `json:"key_id"`
		PolicyVersion int32  `json:"policy_version"`
		UpdatedAt     int64  `json:"updated_at"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         restResp.KeyID,
		PolicyVersion: restResp.PolicyVersion,
		UpdatedAt:     unixToTime(restResp.UpdatedAt),
	}, nil
}

// KeyAlgorithms lists supported algorithms via REST API.
func (r *RESTAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	path := "/api/v1/kms/algorithms"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		Algorithms []string `json:"algorithms"`
	}
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
	restReq := resttypes.EncryptRequest{
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
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
		KeyVersion: restResp.KeyVersion,
		Ciphertext: restResp.Ciphertext,
		Nonce:      restResp.Nonce,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts data via REST API.
func (r *RESTAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/decrypt/%s", opts.KeyID)
	restReq := resttypes.DecryptRequest{
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.DecryptResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoDecryptResult{
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Plaintext:  restResp.Plaintext,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoSign signs data via REST API.
func (r *RESTAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/sign/%s", opts.KeyID)
	restReq := resttypes.SignRequest{
		Message:       opts.Message,
		HashAlgorithm: opts.HashAlgorithm,
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
		KeyVersion:    restResp.KeyVersion,
		Signature:     restResp.Signature,
		HashAlgorithm: restResp.HashAlgorithm,
		Timestamp:     unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature via REST API.
func (r *RESTAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/verify/%s", opts.KeyID)
	restReq := resttypes.VerifyRequest{
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: opts.HashAlgorithm,
		KeyVersion:    opts.KeyVersion,
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
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Valid:      restResp.Valid,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoHash computes a cryptographic hash via REST API.
func (r *RESTAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	path := "/api/v1/kms/crypto/hash"
	restReq := resttypes.HashRequest{
		Data:      data,
		Algorithm: algorithm,
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
		Algorithm: restResp.Algorithm,
		Hash:      restResp.Hash,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoHMAC generates an HMAC via REST API.
func (r *RESTAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/hmac/%s", opts.KeyID)
	restReq := resttypes.HMACRequest{
		Message:       opts.Message,
		HashAlgorithm: opts.HashAlgorithm,
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
		KeyVersion:    restResp.KeyVersion,
		HMAC:          restResp.HMAC,
		HashAlgorithm: restResp.HashAlgorithm,
		Timestamp:     unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC via REST API.
func (r *RESTAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := fmt.Sprintf("/api/v1/kms/hmac/%s/verify", opts.KeyID)
	restReq := resttypes.VerifyHMACRequest{
		Message:       opts.Message,
		HMAC:          opts.HMAC,
		HashAlgorithm: opts.HashAlgorithm,
		KeyVersion:    opts.KeyVersion,
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
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Valid:      restResp.Valid,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// CryptoRandom generates random bytes via REST API.
func (r *RESTAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	path := "/api/v1/kms/crypto/random"
	restReq := resttypes.GenerateRandomRequest{
		NumBytes: int32(numBytes),
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
		RandomBytes: restResp.RandomBytes,
		Timestamp:   unixToTime(restResp.Timestamp),
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
	restReq := resttypes.CreateDEKRequest{
		Path:           opts.Path,
		Algorithm:      opts.Algorithm,
		Description:    opts.Description,
		MaxOperations:  opts.MaxOperations,
		MaxBytes:       opts.MaxBytes,
		WarningPercent: opts.WarningPercent,
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

	var restResp resttypes.GetDEKResponse
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

	var restResp resttypes.DeleteDEKResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &DEKDeleteResult{
		Path:    restResp.Path,
		Deleted: restResp.Deleted,
	}, nil
}

// DEKRotate rotates a DEK via REST API.
func (r *RESTAdapter) DEKRotate(ctx context.Context, dekPath string, background bool) (*DEKRotateResult, error) {
	if dekPath == "" {
		return nil, ErrRESTMissingParameter{Parameter: "path"}
	}

	path := "/api/v1/kms/deks/" + dekPath + "/rotate"
	restReq := resttypes.RotateDEKRequest{
		Background: background,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateDEKResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &DEKRotateResult{
		Path:       restResp.Path,
		OldVersion: restResp.OldVersion,
		NewVersion: restResp.NewVersion,
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

	var restResp struct {
		Path                   string `json:"path"`
		Algorithm              string `json:"algorithm"`
		Version                uint64 `json:"version"`
		Status                 string `json:"status"`
		IsDefault              bool   `json:"is_default"`
		CreatedAt              int64  `json:"created_at"`
		RotatedAt              int64  `json:"rotated_at"`
		Description            string `json:"description"`
		BackendType            string `json:"backend_type"`
		UsageCount             uint64 `json:"usage_count"`
		BytesUsed              uint64 `json:"bytes_used"`
		MaxUsageCount          uint64 `json:"max_usage_count"`
		MaxBytesUsed           uint64 `json:"max_bytes_used"`
		WarningPercent         int32  `json:"warning_percent"`
		ReencryptionInProgress bool   `json:"reencryption_in_progress"`
		ProcessedKeys          int64  `json:"processed_keys"`
		TotalKeys              int64  `json:"total_keys"`
		FailedKeys             int64  `json:"failed_keys"`
		ReencryptionStartedAt  int64  `json:"reencryption_started_at"`
		EstimatedCompletion    int64  `json:"estimated_completion"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &DEKStatusResult{
		Path:                   restResp.Path,
		Algorithm:              restResp.Algorithm,
		Version:                restResp.Version,
		Status:                 restResp.Status,
		IsDefault:              restResp.IsDefault,
		CreatedAt:              unixToTime(restResp.CreatedAt),
		RotatedAt:              unixToTime(restResp.RotatedAt),
		Description:            restResp.Description,
		BackendType:            restResp.BackendType,
		UsageCount:             restResp.UsageCount,
		BytesUsed:              restResp.BytesUsed,
		MaxUsageCount:          restResp.MaxUsageCount,
		MaxBytesUsed:           restResp.MaxBytesUsed,
		WarningPercent:         restResp.WarningPercent,
		ReencryptionInProgress: restResp.ReencryptionInProgress,
		ProcessedKeys:          restResp.ProcessedKeys,
		TotalKeys:              restResp.TotalKeys,
		FailedKeys:             restResp.FailedKeys,
		ReencryptionStartedAt:  unixToTime(restResp.ReencryptionStartedAt),
		EstimatedCompletion:    unixToTime(restResp.EstimatedCompletion),
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

	path := "/api/v1/kms/secrets"
	restReq := struct {
		Name        string `json:"name"`
		Data        []byte `json:"data"`
		Description string `json:"description,omitempty"`
		TenantID    string `json:"tenant_id,omitempty"`
		KeyID       string `json:"key_id,omitempty"`
		Algorithm   string `json:"algorithm,omitempty"`
	}{
		Name:        opts.Name,
		Data:        opts.Data,
		Description: opts.Description,
		TenantID:    opts.TenantID,
		KeyID:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		SecretID  string `json:"secret_id"`
		Version   uint64 `json:"version"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsStoreResult{
		SecretID:  restResp.SecretID,
		Version:   restResp.Version,
		Timestamp: unixToTime(restResp.Timestamp),
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

	var restResp struct {
		SecretID      string            `json:"secret_id"`
		Version       uint64            `json:"version"`
		Data          []byte            `json:"data"`
		Metadata      map[string]string `json:"metadata"`
		Algorithm     string            `json:"algorithm"`
		KeyIdentifier string            `json:"key_identifier"`
		CreatedAt     int64             `json:"created_at"`
		Timestamp     int64             `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsGetResult{
		SecretID:      restResp.SecretID,
		Version:       restResp.Version,
		Data:          restResp.Data,
		Metadata:      restResp.Metadata,
		Algorithm:     restResp.Algorithm,
		KeyIdentifier: restResp.KeyIdentifier,
		CreatedAt:     unixToTime(restResp.CreatedAt),
		Timestamp:     unixToTime(restResp.Timestamp),
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

	var restResp struct {
		Secrets []struct {
			Name           string `json:"name"`
			CurrentVersion uint64 `json:"current_version"`
			Description    string `json:"description"`
			Owner          string `json:"owner"`
			CreatedAt      int64  `json:"created_at"`
			UpdatedAt      int64  `json:"updated_at"`
		} `json:"secrets"`
		TotalCount int32  `json:"total_count"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &SecretsListResult{
		TotalCount: restResp.TotalCount,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}

	for _, s := range restResp.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      unixToTime(s.CreatedAt),
			UpdatedAt:      unixToTime(s.UpdatedAt),
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

	var restResp struct {
		SecretID  string `json:"secret_id"`
		Deleted   bool   `json:"deleted"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsDeleteResult{
		SecretID:  restResp.SecretID,
		Deleted:   restResp.Deleted,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// SecretsRotate rotates a secret via REST API.
func (r *RESTAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	if opts.Name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(opts.Name) + "/rotate"
	restReq := struct {
		NewData   []byte `json:"new_data"`
		TenantID  string `json:"tenant_id,omitempty"`
		KeyID     string `json:"key_id,omitempty"`
		Algorithm string `json:"algorithm,omitempty"`
	}{
		NewData:   opts.NewData,
		TenantID:  opts.TenantID,
		KeyID:     opts.KeyID,
		Algorithm: opts.Algorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		SecretID   string `json:"secret_id"`
		OldVersion uint64 `json:"old_version"`
		NewVersion uint64 `json:"new_version"`
		Timestamp  int64  `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsRotateResult{
		SecretID:   restResp.SecretID,
		OldVersion: restResp.OldVersion,
		NewVersion: restResp.NewVersion,
		Timestamp:  unixToTime(restResp.Timestamp),
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

	var restResp struct {
		SecretID string `json:"secret_id"`
		Versions []struct {
			Version   uint64 `json:"version"`
			CreatedAt int64  `json:"created_at"`
			CreatedBy string `json:"created_by"`
			ExpiresAt int64  `json:"expires_at"`
		} `json:"versions"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &SecretsVersionsResult{
		SecretID:   restResp.SecretID,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}

	for _, v := range restResp.Versions {
		result.Versions = append(result.Versions, SecretVersionInfo{
			Version:   v.Version,
			CreatedAt: unixToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: unixToTime(v.ExpiresAt),
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

	var restResp struct {
		SecretID  string            `json:"secret_id"`
		Version   uint64            `json:"version"`
		Data      []byte            `json:"data"`
		Metadata  map[string]string `json:"metadata"`
		CreatedAt int64             `json:"created_at"`
		CreatedBy string            `json:"created_by"`
		ExpiresAt int64             `json:"expires_at"`
		Timestamp int64             `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsVersionResult{
		SecretID:  restResp.SecretID,
		Version:   restResp.Version,
		Data:      restResp.Data,
		Metadata:  restResp.Metadata,
		CreatedAt: unixToTime(restResp.CreatedAt),
		CreatedBy: restResp.CreatedBy,
		ExpiresAt: unixToTime(restResp.ExpiresAt),
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// SecretsRollback rolls back a secret to a previous version via REST API.
func (r *RESTAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rollback"
	restReq := struct {
		TargetVersion uint64 `json:"target_version"`
	}{
		TargetVersion: targetVersion,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		SecretID   string `json:"secret_id"`
		NewVersion uint64 `json:"new_version"`
		Timestamp  int64  `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsRollbackResult{
		SecretID:   restResp.SecretID,
		NewVersion: restResp.NewVersion,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// SecretsStatus updates secret status via REST API.
func (r *RESTAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	if name == "" {
		return nil, ErrRESTMissingParameter{Parameter: "name"}
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/status"
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	restReq := struct {
		Status string `json:"status"`
	}{
		Status: status,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp struct {
		SecretID  string `json:"secret_id"`
		Status    string `json:"status"`
		Timestamp int64  `json:"timestamp"`
	}
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &SecretsStatusResult{
		SecretID:  restResp.SecretID,
		Status:    restResp.Status,
		Timestamp: unixToTime(restResp.Timestamp),
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

// convertToGenerateKeyRequest converts service request to REST request.
func (r *RESTAdapter) convertToGenerateKeyRequest(req *service.GenerateKeyRequest) *resttypes.GenerateKeyRequest {
	restReq := &resttypes.GenerateKeyRequest{
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Owner:       req.Owner,
	}

	if req.KeyAttributes != nil {
		restReq.KeySpec = resttypes.KeySpecRequest{
			Algorithm:          r.keyAttributesToAlgorithmString(req.KeyAttributes),
			KeySize:            r.getKeySize(req.KeyAttributes),
			Usage:              r.keyUsageToStrings(req.Usage),
			Exportable:         req.Exportable,
			DeletionProtection: req.DeletionProtection,
		}
	}

	return restReq
}

// convertToKeyGenerateResult converts REST response to KeyGenerateResult.
func (r *RESTAdapter) convertToKeyGenerateResult(resp *resttypes.GenerateKeyResponse) *KeyGenerateResult {
	result := &KeyGenerateResult{}
	if resp.Key != nil {
		result.KeyID = resp.Key.KeyID
		result.Version = resp.Key.Version
		result.Algorithm = resp.Key.Algorithm
		result.Status = resp.Key.Status
		result.CreatedAt = unixToTime(resp.Key.CreatedAt)
	}
	if resp.Metadata != nil {
		result.Name = resp.Metadata.Name
		result.Description = resp.Metadata.Description
		result.Exportable = resp.Metadata.Exportable
		result.DeletionProtection = resp.Metadata.DeletionProtection
	}
	return result
}

// convertToKeyGetResult converts REST response to KeyGetResult.
func (r *RESTAdapter) convertToKeyGetResult(resp *resttypes.GetKeyResponse) *KeyGetResult {
	result := &KeyGetResult{}
	if resp.Key != nil {
		result.KeyID = resp.Key.KeyID
		result.Version = resp.Key.Version
		result.Algorithm = resp.Key.Algorithm
		result.Status = resp.Key.Status
		result.CreatedAt = unixToTime(resp.Key.CreatedAt)
	}
	if resp.Metadata != nil {
		result.Name = resp.Metadata.Name
		result.Description = resp.Metadata.Description
		result.Owner = resp.Metadata.Owner
		result.Exportable = resp.Metadata.Exportable
		result.DeletionProtection = resp.Metadata.DeletionProtection
		result.Usage = resp.Metadata.Usage
		result.UpdatedAt = unixToTime(resp.Metadata.UpdatedAt)
		result.LastUsedAt = unixToTime(resp.Metadata.LastUsedAt)
	}
	return result
}

// convertToKeyListResult converts REST response to KeyListResult.
func (r *RESTAdapter) convertToKeyListResult(resp *resttypes.ListKeysResponse) *KeyListResult {
	result := &KeyListResult{
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}

	for _, k := range resp.Keys {
		result.Keys = append(result.Keys, KeySummary{
			KeyID:     k.KeyID,
			Version:   k.Version,
			Algorithm: k.Algorithm,
			Status:    k.Status,
			CreatedAt: unixToTime(k.CreatedAt),
		})
	}

	return result
}

// convertToKeyVersionsResult converts REST response to KeyVersionsResult.
func (r *RESTAdapter) convertToKeyVersionsResult(resp *resttypes.ListKeyVersionsResponse) *KeyVersionsResult {
	result := &KeyVersionsResult{
		KeyID:      resp.KeyID,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}

	for _, v := range resp.Versions {
		result.Versions = append(result.Versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  v.Algorithm,
			Status:     v.Status,
			CreatedAt:  unixToTime(v.CreatedAt),
			DisabledAt: unixToTime(v.DisabledAt),
		})
	}

	return result
}

// convertToDEKCreateResult converts REST response to DEKCreateResult.
func (r *RESTAdapter) convertToDEKCreateResult(resp *resttypes.CreateDEKResponse) *DEKCreateResult {
	result := &DEKCreateResult{}
	if resp.DEK != nil {
		result.Path = resp.DEK.Path
		result.Algorithm = resp.DEK.Algorithm
		result.Version = resp.DEK.Version
		result.CreatedAt = unixToTime(resp.DEK.CreatedAt)
		result.Description = resp.DEK.Description
	}
	return result
}

// convertToDEKGetResult converts REST response to DEKGetResult.
func (r *RESTAdapter) convertToDEKGetResult(resp *resttypes.GetDEKResponse) *DEKGetResult {
	result := &DEKGetResult{}
	if resp.DEK != nil {
		result.Path = resp.DEK.Path
		result.Algorithm = resp.DEK.Algorithm
		result.Version = resp.DEK.Version
		result.Status = resp.DEK.Status
		result.IsDefault = resp.DEK.IsDefault
		result.CreatedAt = unixToTime(resp.DEK.CreatedAt)
		result.RotatedAt = unixToTime(resp.DEK.RotatedAt)
		result.Description = resp.DEK.Description
		result.BackendType = resp.DEK.BackendType
		result.UsageCount = resp.DEK.UsageCount
		result.BytesUsed = resp.DEK.BytesUsed
		result.MaxUsageCount = resp.DEK.MaxUsageCount
		result.MaxBytesUsed = resp.DEK.MaxBytesUsed
		result.WarningPercent = int32(resp.DEK.WarningPercent)
	}
	return result
}

// convertToDEKListResult converts REST response to DEKListResult.
func (r *RESTAdapter) convertToDEKListResult(resp *resttypes.ListDEKsResponse) *DEKListResult {
	result := &DEKListResult{
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}

	for _, d := range resp.DEKs {
		result.DEKs = append(result.DEKs, DEKSummary{
			Path:      d.Path,
			Algorithm: d.Algorithm,
			Version:   d.Version,
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: unixToTime(d.CreatedAt),
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

// keyUsageToStrings converts service KeyUsage to REST usage strings.
func (r *RESTAdapter) keyUsageToStrings(usages []service.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		result = append(result, r.keyUsageToString(u))
	}
	return result
}

// keyUsageToString converts service KeyUsage to REST usage string.
func (r *RESTAdapter) keyUsageToString(usage service.KeyUsage) string {
	switch usage {
	case service.KeyUsageEncrypt:
		return "ENCRYPT"
	case service.KeyUsageDecrypt:
		return "DECRYPT"
	case service.KeyUsageSign:
		return "SIGN"
	case service.KeyUsageVerify:
		return "VERIFY"
	case service.KeyUsageWrapKey:
		return "WRAP_KEY"
	case service.KeyUsageDeriveKey:
		return "DERIVE_KEY"
	case service.KeyUsageGenerateMAC:
		return "GENERATE_MAC"
	case service.KeyUsageVerifyMAC:
		return "VERIFY_MAC"
	default:
		return "UNSPECIFIED"
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
