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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Compile-time interface check
// =============================================================================

var _ KMSCommands = (*RESTAdapter)(nil)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements KMSCommands using HTTP/REST calls to platformd.
// This adapter makes REST API calls to the platformd server for testing
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
		baseURL:    baseURL,
		httpClient: helpers.NewHTTPClient(timeout),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client with base URL from environment or default.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoints := GetServiceEndpoints()
	r.baseURL = helpers.RESTBaseURL(endpoints.PlatformAPI)

	// Check for explicit override via environment variable
	if envURL := os.Getenv("PLATFORM_API_URL"); envURL != "" {
		r.baseURL = helpers.RESTBaseURL(envURL)
	}

	// The REST listener is mTLS: present the runner's client certificate.
	r.httpClient = helpers.NewHTTPClient(30 * time.Second)

	// Verify connectivity by checking backend status
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, daemonKMSStatusPath, nil)
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

	// The body's name is the key ID (docs/kms/api.md §2); the display name
	// follows as key metadata.
	restReq := restapi.KMSGenerateKeyRequest{
		KeySpec:     daemonKeySpec(opts),
		Name:        keyName(opts),
		Description: opts.Description,
		Owner:       opts.Owner,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/keys", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSGenerateKeyResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}
	if restResp.Key == nil {
		return nil, ErrRESTMissingInResponse{Operation: "GenerateKey", Field: "key"}
	}

	result := &KeyGenerateResult{
		KeyID:     restResp.Key.KeyID,
		Version:   restResp.Key.Version,
		Algorithm: daemonAlgorithmName(restResp.Key.Algorithm),
		Status:    daemonStatusName(restResp.Key.Status),
		CreatedAt: grpcUnixToTime(restResp.Key.CreatedAt),
	}
	if md := restResp.Metadata; md != nil {
		result.Name = md.Name
		result.Description = md.Description
		result.Exportable = md.Exportable
		result.DeletionProtection = md.DeletionProtection
	}
	if err := applyKeyDisplay(ctx, r, opts, result); err != nil {
		return nil, err
	}
	return result, nil
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

	var restResp restapi.KMSGetKeyResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}
	if restResp.Key == nil {
		return nil, ErrRESTMissingInResponse{Operation: "GetKey", Field: "key"}
	}

	result := &KeyGetResult{
		KeyID:     restResp.Key.KeyID,
		Version:   restResp.Key.Version,
		Algorithm: daemonAlgorithmName(restResp.Key.Algorithm),
		Status:    daemonStatusName(restResp.Key.Status),
		CreatedAt: grpcUnixToTime(restResp.Key.CreatedAt),
	}
	if md := restResp.Metadata; md != nil {
		result.UpdatedAt = grpcUnixToTime(md.UpdatedAt)
		result.LastUsedAt = grpcUnixToTime(md.LastUsedAt)
		result.Name = md.Name
		result.Description = md.Description
		result.Owner = md.Owner
		result.Exportable = md.Exportable
		result.DeletionProtection = md.DeletionProtection
		result.Usage = daemonUsageNames(md.Usage)
	}
	return result, nil
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

	var restResp restapi.KMSListKeysResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	keys := make([]KeySummary, 0, len(restResp.Keys))
	for _, k := range restResp.Keys {
		keys = append(keys, KeySummary{
			KeyID:     k.KeyID,
			Version:   k.Version,
			Algorithm: daemonAlgorithmName(k.Algorithm),
			Status:    daemonStatusName(k.Status),
			CreatedAt: grpcUnixToTime(k.CreatedAt),
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: restResp.TotalCount,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}, nil
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

	var restResp restapi.KMSDeleteKeyResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID:        restResp.KeyID,
		Status:       daemonStatusName(restResp.Status),
		DeletionDate: grpcUnixToTime(restResp.DeletionDate),
	}, nil
}

// KeyRotate rotates an existing key via REST API.
func (r *RESTAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	if keyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	path := "/api/v1/kms/keys/" + url.PathEscape(keyID) + "/rotate"
	restReq := restapi.KMSRotateKeyRequest{RetainOldVersion: retainOldVersion}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSRotateKeyResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      restResp.KeyID,
		OldVersion: restResp.OldVersion,
		NewVersion: restResp.NewVersion,
		RotatedAt:  grpcUnixToTime(restResp.Timestamp),
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

	var restResp restapi.KMSGetKeyVersionsResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	versions := make([]KeyVersionInfo, 0, len(restResp.Versions))
	for _, v := range restResp.Versions {
		versions = append(versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  daemonAlgorithmName(v.Algorithm),
			Status:     daemonStatusName(v.Status),
			CreatedAt:  grpcUnixToTime(v.CreatedAt),
			DisabledAt: grpcUnixToTime(v.DisabledAt),
		})
	}

	return &KeyVersionsResult{
		KeyID:      restResp.KeyID,
		Versions:   versions,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}, nil
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

	restReq := restapi.KMSEncryptRequest{
		KeyID:     opts.KeyID,
		Plaintext: base64.StdEncoding.EncodeToString(opts.Plaintext),
		Context:   encodeOptionalBytes(opts.Context),
		Nonce:     encodeOptionalBytes(opts.Nonce),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/encrypt", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSEncryptResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	ciphertext, err := decodeBytes(restResp.Ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeBytes(restResp.Nonce)
	if err != nil {
		return nil, err
	}

	return &CryptoEncryptResult{
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Timestamp:  grpcUnixToTime(restResp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts data via REST API.
func (r *RESTAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	restReq := restapi.KMSDecryptRequest{
		KeyID:      opts.KeyID,
		Ciphertext: base64.StdEncoding.EncodeToString(opts.Ciphertext),
		Context:    encodeOptionalBytes(opts.Context),
		Nonce:      encodeOptionalBytes(opts.Nonce),
		KeyVersion: opts.KeyVersion,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/decrypt", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSDecryptResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	plaintext, err := decodeBytes(restResp.Plaintext)
	if err != nil {
		return nil, err
	}

	return &CryptoDecryptResult{
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Plaintext:  plaintext,
		Timestamp:  grpcUnixToTime(restResp.Timestamp),
	}, nil
}

// CryptoSign signs data via REST API.
func (r *RESTAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	hashAlgorithm, err := daemonHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	restReq := restapi.KMSSignRequest{
		KeyID:         opts.KeyID,
		Message:       base64.StdEncoding.EncodeToString(opts.Message),
		HashAlgorithm: hashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/sign", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSSignResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	signature, err := decodeBytes(restResp.Signature)
	if err != nil {
		return nil, err
	}

	return &CryptoSignResult{
		KeyID:         restResp.KeyID,
		KeyVersion:    restResp.KeyVersion,
		Signature:     signature,
		HashAlgorithm: daemonHashName(restResp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(restResp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature via REST API.
func (r *RESTAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	hashAlgorithm, err := daemonHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	restReq := restapi.KMSVerifyRequest{
		KeyID:         opts.KeyID,
		Message:       base64.StdEncoding.EncodeToString(opts.Message),
		Signature:     base64.StdEncoding.EncodeToString(opts.Signature),
		HashAlgorithm: hashAlgorithm,
		KeyVersion:    opts.KeyVersion,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/verify", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSVerifyResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      restResp.KeyID,
		KeyVersion: restResp.KeyVersion,
		Valid:      restResp.Valid,
		Timestamp:  grpcUnixToTime(restResp.Timestamp),
	}, nil
}

// CryptoHash computes a cryptographic hash via REST API.
func (r *RESTAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	hashAlgorithm, err := daemonHashAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	restReq := restapi.KMSHashRequest{
		Data:      base64.StdEncoding.EncodeToString(data),
		Algorithm: hashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/hash", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSHashResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	hash, err := decodeBytes(restResp.Hash)
	if err != nil {
		return nil, err
	}

	return &CryptoHashResult{
		Algorithm: daemonHashName(restResp.Algorithm),
		Hash:      hash,
		Timestamp: grpcUnixToTime(restResp.Timestamp),
	}, nil
}

// CryptoHMAC generates an HMAC via REST API.
func (r *RESTAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	if opts.KeyID == "" {
		return nil, ErrRESTMissingParameter{Parameter: "key_id"}
	}

	hashAlgorithm, err := daemonHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	restReq := restapi.KMSHMACRequest{
		KeyID:         opts.KeyID,
		Message:       base64.StdEncoding.EncodeToString(opts.Message),
		HashAlgorithm: hashAlgorithm,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/hmac", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSHMACResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	mac, err := decodeBytes(restResp.HMAC)
	if err != nil {
		return nil, err
	}

	return &CryptoHMACResult{
		KeyID:         restResp.KeyID,
		KeyVersion:    restResp.KeyVersion,
		HMAC:          mac,
		HashAlgorithm: daemonHashName(restResp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(restResp.Timestamp),
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
	restReq := restapi.KMSRandomRequest{
		NumBytes: int32(numBytes),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/kms/random", restReq)
	if err != nil {
		return nil, err
	}

	var restResp restapi.KMSRandomResponse
	if err := r.handleDaemonResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	randomBytes, err := decodeBytes(restResp.RandomBytes)
	if err != nil {
		return nil, err
	}

	return &CryptoRandomResult{
		RandomBytes: randomBytes,
		Timestamp:   grpcUnixToTime(restResp.Timestamp),
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

// algorithmStringToKeyAttributes converts an algorithm string to KeyAttributes.
// purposeToKeyUsage converts a purpose string to KeyUsage slice.
// convertToGenerateKeyRequest maps the domain generate request onto the
// REST wire contract, including the generate-time protection flags now
// carried end-to-end by the QuicBaaS SDK kms client.
// convertToKeyGenerateResult converts REST response to KeyGenerateResult.
// convertToKeyGetResult converts REST response to KeyGetResult. The
// current contract reports created_at and rotated_at; rotation is the
// only update it reports, so rotated_at is surfaced as UpdatedAt.
// Status / Owner / Exportable / DeletionProtection / LastUsedAt are no
// longer part of the wire.
// convertToKeyListResult converts REST response to KeyListResult. The
// current contract returns the full key list without pagination
// metadata, so TotalCount is derived from the returned slice.
// convertToKeyVersionsResult converts REST response to
// KeyVersionsResult. The current contract does not echo the key ID or
// pagination metadata, so the request key ID is carried through.
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
// getKeySize extracts key size from KeyAttributes.
// keyUsageToStrings converts service KeyUsage to REST usage strings,
// skipping usages the current wire vocabulary cannot express.
// keyUsageToString converts service KeyUsage to the current REST usage
// vocabulary (ENCRYPT / DECRYPT / SIGN / VERIFY / WRAP / UNWRAP). MAC
// usages map onto SIGN / VERIFY, the closest expressible intent. An
// empty string is returned for usages the wire cannot express so they
// can be filtered out instead of failing server-side validation.
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
