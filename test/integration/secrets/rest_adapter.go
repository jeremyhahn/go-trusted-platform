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

package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	resttypes "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
)

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements SecretsCommands using HTTP/REST calls to platform-api.
// This adapter makes REST API calls to the platform-api server for testing
// the REST transport layer consistency with other protocol adapters.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// NewRESTAdapterWithConfig creates a REST adapter with explicit configuration.
func NewRESTAdapterWithConfig(baseURL string, client *http.Client) *RESTAdapter {
	return &RESTAdapter{
		baseURL:    baseURL,
		httpClient: client,
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

	// Verify connectivity by checking a basic endpoint
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
// Time Conversion Helpers
// =============================================================================

// unixToTime converts a Unix timestamp (seconds) to time.Time.
func unixToTime(unix int64) time.Time {
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// Store stores a new secret via REST API.
func (r *RESTAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	path := "/api/v1/kms/secrets"
	restReq := resttypes.StoreSecretRequest{
		Name:        opts.Name,
		Description: opts.Description,
		Data:        opts.Data,
		Metadata:    opts.Metadata,
		Tags:        opts.Tags,
		TenantID:    opts.TenantID,
		KeyID:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}
	if !opts.ExpiresAt.IsZero() {
		restReq.ExpiresAt = opts.ExpiresAt.Unix()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.StoreSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &StoreResult{
		SecretID:  restResp.SecretID,
		Version:   restResp.Version,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// Get retrieves a secret via REST API.
func (r *RESTAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GetSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &GetResult{
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

// List lists secrets via REST API.
func (r *RESTAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
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

	result := &ListResult{
		TotalCount: restResp.TotalCount,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}
	for _, s := range restResp.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			SecretID:       s.SecretID,
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

// Delete deletes a secret via REST API.
func (r *RESTAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	params := url.Values{}
	if permanent {
		params.Set("permanently_delete", "true")
	}

	path := "/api/v1/kms/secrets/" + url.PathEscape(name)
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.DeleteSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &DeleteResult{
		SecretID:  restResp.SecretID,
		Deleted:   restResp.Deleted,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// Rotate rotates a secret via REST API.
func (r *RESTAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rotate"
	restReq := resttypes.RotateSecretRequest{
		NewData: newData,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotateSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &RotateResult{
		SecretID:   restResp.SecretID,
		OldVersion: restResp.OldVersion,
		NewVersion: restResp.NewVersion,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// Versions lists secret versions via REST API.
func (r *RESTAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/versions"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListSecretVersionsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &VersionsResult{
		SecretID:   name,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}
	for _, v := range restResp.Versions {
		result.Versions = append(result.Versions, VersionInfo{
			Version:   v.Version,
			CreatedAt: unixToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: unixToTime(v.ExpiresAt),
			DeletedAt: unixToTime(v.DeletedAt),
		})
	}

	return result, nil
}

// Version retrieves a specific secret version via REST API.
func (r *RESTAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/versions/" + strconv.Itoa(version)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GetSecretVersionResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &VersionResult{
		SecretID:  name,
		Data:      restResp.Data,
		Timestamp: unixToTime(restResp.Timestamp),
	}
	if restResp.Version != nil {
		result.Version = restResp.Version.Version
		result.Metadata = restResp.Version.Metadata
		result.CreatedAt = unixToTime(restResp.Version.CreatedAt)
		result.CreatedBy = restResp.Version.CreatedBy
		result.ExpiresAt = unixToTime(restResp.Version.ExpiresAt)
	}

	return result, nil
}

// Rollback rolls back a secret to a previous version via REST API.
func (r *RESTAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rollback"
	restReq := resttypes.RollbackSecretRequest{
		TargetVersion: uint64(targetVersion),
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RollbackSecretResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &RollbackResult{
		SecretID:   restResp.SecretID,
		NewVersion: restResp.NewVersion,
		Timestamp:  unixToTime(restResp.Timestamp),
	}, nil
}

// Status updates secret status via REST API.
func (r *RESTAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/status"
	status := "DISABLED"
	if enabled {
		status = "ENABLED"
	}
	restReq := resttypes.UpdateSecretStatusRequest{
		Status: status,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.UpdateSecretStatusResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &StatusResult{
		SecretID:  restResp.SecretID,
		Status:    restResp.Status,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// Policy retrieves secret rotation policy via REST API.
func (r *RESTAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/policy"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GetSecretRotationPolicyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &PolicyResult{
		SecretID: restResp.SecretID,
	}
	if restResp.Policy != nil {
		result.Enabled = restResp.Policy.Enabled
		result.IntervalSeconds = restResp.Policy.IntervalSeconds
		result.NextRotation = unixToTime(restResp.Policy.NextRotation)
		result.RetainVersions = restResp.Policy.RetainVersions
		result.RotationLambda = restResp.Policy.RotationLambda
	}

	return result, nil
}

// PolicySet sets secret rotation policy via REST API.
func (r *RESTAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/policy"
	restReq := resttypes.SetSecretRotationPolicyRequest{
		Policy: resttypes.SecretRotationPolicyRequest{
			Enabled:         opts.Enabled,
			IntervalSeconds: opts.IntervalSeconds,
			RetainVersions:  opts.RetainVersions,
			RotationLambda:  opts.RotationLambda,
		},
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.SetSecretRotationPolicyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &PolicySetResult{
		SecretID:  restResp.SecretID,
		Timestamp: unixToTime(restResp.Timestamp),
	}, nil
}

// Prefix retrieves secrets by prefix via REST API.
func (r *RESTAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	params := url.Values{}
	params.Set("prefix", prefix)
	if includeData {
		params.Set("include_data", "true")
	}

	path := "/api/v1/kms/secrets/prefix?" + params.Encode()

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.GetSecretsByPrefixResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &PrefixResult{
		Secrets:    make(map[string]PrefixSecretData),
		TotalCount: restResp.TotalCount,
		HasMore:    restResp.HasMore,
		NextCursor: restResp.NextCursor,
	}
	for name, s := range restResp.Secrets {
		var data []byte
		for _, v := range s.Data {
			data = v
			break
		}
		result.Secrets[name] = PrefixSecretData{
			Data:     data,
			Metadata: s.Metadata,
			Version:  s.Version,
		}
	}

	return result, nil
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
