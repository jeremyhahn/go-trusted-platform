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
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements SecretsCommands using HTTP/REST calls to platformd.
// This adapter makes REST API calls to the platformd server for testing
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
	r.baseURL = helpers.RESTBaseURL(endpoints.PlatformAPI)

	// Check for explicit override via environment variable
	if envURL := os.Getenv("PLATFORM_API_URL"); envURL != "" {
		r.baseURL = helpers.RESTBaseURL(envURL)
	}

	// The REST listener is mTLS: present the runner's client certificate.
	r.httpClient = helpers.NewHTTPClient(30 * time.Second)

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
// Time Conversion Helpers
// =============================================================================

// mergeTags merges the legacy metadata and tags maps into the single
// tags map carried by the current REST contract. Metadata keys win on
// collision.
func mergeTags(metadata, tags map[string]string) map[string]string {
	if len(metadata) == 0 && len(tags) == 0 {
		return nil
	}
	merged := make(map[string]string, len(metadata)+len(tags))
	for k, v := range tags {
		merged[k] = v
	}
	for k, v := range metadata {
		merged[k] = v
	}
	return merged
}

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
	// The current REST contract stores secrets by path with a value
	// payload and a single tags map. ExpiresAt / TenantID / KeyID /
	// Algorithm are not expressible on this transport (expiry and key
	// selection are managed server-side).
	path := "/api/v1/kms/secrets"
	restReq := resttypes.StoreSecretRequest{
		Path:        opts.Name,
		Value:       resttypes.SecretValue(opts.Data),
		Description: opts.Description,
		Tags:        mergeTags(opts.Metadata, opts.Tags),
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
		SecretID: restResp.Path,
		Version:  uint64(restResp.Version),
	}, nil
}

// Get retrieves a secret via REST API.
func (r *RESTAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
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
	return &GetResult{
		SecretID:  restResp.Path,
		Version:   uint64(restResp.Version),
		Data:      restResp.Value,
		Metadata:  restResp.Tags,
		CreatedAt: restResp.CreatedAt,
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

	// The current contract lists secret paths without pagination
	// metadata, description, or owner details.
	result := &ListResult{
		TotalCount: int32(len(restResp.Secrets)),
	}
	for _, s := range restResp.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			SecretID:       s.Path,
			Name:           s.Path,
			CurrentVersion: uint64(s.Version),
			UpdatedAt:      s.UpdatedAt,
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

	// The current contract returns an empty JSON object; a success status
	// means the secret was deleted.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	return &DeleteResult{
		SecretID: name,
		Deleted:  true,
	}, nil
}

// Rotate rotates a secret via REST API.
func (r *RESTAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rotate"
	restReq := resttypes.RotateSecretRequest{
		Value: newData,
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

	return &RotateResult{
		SecretID:   restResp.Path,
		OldVersion: oldVersion,
		NewVersion: newVersion,
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

	// CreatedBy / ExpiresAt / DeletedAt and pagination metadata are not
	// part of the current secret-versions contract.
	result := &VersionsResult{
		SecretID: name,
	}
	for _, v := range restResp.Versions {
		result.Versions = append(result.Versions, VersionInfo{
			Version:   uint64(v.Version),
			CreatedAt: v.CreatedAt,
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

	var restResp resttypes.SecretVersionResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	// Metadata / CreatedBy / ExpiresAt are not part of the current
	// secret-version contract.
	return &VersionResult{
		SecretID:  name,
		Version:   uint64(restResp.Version),
		Data:      restResp.Value,
		CreatedAt: restResp.CreatedAt,
	}, nil
}

// Rollback rolls back a secret to a previous version via REST API.
func (r *RESTAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/rollback"
	restReq := resttypes.RollbackSecretRequest{
		Version: targetVersion,
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
		SecretID:   restResp.Path,
		NewVersion: uint64(restResp.Version),
	}, nil
}

// Status updates secret status via REST API.
func (r *RESTAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
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

	return &StatusResult{
		SecretID: name,
		Status:   status,
	}, nil
}

// Policy retrieves secret rotation policy via REST API.
func (r *RESTAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/policy"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.RotationPolicyResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	return &PolicyResult{
		SecretID:        name,
		Enabled:         restResp.Enabled,
		IntervalSeconds: restResp.IntervalSeconds,
		NextRotation:    unixToTime(restResp.NextRotationUnixTime),
		RetainVersions:  int32(restResp.RetainVersions),
		RotationLambda:  restResp.Method,
		UpdatedAt:       restResp.UpdatedAt,
	}, nil
}

// PolicySet sets secret rotation policy via REST API.
func (r *RESTAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	path := "/api/v1/kms/secrets/" + url.PathEscape(name) + "/policy"
	restReq := resttypes.RotationPolicyRequest{
		Enabled:         opts.Enabled,
		IntervalSeconds: opts.IntervalSeconds,
		RetainVersions:  int(opts.RetainVersions),
		Method:          opts.RotationLambda,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, restReq)
	if err != nil {
		return nil, err
	}

	// The current contract returns an empty JSON object on success.
	if err := r.handleResponse(respBody, statusCode, nil); err != nil {
		return nil, err
	}

	return &PolicySetResult{
		SecretID: name,
	}, nil
}

// Prefix retrieves secrets by prefix via REST API.
func (r *RESTAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	// The current REST contract exposes prefix search as a query
	// parameter on the secrets list endpoint and returns paths only, so
	// secret data is fetched per path when requested.
	params := url.Values{}
	params.Set("prefix", prefix)

	path := "/api/v1/kms/secrets?" + params.Encode()

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var restResp resttypes.ListSecretsResponse
	if err := r.handleResponse(respBody, statusCode, &restResp); err != nil {
		return nil, err
	}

	result := &PrefixResult{
		Secrets:    make(map[string]PrefixSecretData),
		TotalCount: int32(len(restResp.Secrets)),
	}
	for _, s := range restResp.Secrets {
		entry := PrefixSecretData{
			Version: int64(s.Version),
		}
		if includeData {
			secret, err := r.Get(ctx, s.Path)
			if err != nil {
				return nil, err
			}
			entry.Data = secret.Data
			entry.Metadata = secret.Metadata
			entry.Version = int64(secret.Version)
		}
		result.Secrets[s.Path] = entry
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
