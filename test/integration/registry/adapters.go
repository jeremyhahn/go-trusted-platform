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

package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Common Constants
// =============================================================================

const (
	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// DefaultPlatformctlBinary is the default binary name.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultCommandTimeout is the default timeout for commands.
	DefaultCommandTimeout = 30 * time.Second
)

// =============================================================================
// Common Error Types
// =============================================================================

// ErrAdapterConnectionFailed is returned when adapter connection fails.
type ErrAdapterConnectionFailed struct {
	Adapter string
	URL     string
	Err     error
}

func (e ErrAdapterConnectionFailed) Error() string {
	return fmt.Sprintf("%s adapter connection to %s failed: %v", e.Adapter, e.URL, e.Err)
}

func (e ErrAdapterConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrSetupFailed is returned when adapter setup fails.
type ErrSetupFailed struct {
	Adapter string
	Reason  string
	Err     error
}

func (e ErrSetupFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s adapter setup failed: %s: %v", e.Adapter, e.Reason, e.Err)
	}
	return fmt.Sprintf("%s adapter setup failed: %s", e.Adapter, e.Reason)
}

func (e ErrSetupFailed) Unwrap() error {
	return e.Err
}

// ErrCommandFailed is returned when a command execution fails.
type ErrCommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("command %q failed: %v", e.Command, e.Err)
}

func (e ErrCommandFailed) Unwrap() error {
	return e.Err
}

// ErrImageNotFound is returned when an image cannot be found.
type ErrImageNotFound struct {
	Reference string
}

func (e ErrImageNotFound) Error() string {
	return fmt.Sprintf("image not found: %s", e.Reference)
}

// ErrInvalidResponse is returned when the response cannot be parsed.
type ErrInvalidResponse struct {
	Operation string
	Err       error
}

func (e ErrInvalidResponse) Error() string {
	return fmt.Sprintf("invalid response for %s: %v", e.Operation, e.Err)
}

func (e ErrInvalidResponse) Unwrap() error {
	return e.Err
}

// ErrSessionNotFound is returned when a session cannot be found.
type ErrSessionNotFound struct {
	ClientID string
}

func (e ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session not found: %s", e.ClientID)
}

// ErrInvalidArgument is returned when an argument is invalid.
type ErrInvalidArgument struct {
	Argument string
	Reason   string
}

func (e ErrInvalidArgument) Error() string {
	return fmt.Sprintf("invalid argument %q: %s", e.Argument, e.Reason)
}

// =============================================================================
// Compile-time interface checks
// =============================================================================

var (
	_ RegistryCommands = (*CLIAdapter)(nil)
	_ RegistryCommands = (*RESTAdapter)(nil)
	_ RegistryCommands = (*GRPCAdapter)(nil)
	_ RegistryCommands = (*QUICAdapter)(nil)
	_ RegistryCommands = (*MCPAdapter)(nil)
	_ RegistryCommands = (*UnixAdapter)(nil)
)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements RegistryCommands using HTTP/REST calls.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}
	r.baseURL = "http://" + endpoint

	r.httpClient = &http.Client{
		Timeout: DefaultCommandTimeout,
	}

	// Verify connectivity
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/health", nil)
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "REST", URL: r.baseURL, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrAdapterConnectionFailed{Adapter: "REST", URL: r.baseURL, Err: fmt.Errorf("unexpected status: %d", statusCode)}
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

// doRequest performs an HTTP request.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the response and checks for errors.
func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			msg := errResp.Error
			if msg == "" {
				msg = errResp.Message
			}
			if strings.Contains(strings.ToLower(msg), "not found") {
				return ErrImageNotFound{Reference: ""}
			}
			return fmt.Errorf("API error (%d): %s", statusCode, msg)
		}
		return fmt.Errorf("API error (%d): %s", statusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrInvalidResponse{Operation: "response", Err: err}
		}
	}

	return nil
}

// Push pushes an image to the registry via REST.
func (r *RESTAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	reqBody := restPushRequest{
		Reference:      ref,
		Encrypt:        opts.Encrypt,
		KeyID:          opts.KeyID,
		AllowOverwrite: opts.AllowOverwrite,
		Sign:           opts.SignImage,
		SigningKeyID:   opts.SigningKeyID,
		Annotations:    opts.Annotations,
	}

	// Encode layers as base64
	if len(opts.Layers) > 0 {
		reqBody.Layers = make([]restLayerData, len(opts.Layers))
		for i, layer := range opts.Layers {
			reqBody.Layers[i] = restLayerData{
				MediaType:   layer.MediaType,
				Content:     base64.StdEncoding.EncodeToString(layer.Content),
				Annotations: layer.Annotations,
			}
		}
	}

	if len(opts.Config) > 0 {
		reqBody.Config = base64.StdEncoding.EncodeToString(opts.Config)
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/registry/images", reqBody)
	if err != nil {
		return nil, err
	}

	var result restPushResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toPushResult(), nil
}

// Pull pulls an image from the registry via REST.
func (r *RESTAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s", ref)
	params := make([]string, 0)

	if opts.DecryptIfEncrypted {
		params = append(params, "decrypt=true")
	}
	if opts.VerifySignature {
		params = append(params, "verify=true")
	}
	if opts.Platform != "" {
		params = append(params, fmt.Sprintf("platform=%s", opts.Platform))
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restPullResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toPullResult(), nil
}

// List lists images in the registry via REST.
func (r *RESTAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	path := "/api/v1/registry/images"
	params := make([]string, 0)

	if opts.Repository != "" {
		params = append(params, fmt.Sprintf("repository=%s", opts.Repository))
	}
	if opts.TagPrefix != "" {
		params = append(params, fmt.Sprintf("tag_prefix=%s", opts.TagPrefix))
	}
	if opts.Limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", opts.Limit))
	}
	if opts.Cursor != "" {
		params = append(params, fmt.Sprintf("cursor=%s", opts.Cursor))
	}
	if opts.IncludeEncrypted {
		params = append(params, "include_encrypted=true")
	}
	if opts.SortBy != "" {
		params = append(params, fmt.Sprintf("sort_by=%s", opts.SortBy))
	}
	if opts.SortDesc {
		params = append(params, "sort_desc=true")
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restListResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toListResult(), nil
}

// Delete deletes an image from the registry via REST.
func (r *RESTAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s", ref)
	params := make([]string, 0)

	if opts.Force {
		params = append(params, "force=true")
	}
	if opts.DeleteLayers {
		params = append(params, "delete_layers=true")
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restDeleteResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toDeleteResult(), nil
}

// Inspect inspects an image in the registry via REST.
func (r *RESTAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s/inspect", ref)

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restInspectResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toInspectResult(), nil
}

// Status retrieves the registry status via REST.
func (r *RESTAdapter) Status(ctx context.Context) (*StatusResult, error) {
	body, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/registry/status", nil)
	if err != nil {
		return nil, err
	}

	var result restStatusResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toStatusResult(), nil
}

// Tag adds a tag to an existing image via REST.
func (r *RESTAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	reqBody := struct {
		SourceReference string `json:"source_reference"`
		TargetReference string `json:"target_reference"`
	}{
		SourceReference: sourceRef,
		TargetReference: targetRef,
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/registry/images/tag", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: sourceRef}
	}

	var result restTagResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toTagResult(), nil
}

// VerifyClient verifies a client's attestation via REST.
func (r *RESTAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	reqBody := restVerifyClientRequest{
		ClientID:  opts.ClientID,
		AIK:       base64.StdEncoding.EncodeToString(opts.AIK),
		Quote:     base64.StdEncoding.EncodeToString(opts.Quote),
		Signature: base64.StdEncoding.EncodeToString(opts.Signature),
		Nonce:     base64.StdEncoding.EncodeToString(opts.Nonce),
		PCRs:      make(map[int]string),
		EventLog:  base64.StdEncoding.EncodeToString(opts.EventLog),
		Timestamp: opts.Timestamp,
	}

	for idx, val := range opts.PCRs {
		reqBody.PCRs[idx] = base64.StdEncoding.EncodeToString(val)
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/registry/attestation/verify", reqBody)
	if err != nil {
		return nil, err
	}

	var result restVerifyClientResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toVerifyClientResult(), nil
}

// GetSession retrieves a client session via REST.
func (r *RESTAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	path := fmt.Sprintf("/api/v1/registry/attestation/sessions/%s", clientID)

	body, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrSessionNotFound{ClientID: clientID}
	}

	var result restSessionResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toSessionResult(), nil
}

// InvalidateSession invalidates a client session via REST.
func (r *RESTAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	path := fmt.Sprintf("/api/v1/registry/attestation/sessions/%s", clientID)

	body, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		return ErrSessionNotFound{ClientID: clientID}
	}

	return r.handleResponse(body, statusCode, nil)
}

// EncryptImage encrypts an image via REST.
func (r *RESTAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	reqBody := struct {
		Reference string `json:"reference"`
		KeyID     string `json:"key_id"`
	}{
		Reference: ref,
		KeyID:     keyID,
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/registry/encryption/encrypt", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restEncryptImageResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toEncryptImageResult(), nil
}

// DecryptImage decrypts an image via REST.
func (r *RESTAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	reqBody := struct {
		Reference string `json:"reference"`
	}{
		Reference: ref,
	}

	body, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/registry/encryption/decrypt", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restDecryptImageResponse
	if err := r.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toDecryptImageResult(), nil
}

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// GRPCAdapter implements RegistryCommands using gRPC calls.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
}

// NewGRPCAdapter creates a new gRPC adapter for integration testing.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdGRPCEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdGRPCEndpoint
	}
	g.endpoint = endpoint

	conn, err := grpc.DialContext(ctx, endpoint,
		helpers.GRPCTransportCredentials(),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "gRPC", URL: endpoint, Err: err}
	}

	g.conn = conn
	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// Push pushes an image to the registry via gRPC.
func (g *GRPCAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	return nil, fmt.Errorf("gRPC Push not yet implemented")
}

// Pull pulls an image from the registry via gRPC.
func (g *GRPCAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	return nil, fmt.Errorf("gRPC Pull not yet implemented")
}

// List lists images in the registry via gRPC.
func (g *GRPCAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	return nil, fmt.Errorf("gRPC List not yet implemented")
}

// Delete deletes an image from the registry via gRPC.
func (g *GRPCAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	return nil, fmt.Errorf("gRPC Delete not yet implemented")
}

// Inspect inspects an image in the registry via gRPC.
func (g *GRPCAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	return nil, fmt.Errorf("gRPC Inspect not yet implemented")
}

// Status retrieves the registry status via gRPC.
func (g *GRPCAdapter) Status(ctx context.Context) (*StatusResult, error) {
	return nil, fmt.Errorf("gRPC Status not yet implemented")
}

// Tag adds a tag to an existing image via gRPC.
func (g *GRPCAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, fmt.Errorf("gRPC Tag not yet implemented")
}

// VerifyClient verifies a client's attestation via gRPC.
func (g *GRPCAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, fmt.Errorf("gRPC VerifyClient not yet implemented")
}

// GetSession retrieves a client session via gRPC.
func (g *GRPCAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, fmt.Errorf("gRPC GetSession not yet implemented")
}

// InvalidateSession invalidates a client session via gRPC.
func (g *GRPCAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return fmt.Errorf("gRPC InvalidateSession not yet implemented")
}

// EncryptImage encrypts an image via gRPC.
func (g *GRPCAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, fmt.Errorf("gRPC EncryptImage not yet implemented")
}

// DecryptImage decrypts an image via gRPC.
func (g *GRPCAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, fmt.Errorf("gRPC DecryptImage not yet implemented")
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements RegistryCommands using QUIC protocol.
type QUICAdapter struct {
	endpoint string
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup initializes the QUIC connection.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdQUICEndpoint
	}
	q.endpoint = endpoint

	// TODO: Implement QUIC connection verification
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	return nil
}

// Push pushes an image to the registry via QUIC.
func (q *QUICAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	return nil, fmt.Errorf("QUIC Push not yet implemented")
}

// Pull pulls an image from the registry via QUIC.
func (q *QUICAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	return nil, fmt.Errorf("QUIC Pull not yet implemented")
}

// List lists images in the registry via QUIC.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	return nil, fmt.Errorf("QUIC List not yet implemented")
}

// Delete deletes an image from the registry via QUIC.
func (q *QUICAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	return nil, fmt.Errorf("QUIC Delete not yet implemented")
}

// Inspect inspects an image in the registry via QUIC.
func (q *QUICAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	return nil, fmt.Errorf("QUIC Inspect not yet implemented")
}

// Status retrieves the registry status via QUIC.
func (q *QUICAdapter) Status(ctx context.Context) (*StatusResult, error) {
	return nil, fmt.Errorf("QUIC Status not yet implemented")
}

// Tag adds a tag to an existing image via QUIC.
func (q *QUICAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, fmt.Errorf("QUIC Tag not yet implemented")
}

// VerifyClient verifies a client's attestation via QUIC.
func (q *QUICAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, fmt.Errorf("QUIC VerifyClient not yet implemented")
}

// GetSession retrieves a client session via QUIC.
func (q *QUICAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, fmt.Errorf("QUIC GetSession not yet implemented")
}

// InvalidateSession invalidates a client session via QUIC.
func (q *QUICAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return fmt.Errorf("QUIC InvalidateSession not yet implemented")
}

// EncryptImage encrypts an image via QUIC.
func (q *QUICAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, fmt.Errorf("QUIC EncryptImage not yet implemented")
}

// DecryptImage decrypts an image via QUIC.
func (q *QUICAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, fmt.Errorf("QUIC DecryptImage not yet implemented")
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements RegistryCommands using Model Context Protocol.
type MCPAdapter struct {
	endpoint string
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformdMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformdMCPEndpoint
	}
	m.endpoint = endpoint

	// TODO: Implement MCP connection verification
	return nil
}

// Teardown closes the MCP connection.
func (m *MCPAdapter) Teardown() error {
	return nil
}

// Push pushes an image to the registry via MCP.
func (m *MCPAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	return nil, fmt.Errorf("MCP Push not yet implemented")
}

// Pull pulls an image from the registry via MCP.
func (m *MCPAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	return nil, fmt.Errorf("MCP Pull not yet implemented")
}

// List lists images in the registry via MCP.
func (m *MCPAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	return nil, fmt.Errorf("MCP List not yet implemented")
}

// Delete deletes an image from the registry via MCP.
func (m *MCPAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	return nil, fmt.Errorf("MCP Delete not yet implemented")
}

// Inspect inspects an image in the registry via MCP.
func (m *MCPAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	return nil, fmt.Errorf("MCP Inspect not yet implemented")
}

// Status retrieves the registry status via MCP.
func (m *MCPAdapter) Status(ctx context.Context) (*StatusResult, error) {
	return nil, fmt.Errorf("MCP Status not yet implemented")
}

// Tag adds a tag to an existing image via MCP.
func (m *MCPAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, fmt.Errorf("MCP Tag not yet implemented")
}

// VerifyClient verifies a client's attestation via MCP.
func (m *MCPAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, fmt.Errorf("MCP VerifyClient not yet implemented")
}

// GetSession retrieves a client session via MCP.
func (m *MCPAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, fmt.Errorf("MCP GetSession not yet implemented")
}

// InvalidateSession invalidates a client session via MCP.
func (m *MCPAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return fmt.Errorf("MCP InvalidateSession not yet implemented")
}

// EncryptImage encrypts an image via MCP.
func (m *MCPAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, fmt.Errorf("MCP EncryptImage not yet implemented")
}

// DecryptImage decrypts an image via MCP.
func (m *MCPAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, fmt.Errorf("MCP DecryptImage not yet implemented")
}

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// UnixAdapter implements RegistryCommands using Unix socket.
type UnixAdapter struct {
	socketPath string
	httpClient *http.Client
}

// NewUnixAdapter creates a new Unix socket adapter for integration testing.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the Unix socket connection.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}
	u.socketPath = socketPath

	// Create HTTP client that uses Unix socket
	u.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", u.socketPath)
			},
		},
		Timeout: DefaultCommandTimeout,
	}

	// Verify socket exists
	if _, err := os.Stat(u.socketPath); os.IsNotExist(err) {
		return ErrAdapterConnectionFailed{Adapter: "Unix", URL: u.socketPath, Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (u *UnixAdapter) Teardown() error {
	if u.httpClient != nil {
		u.httpClient.CloseIdleConnections()
	}
	return nil
}

// doRequest performs an HTTP request over Unix socket.
func (u *UnixAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to marshal request: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	// Use http://localhost as dummy host - the transport uses Unix socket
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the response.
func (u *UnixAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		var errResp struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			msg := errResp.Error
			if msg == "" {
				msg = errResp.Message
			}
			if strings.Contains(strings.ToLower(msg), "not found") {
				return ErrImageNotFound{Reference: ""}
			}
			return fmt.Errorf("API error (%d): %s", statusCode, msg)
		}
		return fmt.Errorf("API error (%d): %s", statusCode, string(respBody))
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrInvalidResponse{Operation: "response", Err: err}
		}
	}

	return nil
}

// Push pushes an image to the registry via Unix socket.
func (u *UnixAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	reqBody := restPushRequest{
		Reference:      ref,
		Encrypt:        opts.Encrypt,
		KeyID:          opts.KeyID,
		AllowOverwrite: opts.AllowOverwrite,
		Sign:           opts.SignImage,
		SigningKeyID:   opts.SigningKeyID,
		Annotations:    opts.Annotations,
	}

	if len(opts.Layers) > 0 {
		reqBody.Layers = make([]restLayerData, len(opts.Layers))
		for i, layer := range opts.Layers {
			reqBody.Layers[i] = restLayerData{
				MediaType:   layer.MediaType,
				Content:     base64.StdEncoding.EncodeToString(layer.Content),
				Annotations: layer.Annotations,
			}
		}
	}

	if len(opts.Config) > 0 {
		reqBody.Config = base64.StdEncoding.EncodeToString(opts.Config)
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/registry/images", reqBody)
	if err != nil {
		return nil, err
	}

	var result restPushResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toPushResult(), nil
}

// Pull pulls an image from the registry via Unix socket.
func (u *UnixAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s", ref)

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restPullResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toPullResult(), nil
}

// List lists images in the registry via Unix socket.
func (u *UnixAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	path := "/api/v1/registry/images"
	params := make([]string, 0)

	if opts.Limit > 0 {
		params = append(params, fmt.Sprintf("limit=%d", opts.Limit))
	}

	if len(params) > 0 {
		path += "?" + strings.Join(params, "&")
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restListResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toListResult(), nil
}

// Delete deletes an image from the registry via Unix socket.
func (u *UnixAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s", ref)
	if opts.Force {
		path += "?force=true"
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restDeleteResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toDeleteResult(), nil
}

// Inspect inspects an image in the registry via Unix socket.
func (u *UnixAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	path := fmt.Sprintf("/api/v1/registry/images/%s/inspect", ref)

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restInspectResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toInspectResult(), nil
}

// Status retrieves the registry status via Unix socket.
func (u *UnixAdapter) Status(ctx context.Context) (*StatusResult, error) {
	body, statusCode, err := u.doRequest(ctx, http.MethodGet, "/api/v1/registry/status", nil)
	if err != nil {
		return nil, err
	}

	var result restStatusResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toStatusResult(), nil
}

// Tag adds a tag to an existing image via Unix socket.
func (u *UnixAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	reqBody := struct {
		SourceReference string `json:"source_reference"`
		TargetReference string `json:"target_reference"`
	}{
		SourceReference: sourceRef,
		TargetReference: targetRef,
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/registry/images/tag", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: sourceRef}
	}

	var result restTagResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toTagResult(), nil
}

// VerifyClient verifies a client's attestation via Unix socket.
func (u *UnixAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	reqBody := restVerifyClientRequest{
		ClientID:  opts.ClientID,
		AIK:       base64.StdEncoding.EncodeToString(opts.AIK),
		Quote:     base64.StdEncoding.EncodeToString(opts.Quote),
		Signature: base64.StdEncoding.EncodeToString(opts.Signature),
		Nonce:     base64.StdEncoding.EncodeToString(opts.Nonce),
		PCRs:      make(map[int]string),
		EventLog:  base64.StdEncoding.EncodeToString(opts.EventLog),
		Timestamp: opts.Timestamp,
	}

	for idx, val := range opts.PCRs {
		reqBody.PCRs[idx] = base64.StdEncoding.EncodeToString(val)
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/registry/attestation/verify", reqBody)
	if err != nil {
		return nil, err
	}

	var result restVerifyClientResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toVerifyClientResult(), nil
}

// GetSession retrieves a client session via Unix socket.
func (u *UnixAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	path := fmt.Sprintf("/api/v1/registry/attestation/sessions/%s", clientID)

	body, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrSessionNotFound{ClientID: clientID}
	}

	var result restSessionResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toSessionResult(), nil
}

// InvalidateSession invalidates a client session via Unix socket.
func (u *UnixAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	path := fmt.Sprintf("/api/v1/registry/attestation/sessions/%s", clientID)

	body, statusCode, err := u.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		return ErrSessionNotFound{ClientID: clientID}
	}

	return u.handleResponse(body, statusCode, nil)
}

// EncryptImage encrypts an image via Unix socket.
func (u *UnixAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	reqBody := struct {
		Reference string `json:"reference"`
		KeyID     string `json:"key_id"`
	}{
		Reference: ref,
		KeyID:     keyID,
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/registry/encryption/encrypt", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restEncryptImageResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toEncryptImageResult(), nil
}

// DecryptImage decrypts an image via Unix socket.
func (u *UnixAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	reqBody := struct {
		Reference string `json:"reference"`
	}{
		Reference: ref,
	}

	body, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/registry/encryption/decrypt", reqBody)
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusNotFound {
		return nil, ErrImageNotFound{Reference: ref}
	}

	var result restDecryptImageResponse
	if err := u.handleResponse(body, statusCode, &result); err != nil {
		return nil, err
	}

	return result.toDecryptImageResult(), nil
}

// =============================================================================
// Response Types for JSON Parsing
// =============================================================================

// CLI Response Types

type cliPushResponse struct {
	Reference string    `json:"reference"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Encrypted bool      `json:"encrypted"`
	Signed    bool      `json:"signed"`
	PushedAt  time.Time `json:"pushed_at"`
}

func (r *cliPushResponse) toPushResult() *PushResult {
	return &PushResult{
		Reference: r.Reference,
		Digest:    r.Digest,
		Size:      r.Size,
		Encrypted: r.Encrypted,
		Signed:    r.Signed,
		PushedAt:  r.PushedAt,
	}
}

type cliPullResponse struct {
	Reference      string              `json:"reference"`
	Manifest       cliManifestResponse `json:"manifest"`
	Config         string              `json:"config"`
	Layers         []cliLayerResponse  `json:"layers"`
	Encrypted      bool                `json:"encrypted"`
	Signed         bool                `json:"signed"`
	SignatureValid bool                `json:"signature_valid"`
	PulledAt       time.Time           `json:"pulled_at"`
}

func (r *cliPullResponse) toPullResult() *PullResult {
	result := &PullResult{
		Reference:      r.Reference,
		Manifest:       r.Manifest.toImageManifest(),
		Encrypted:      r.Encrypted,
		Signed:         r.Signed,
		SignatureValid: r.SignatureValid,
		PulledAt:       r.PulledAt,
	}

	if r.Config != "" {
		result.Config, _ = base64.StdEncoding.DecodeString(r.Config)
	}

	if len(r.Layers) > 0 {
		result.Layers = make([]LayerData, len(r.Layers))
		for i, layer := range r.Layers {
			result.Layers[i] = layer.toLayerData()
		}
	}

	return result
}

type cliLayerResponse struct {
	MediaType   string            `json:"media_type"`
	Content     string            `json:"content"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (r *cliLayerResponse) toLayerData() LayerData {
	content, _ := base64.StdEncoding.DecodeString(r.Content)
	return LayerData{
		MediaType:   r.MediaType,
		Content:     content,
		Annotations: r.Annotations,
	}
}

type cliManifestResponse struct {
	SchemaVersion int                     `json:"schemaVersion"`
	MediaType     string                  `json:"mediaType"`
	Config        cliDescriptorResponse   `json:"config"`
	Layers        []cliDescriptorResponse `json:"layers"`
	Annotations   map[string]string       `json:"annotations,omitempty"`
	Reference     string                  `json:"reference"`
	Digest        string                  `json:"digest"`
	Size          int64                   `json:"size"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Encrypted     bool                    `json:"encrypted"`
	Signed        bool                    `json:"signed"`
}

func (r *cliManifestResponse) toImageManifest() *ImageManifest {
	layers := make([]Descriptor, len(r.Layers))
	for i, l := range r.Layers {
		layers[i] = l.toDescriptor()
	}

	return &ImageManifest{
		SchemaVersion: r.SchemaVersion,
		MediaType:     r.MediaType,
		Config:        r.Config.toDescriptor(),
		Layers:        layers,
		Annotations:   r.Annotations,
		Reference:     r.Reference,
		Digest:        r.Digest,
		Size:          r.Size,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
		Encrypted:     r.Encrypted,
		Signed:        r.Signed,
	}
}

type cliDescriptorResponse struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func (r *cliDescriptorResponse) toDescriptor() Descriptor {
	return Descriptor{
		MediaType:   r.MediaType,
		Digest:      r.Digest,
		Size:        r.Size,
		Annotations: r.Annotations,
	}
}

type cliListResponse struct {
	Images     []cliManifestResponse `json:"images"`
	TotalCount int                   `json:"total_count"`
	HasMore    bool                  `json:"has_more"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

func (r *cliListResponse) toListResult() *ListResult {
	images := make([]ImageManifest, len(r.Images))
	for i, img := range r.Images {
		images[i] = *img.toImageManifest()
	}

	return &ListResult{
		Images:     images,
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
}

type cliDeleteResponse struct {
	Reference     string    `json:"reference"`
	Digest        string    `json:"digest"`
	DeletedAt     time.Time `json:"deleted_at"`
	LayersDeleted int       `json:"layers_deleted"`
}

func (r *cliDeleteResponse) toDeleteResult() *DeleteResult {
	return &DeleteResult{
		Reference:     r.Reference,
		Digest:        r.Digest,
		DeletedAt:     r.DeletedAt,
		LayersDeleted: r.LayersDeleted,
	}
}

type cliInspectResponse struct {
	Reference       string                 `json:"reference"`
	Manifest        cliManifestResponse    `json:"manifest"`
	Config          cliImageConfigResponse `json:"config"`
	TotalSize       int64                  `json:"total_size"`
	LayerCount      int                    `json:"layer_count"`
	Encrypted       bool                   `json:"encrypted"`
	EncryptionKeyID string                 `json:"encryption_key_id,omitempty"`
	Signed          bool                   `json:"signed"`
	SigningKeyID    string                 `json:"signing_key_id,omitempty"`
	SignatureValid  bool                   `json:"signature_valid"`
}

func (r *cliInspectResponse) toInspectResult() *InspectResult {
	return &InspectResult{
		Reference:       r.Reference,
		Manifest:        r.Manifest.toImageManifest(),
		Config:          r.Config.toImageConfig(),
		TotalSize:       r.TotalSize,
		LayerCount:      r.LayerCount,
		Encrypted:       r.Encrypted,
		EncryptionKeyID: r.EncryptionKeyID,
		Signed:          r.Signed,
		SigningKeyID:    r.SigningKeyID,
		SignatureValid:  r.SignatureValid,
	}
}

type cliImageConfigResponse struct {
	Architecture string            `json:"architecture"`
	OS           string            `json:"os"`
	Author       string            `json:"author,omitempty"`
	Created      time.Time         `json:"created"`
	Entrypoint   []string          `json:"entrypoint,omitempty"`
	Cmd          []string          `json:"cmd,omitempty"`
	Env          []string          `json:"env,omitempty"`
	WorkingDir   string            `json:"working_dir,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	ExposedPorts []string          `json:"exposed_ports,omitempty"`
	Volumes      []string          `json:"volumes,omitempty"`
}

func (r *cliImageConfigResponse) toImageConfig() *ImageConfig {
	return &ImageConfig{
		Architecture: r.Architecture,
		OS:           r.OS,
		Author:       r.Author,
		Created:      r.Created,
		Entrypoint:   r.Entrypoint,
		Cmd:          r.Cmd,
		Env:          r.Env,
		WorkingDir:   r.WorkingDir,
		Labels:       r.Labels,
		ExposedPorts: r.ExposedPorts,
		Volumes:      r.Volumes,
	}
}

type cliStatusResponse struct {
	Healthy            bool   `json:"healthy"`
	Status             string `json:"status"`
	Version            string `json:"version"`
	UptimeSeconds      int64  `json:"uptime_seconds"`
	ImageCount         int    `json:"image_count"`
	TotalSize          int64  `json:"total_size"`
	ActiveConnections  int    `json:"active_connections"`
	AttestationEnabled bool   `json:"attestation_enabled"`
	EncryptionEnabled  bool   `json:"encryption_enabled"`
	StorageBackend     string `json:"storage_backend"`
	StorageStatus      string `json:"storage_status"`
}

func (r *cliStatusResponse) toStatusResult() *StatusResult {
	return &StatusResult{
		Healthy:            r.Healthy,
		Status:             r.Status,
		Version:            r.Version,
		Uptime:             time.Duration(r.UptimeSeconds) * time.Second,
		ImageCount:         r.ImageCount,
		TotalSize:          r.TotalSize,
		ActiveConnections:  r.ActiveConnections,
		AttestationEnabled: r.AttestationEnabled,
		EncryptionEnabled:  r.EncryptionEnabled,
		StorageBackend:     r.StorageBackend,
		StorageStatus:      r.StorageStatus,
	}
}

type cliTagResponse struct {
	SourceReference string    `json:"source_reference"`
	TargetReference string    `json:"target_reference"`
	Digest          string    `json:"digest"`
	TaggedAt        time.Time `json:"tagged_at"`
}

func (r *cliTagResponse) toTagResult() *TagResult {
	return &TagResult{
		SourceReference: r.SourceReference,
		TargetReference: r.TargetReference,
		Digest:          r.Digest,
		TaggedAt:        r.TaggedAt,
	}
}

type cliVerifyClientResponse struct {
	Verified    bool      `json:"verified"`
	ClientID    string    `json:"client_id"`
	SessionID   string    `json:"session_id,omitempty"`
	ValidUntil  time.Time `json:"valid_until,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

func (r *cliVerifyClientResponse) toVerifyClientResult() *VerifyClientResult {
	return &VerifyClientResult{
		Verified:    r.Verified,
		ClientID:    r.ClientID,
		SessionID:   r.SessionID,
		ValidUntil:  r.ValidUntil,
		Permissions: r.Permissions,
		Reason:      r.Reason,
	}
}

type cliSessionResponse struct {
	ClientID    string         `json:"client_id"`
	SessionID   string         `json:"session_id"`
	AIK         string         `json:"aik"`
	PCRs        map[int]string `json:"pcrs,omitempty"`
	ValidUntil  time.Time      `json:"valid_until"`
	Permissions []string       `json:"permissions"`
	CreatedAt   time.Time      `json:"created_at"`
}

func (r *cliSessionResponse) toSessionResult() *SessionResult {
	pcrs := make(map[int][]byte)
	for idx, val := range r.PCRs {
		pcrs[idx], _ = base64.StdEncoding.DecodeString(val)
	}

	return &SessionResult{
		ClientID:    r.ClientID,
		SessionID:   r.SessionID,
		AIK:         r.AIK,
		PCRs:        pcrs,
		ValidUntil:  r.ValidUntil,
		Permissions: r.Permissions,
		CreatedAt:   r.CreatedAt,
	}
}

type cliEncryptImageResponse struct {
	Reference       string    `json:"reference"`
	KeyID           string    `json:"key_id"`
	EncryptedAt     time.Time `json:"encrypted_at"`
	LayersEncrypted int       `json:"layers_encrypted"`
}

func (r *cliEncryptImageResponse) toEncryptImageResult() *EncryptImageResult {
	return &EncryptImageResult{
		Reference:       r.Reference,
		KeyID:           r.KeyID,
		EncryptedAt:     r.EncryptedAt,
		LayersEncrypted: r.LayersEncrypted,
	}
}

type cliDecryptImageResponse struct {
	Reference   string              `json:"reference"`
	KeyID       string              `json:"key_id"`
	DecryptedAt time.Time           `json:"decrypted_at"`
	Manifest    cliManifestResponse `json:"manifest"`
	Layers      []cliLayerResponse  `json:"layers"`
}

func (r *cliDecryptImageResponse) toDecryptImageResult() *DecryptImageResult {
	layers := make([]LayerData, len(r.Layers))
	for i, layer := range r.Layers {
		layers[i] = layer.toLayerData()
	}

	return &DecryptImageResult{
		Reference:   r.Reference,
		KeyID:       r.KeyID,
		DecryptedAt: r.DecryptedAt,
		Manifest:    r.Manifest.toImageManifest(),
		Layers:      layers,
	}
}

// REST Request/Response Types

type restPushRequest struct {
	Reference      string            `json:"reference"`
	Encrypt        bool              `json:"encrypt,omitempty"`
	KeyID          string            `json:"key_id,omitempty"`
	AllowOverwrite bool              `json:"allow_overwrite,omitempty"`
	Sign           bool              `json:"sign,omitempty"`
	SigningKeyID   string            `json:"signing_key_id,omitempty"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	Config         string            `json:"config,omitempty"`
	Layers         []restLayerData   `json:"layers,omitempty"`
}

type restLayerData struct {
	MediaType   string            `json:"media_type"`
	Content     string            `json:"content"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type restPushResponse = cliPushResponse
type restPullResponse = cliPullResponse
type restListResponse = cliListResponse
type restDeleteResponse = cliDeleteResponse
type restInspectResponse = cliInspectResponse
type restStatusResponse = cliStatusResponse
type restTagResponse = cliTagResponse
type restVerifyClientResponse = cliVerifyClientResponse
type restSessionResponse = cliSessionResponse
type restEncryptImageResponse = cliEncryptImageResponse
type restDecryptImageResponse = cliDecryptImageResponse
type restVerifyClientRequest struct {
	ClientID  string         `json:"client_id"`
	AIK       string         `json:"aik"`
	Quote     string         `json:"quote"`
	Signature string         `json:"signature"`
	Nonce     string         `json:"nonce"`
	PCRs      map[int]string `json:"pcrs,omitempty"`
	EventLog  string         `json:"event_log,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}
