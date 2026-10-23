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

// Package invitation provides a client for invitation service operations.
package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// ClientInterface defines the interface for invitation service operations.
type ClientInterface interface {
	// Create creates a new invitation to join the current user's tenant.
	Create(ctx context.Context, req *CreateInvitationRequest) (*Invitation, error)
	// Get retrieves an invitation by ID.
	Get(ctx context.Context, id uint64) (*Invitation, error)
	// GetByToken retrieves an invitation by its secure token.
	GetByToken(ctx context.Context, token string) (*Invitation, error)
	// List returns all invitations for the current user's tenant.
	List(ctx context.Context) ([]*Invitation, error)
	// Revoke revokes an invitation by ID.
	Revoke(ctx context.Context, id uint64) error
}

// TransportType indicates which transport the client uses.
type TransportType int

const (
	// TransportGRPC uses gRPC transport (currently maps to REST until gRPC is implemented).
	TransportGRPC TransportType = iota
	// TransportREST uses REST/HTTP transport.
	TransportREST
)

// Client provides access to invitation service operations.
// It supports both gRPC and REST transports based on configuration.
type Client struct {
	transport     TransportType
	restBaseURL   string
	httpClient    *http.Client
	grpcTransport transport.Adapter
	authToken     string
}

// ClientConfig holds configuration for creating an invitation client.
type ClientConfig struct {
	// Transport specifies which transport to use.
	Transport TransportType
	// RESTBaseURL is the base URL for REST API calls (e.g., "https://localhost:8443/api/v1").
	RESTBaseURL string
	// HTTPClient is the HTTP client to use for REST calls. If nil, a default client is used.
	HTTPClient *http.Client
	// GRPCTransport is the gRPC transport adapter.
	GRPCTransport transport.Adapter
	// AuthToken is the bearer token for authentication.
	AuthToken string
}

// NewClient creates a new invitation service client.
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, common.ErrNilClient
	}

	c := &Client{
		transport:     config.Transport,
		restBaseURL:   config.RESTBaseURL,
		httpClient:    config.HTTPClient,
		grpcTransport: config.GRPCTransport,
		authToken:     config.AuthToken,
	}

	// Set default HTTP client if not provided
	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	// Validate configuration based on transport
	switch c.transport {
	case TransportREST:
		if c.restBaseURL == "" {
			return nil, &ErrValidationFailed{Field: "RESTBaseURL", Reason: "required for REST transport"}
		}
	case TransportGRPC:
		if c.grpcTransport == nil {
			return nil, &ErrValidationFailed{Field: "GRPCTransport", Reason: "required for gRPC transport"}
		}
	}

	return c, nil
}

// NewRESTClient creates a new invitation client using REST transport.
func NewRESTClient(baseURL, authToken string) (*Client, error) {
	return NewClient(&ClientConfig{
		Transport:   TransportREST,
		RESTBaseURL: baseURL,
		AuthToken:   authToken,
	})
}

// NewGRPCClient creates a new invitation client using gRPC transport.
func NewGRPCClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	return NewClient(&ClientConfig{
		Transport:     TransportGRPC,
		GRPCTransport: conn,
	})
}

// SetAuthToken sets the authentication token for API calls.
func (c *Client) SetAuthToken(token string) {
	c.authToken = token
}

// Create creates a new invitation to join the current user's tenant.
func (c *Client) Create(ctx context.Context, req *CreateInvitationRequest) (*Invitation, error) {
	if req == nil {
		return nil, &ErrValidationFailed{Reason: "request cannot be nil"}
	}

	if err := req.Validate(); err != nil {
		return nil, err
	}

	switch c.transport {
	case TransportREST:
		return c.createREST(ctx, req)
	case TransportGRPC:
		return c.createGRPC(ctx, req)
	default:
		return nil, &ErrValidationFailed{Reason: "unsupported transport"}
	}
}

// Get retrieves an invitation by ID.
func (c *Client) Get(ctx context.Context, id uint64) (*Invitation, error) {
	if id == 0 {
		return nil, &ErrValidationFailed{Field: "id", Reason: "id is required"}
	}

	switch c.transport {
	case TransportREST:
		return c.getREST(ctx, id)
	case TransportGRPC:
		return c.getGRPC(ctx, id)
	default:
		return nil, &ErrValidationFailed{Reason: "unsupported transport"}
	}
}

// GetByToken retrieves an invitation by its secure token.
func (c *Client) GetByToken(ctx context.Context, token string) (*Invitation, error) {
	if token == "" {
		return nil, &ErrValidationFailed{Field: "token", Reason: "token is required"}
	}

	switch c.transport {
	case TransportREST:
		return c.getByTokenREST(ctx, token)
	case TransportGRPC:
		return c.getByTokenGRPC(ctx, token)
	default:
		return nil, &ErrValidationFailed{Reason: "unsupported transport"}
	}
}

// List returns all invitations for the current user's tenant.
func (c *Client) List(ctx context.Context) ([]*Invitation, error) {
	switch c.transport {
	case TransportREST:
		return c.listREST(ctx)
	case TransportGRPC:
		return c.listGRPC(ctx)
	default:
		return nil, &ErrValidationFailed{Reason: "unsupported transport"}
	}
}

// Revoke revokes an invitation by ID.
func (c *Client) Revoke(ctx context.Context, id uint64) error {
	if id == 0 {
		return &ErrValidationFailed{Field: "id", Reason: "id is required"}
	}

	switch c.transport {
	case TransportREST:
		return c.revokeREST(ctx, id)
	case TransportGRPC:
		return c.revokeGRPC(ctx, id)
	default:
		return &ErrValidationFailed{Reason: "unsupported transport"}
	}
}

// REST Transport Implementation

func (c *Client) createREST(ctx context.Context, req *CreateInvitationRequest) (*Invitation, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &ErrCreateInvitationFailed{Cause: err}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.restBaseURL+"/invitations", bytes.NewReader(body))
	if err != nil {
		return nil, &ErrCreateInvitationFailed{Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ErrCreateInvitationFailed{Cause: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "create invitation")
	}

	var invitation Invitation
	if err := json.NewDecoder(resp.Body).Decode(&invitation); err != nil {
		return nil, &ErrCreateInvitationFailed{Cause: err}
	}

	return &invitation, nil
}

func (c *Client) getREST(ctx context.Context, id uint64) (*Invitation, error) {
	url := fmt.Sprintf("%s/invitations/%d", c.restBaseURL, id)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &ErrGetInvitationFailed{ID: id, Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ErrGetInvitationFailed{ID: id, Cause: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ErrInvitationNotFound{ID: id}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "get invitation")
	}

	var invitation Invitation
	if err := json.NewDecoder(resp.Body).Decode(&invitation); err != nil {
		return nil, &ErrGetInvitationFailed{ID: id, Cause: err}
	}

	return &invitation, nil
}

func (c *Client) getByTokenREST(ctx context.Context, token string) (*Invitation, error) {
	url := fmt.Sprintf("%s/invitations/token/%s", c.restBaseURL, token)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, &ErrGetInvitationFailed{Token: token, Cause: err}
	}

	// Note: GetByToken is a public endpoint, no auth required
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ErrGetInvitationFailed{Token: token, Cause: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ErrInvitationNotFound{Token: token}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "get invitation by token")
	}

	var invitation Invitation
	if err := json.NewDecoder(resp.Body).Decode(&invitation); err != nil {
		return nil, &ErrGetInvitationFailed{Token: token, Cause: err}
	}

	return &invitation, nil
}

func (c *Client) listREST(ctx context.Context) ([]*Invitation, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.restBaseURL+"/invitations", nil)
	if err != nil {
		return nil, &ErrListInvitationsFailed{Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ErrListInvitationsFailed{Cause: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "list invitations")
	}

	var result ListInvitationsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Try decoding as array directly for simpler responses
		resp.Body = io.NopCloser(bytes.NewReader([]byte{}))
		var invitations []*Invitation
		if arrErr := json.NewDecoder(resp.Body).Decode(&invitations); arrErr != nil {
			return nil, &ErrListInvitationsFailed{Cause: err}
		}
		return invitations, nil
	}

	return result.Invitations, nil
}

func (c *Client) revokeREST(ctx context.Context, id uint64) error {
	url := fmt.Sprintf("%s/invitations/%d", c.restBaseURL, id)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return &ErrRevokeInvitationFailed{ID: id, Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return &ErrRevokeInvitationFailed{ID: id, Cause: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("failed to close response body", "error", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusNotFound {
		return &ErrInvitationNotFound{ID: id}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return c.handleErrorResponse(resp, "revoke invitation")
	}

	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
}

func (c *Client) handleErrorResponse(resp *http.Response, operation string) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &ErrResponseReadFailed{Operation: operation, StatusCode: resp.StatusCode, Cause: err}
	}

	// Carry the server's message when the body is a JSON error response
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	statusErr := &ErrUnexpectedStatus{Operation: operation, StatusCode: resp.StatusCode}
	if json.Unmarshal(body, &errResp) == nil {
		statusErr.Message = errResp.Error
		if statusErr.Message == "" {
			statusErr.Message = errResp.Message
		}
	}
	return statusErr
}

// gRPC Transport Implementation
// Note: These methods are placeholders until the InvitationService gRPC definition is added.
// Currently, the invitation service only has REST endpoints.

func (c *Client) createGRPC(ctx context.Context, req *CreateInvitationRequest) (*Invitation, error) {
	// Fall back to REST until gRPC service is implemented
	return c.createREST(ctx, req)
}

func (c *Client) getGRPC(ctx context.Context, id uint64) (*Invitation, error) {
	// Fall back to REST until gRPC service is implemented
	return c.getREST(ctx, id)
}

func (c *Client) getByTokenGRPC(ctx context.Context, token string) (*Invitation, error) {
	// Fall back to REST until gRPC service is implemented
	return c.getByTokenREST(ctx, token)
}

func (c *Client) listGRPC(ctx context.Context) ([]*Invitation, error) {
	// Fall back to REST until gRPC service is implemented
	return c.listREST(ctx)
}

func (c *Client) revokeGRPC(ctx context.Context, id uint64) error {
	// Fall back to REST until gRPC service is implemented
	return c.revokeREST(ctx, id)
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)
