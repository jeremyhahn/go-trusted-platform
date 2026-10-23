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

package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// UserClientInterface defines the interface for tenant user operations.
// These are operations available to authenticated users to interact with their tenant.
type UserClientInterface interface {
	// GetTenant returns the current user's tenant information.
	GetTenant(ctx context.Context) (*TenantInfo, error)
	// IsTenantOwner returns whether the current user is the tenant owner.
	IsTenantOwner(ctx context.Context) (bool, error)
}

// UserTransportType indicates which transport the client uses.
type UserTransportType int

const (
	// UserTransportGRPC uses gRPC transport.
	UserTransportGRPC UserTransportType = iota
	// UserTransportREST uses REST/HTTP transport.
	UserTransportREST
)

// UserClient provides access to tenant user operations.
// It supports both gRPC and REST transports based on configuration.
type UserClient struct {
	transport     UserTransportType
	restBaseURL   string
	httpClient    *http.Client
	grpcTransport transport.Adapter
	authToken     string
}

// UserClientConfig holds configuration for creating a tenant user client.
type UserClientConfig struct {
	// Transport specifies which transport to use.
	Transport UserTransportType
	// RESTBaseURL is the base URL for REST API calls (e.g., "https://localhost:8443/api/v1").
	RESTBaseURL string
	// HTTPClient is the HTTP client to use for REST calls. If nil, a default client is used.
	HTTPClient *http.Client
	// GRPCTransport is the gRPC transport adapter.
	GRPCTransport transport.Adapter
	// AuthToken is the bearer token for authentication.
	AuthToken string
}

// NewUserClient creates a new tenant user service client.
func NewUserClient(config *UserClientConfig) (*UserClient, error) {
	if config == nil {
		return nil, common.ErrNilClient
	}

	c := &UserClient{
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
	case UserTransportREST:
		if c.restBaseURL == "" {
			return nil, &ErrUserClientValidation{Field: "RESTBaseURL", Reason: "required for REST transport"}
		}
	case UserTransportGRPC:
		if c.grpcTransport == nil {
			return nil, &ErrUserClientValidation{Field: "GRPCTransport", Reason: "required for gRPC transport"}
		}
	}

	return c, nil
}

// NewRESTUserClient creates a new tenant user client using REST transport.
func NewRESTUserClient(baseURL, authToken string) (*UserClient, error) {
	return NewUserClient(&UserClientConfig{
		Transport:   UserTransportREST,
		RESTBaseURL: baseURL,
		AuthToken:   authToken,
	})
}

// NewGRPCUserClient creates a new tenant user client using gRPC transport.
func NewGRPCUserClient(conn transport.Adapter) (*UserClient, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	return NewUserClient(&UserClientConfig{
		Transport:     UserTransportGRPC,
		GRPCTransport: conn,
	})
}

// SetAuthToken sets the authentication token for API calls.
func (c *UserClient) SetAuthToken(token string) {
	c.authToken = token
}

// GetTenant returns the current user's tenant information.
func (c *UserClient) GetTenant(ctx context.Context) (*TenantInfo, error) {
	switch c.transport {
	case UserTransportREST:
		return c.getTenantREST(ctx)
	case UserTransportGRPC:
		return c.getTenantGRPC(ctx)
	default:
		return nil, &ErrUserClientValidation{Reason: "unsupported transport"}
	}
}

// IsTenantOwner returns whether the current user is the tenant owner.
func (c *UserClient) IsTenantOwner(ctx context.Context) (bool, error) {
	switch c.transport {
	case UserTransportREST:
		return c.isTenantOwnerREST(ctx)
	case UserTransportGRPC:
		return c.isTenantOwnerGRPC(ctx)
	default:
		return false, &ErrUserClientValidation{Reason: "unsupported transport"}
	}
}

// REST Transport Implementation

func (c *UserClient) getTenantREST(ctx context.Context) (*TenantInfo, error) {
	// The endpoint returns the current user's tenant based on their JWT claims
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.restBaseURL+"/me/tenant", nil)
	if err != nil {
		return nil, &ErrGetUserTenantFailed{Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, &ErrGetUserTenantFailed{Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &ErrUserNotInTenant{}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleErrorResponse(resp, "get user tenant")
	}

	var tenant TenantInfo
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		return nil, &ErrGetUserTenantFailed{Cause: err}
	}

	return &tenant, nil
}

func (c *UserClient) isTenantOwnerREST(ctx context.Context) (bool, error) {
	// The endpoint checks if the current user owns their tenant
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.restBaseURL+"/me/tenant/owner", nil)
	if err != nil {
		return false, &ErrCheckOwnershipFailed{Cause: err}
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, &ErrCheckOwnershipFailed{Cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return false, &ErrUserNotInTenant{}
	}

	if resp.StatusCode != http.StatusOK {
		return false, c.handleErrorResponse(resp, "check tenant ownership")
	}

	var result struct {
		IsOwner bool `json:"is_owner"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, &ErrCheckOwnershipFailed{Cause: err}
	}

	return result.IsOwner, nil
}

func (c *UserClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
}

func (c *UserClient) handleErrorResponse(resp *http.Response, operation string) error {
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
// Note: These methods use the TenantService gRPC client when available.

func (c *UserClient) getTenantGRPC(ctx context.Context) (*TenantInfo, error) {
	// For gRPC, we need to get the user's tenant ID from context/claims
	// and then call TenantService.GetTenant
	// Fall back to REST until user context extraction is implemented
	return c.getTenantREST(ctx)
}

func (c *UserClient) isTenantOwnerGRPC(ctx context.Context) (bool, error) {
	// For gRPC, we need to get the user ID from context/claims
	// and check the user's IsTenantOwner flag
	// Fall back to REST until user context extraction is implemented
	return c.isTenantOwnerREST(ctx)
}

// UserClient Error Types

// ErrUserClientValidation is returned when user client validation fails.
type ErrUserClientValidation struct {
	Field  string
	Reason string
}

func (e *ErrUserClientValidation) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("user client validation failed for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("user client validation failed: %s", e.Reason)
}

// ErrGetUserTenantFailed is returned when getting user tenant fails.
type ErrGetUserTenantFailed struct {
	Cause error
}

func (e *ErrGetUserTenantFailed) Error() string {
	return fmt.Sprintf("failed to get user tenant: %v", e.Cause)
}

func (e *ErrGetUserTenantFailed) Unwrap() error { return e.Cause }

// ErrUserNotInTenant is returned when the user is not associated with a tenant.
type ErrUserNotInTenant struct{}

func (e *ErrUserNotInTenant) Error() string {
	return "user is not associated with a tenant"
}

// ErrCheckOwnershipFailed is returned when checking tenant ownership fails.
type ErrCheckOwnershipFailed struct {
	Cause error
}

func (e *ErrCheckOwnershipFailed) Error() string {
	return fmt.Sprintf("failed to check tenant ownership: %v", e.Cause)
}

func (e *ErrCheckOwnershipFailed) Unwrap() error { return e.Cause }

// ErrUnexpectedStatus is returned when the server answers with a non-success
// HTTP status. Message is the server's error text, empty when it sent none.
type ErrUnexpectedStatus struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e *ErrUnexpectedStatus) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s failed: %s (status %d)", e.Operation, e.Message, e.StatusCode)
	}
	return fmt.Sprintf("%s failed: status %d", e.Operation, e.StatusCode)
}

// ErrResponseReadFailed is returned when the body of a non-success response
// cannot be read.
type ErrResponseReadFailed struct {
	Operation  string
	StatusCode int
	Cause      error
}

func (e *ErrResponseReadFailed) Error() string {
	return fmt.Sprintf("%s failed: status %d, failed to read response body: %v", e.Operation, e.StatusCode, e.Cause)
}

func (e *ErrResponseReadFailed) Unwrap() error { return e.Cause }

// Ensure UserClient implements UserClientInterface.
var _ UserClientInterface = (*UserClient)(nil)
