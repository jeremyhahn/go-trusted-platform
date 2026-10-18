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

// Package invitation provides integration test adapters for Invitation services.
// This file implements protocol adapters for CLI, REST, gRPC, QUIC, MCP, and Unix.
package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLINotFound indicates the CLI tool was not found
type ErrCLINotFound struct {
	Path string
}

func (e ErrCLINotFound) Error() string {
	return fmt.Sprintf("CLI not found: %s", e.Path)
}

// ErrCLICommandFailed indicates a CLI command failed
type ErrCLICommandFailed struct {
	Operation string
	Message   string
	Output    string
}

func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("CLI command failed [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// ErrAdapterNotImplemented indicates the adapter method is not yet implemented
type ErrAdapterNotImplemented struct {
	Adapter   string
	Operation string
}

func (e ErrAdapterNotImplemented) Error() string {
	return fmt.Sprintf("%s adapter: %s not implemented", e.Adapter, e.Operation)
}

// ErrHTTPRequest indicates an HTTP request error
type ErrHTTPRequest struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e ErrHTTPRequest) Error() string {
	return fmt.Sprintf("HTTP %s %s failed with status %d: %s", e.Method, e.URL, e.StatusCode, e.Body)
}

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements InvitationCommands using the platformctl CLI
type CLIAdapter struct {
	cliPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return ErrCLINotFound{Path: a.cliPath}
	}
	return nil
}

// Teardown cleans up after testing
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, ErrCLICommandFailed{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
}

// CreateInvitation creates a new invitation via CLI
func (a *CLIAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	args := []string{"invitation", "create",
		"--tenant-id", opts.TenantID,
		"--email", opts.Email,
		"--role", opts.Role,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var inv Invitation
	if err := json.Unmarshal(output, &inv); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "CreateInvitation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateInvitationResult{Invitation: &inv}, nil
}

// GetInvitationByToken retrieves an invitation by token via CLI
func (a *CLIAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	args := []string{"invitation", "get",
		"--token", opts.Token,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var inv Invitation
	if err := json.Unmarshal(output, &inv); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "GetInvitationByToken",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetInvitationResult{Invitation: &inv}, nil
}

// ListInvitations lists invitations for a tenant via CLI
func (a *CLIAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	args := []string{"invitation", "list",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListInvitationsResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "ListInvitations",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// RevokeInvitation revokes an invitation via CLI
func (a *CLIAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	args := []string{"invitation", "revoke",
		"--tenant-id", opts.TenantID,
		"--id", fmt.Sprintf("%d", opts.InvitationID),
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result RevokeResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "RevokeInvitation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// AcceptInvitation accepts an invitation via CLI
func (a *CLIAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	args := []string{"invitation", "accept",
		"--token", opts.Token,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Password != "" {
		args = append(args, "--password", opts.Password)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result AcceptResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLICommandFailed{
			Operation: "AcceptInvitation",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &result, nil
}

// =============================================================================
// REST Protocol Adapter
// =============================================================================

// RESTAdapter implements InvitationCommands using the REST API
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
	authToken  string
}

// NewRESTAdapter creates a new REST adapter
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		baseURL: GetRESTEndpoint(),
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
	}
}

// Setup prepares the adapter for testing
func (a *RESTAdapter) Setup(ctx context.Context) error {
	a.authToken = GetAdminToken()
	return nil
}

// Teardown cleans up after testing
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *RESTAdapter) Name() string {
	return "REST"
}

// doRequest performs an HTTP request
func (a *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	url := a.baseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if a.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+a.authToken)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, ErrHTTPRequest{
			Method:     method,
			URL:        url,
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// CreateInvitation creates a new invitation via REST
func (a *RESTAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	body := map[string]interface{}{
		"email": opts.Email,
		"role":  opts.Role,
	}
	if opts.ExpiresIn > 0 {
		body["expires_in"] = opts.ExpiresIn
	}

	path := "/api/v1/invitations"
	respBody, err := a.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var inv Invitation
	if err := json.Unmarshal(respBody, &inv); err != nil {
		return nil, err
	}

	return &CreateInvitationResult{Invitation: &inv}, nil
}

// GetInvitationByToken retrieves an invitation by token via REST
func (a *RESTAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	path := "/api/v1/invitations/token/" + opts.Token
	respBody, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var inv Invitation
	if err := json.Unmarshal(respBody, &inv); err != nil {
		return nil, err
	}

	return &GetInvitationResult{Invitation: &inv}, nil
}

// ListInvitations lists invitations for a tenant via REST
func (a *RESTAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	path := fmt.Sprintf("/api/v1/invitations?limit=%d&offset=%d", opts.Limit, opts.Offset)
	respBody, err := a.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result ListInvitationsResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// RevokeInvitation revokes an invitation via REST
func (a *RESTAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	path := fmt.Sprintf("/api/v1/invitations/%d", opts.InvitationID)
	_, err := a.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return &RevokeResult{Success: true, Message: "invitation revoked"}, nil
}

// AcceptInvitation accepts an invitation via REST
func (a *RESTAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	body := map[string]string{
		"token": opts.Token,
	}
	if opts.Name != "" {
		body["name"] = opts.Name
	}
	if opts.Password != "" {
		body["password"] = opts.Password
	}

	path := "/api/v1/invitations/accept"
	respBody, err := a.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}

	var result AcceptResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements InvitationCommands using the gRPC API
type GRPCAdapter struct {
	endpoint string
}

// NewGRPCAdapter creates a new gRPC adapter
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the adapter for testing
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	// TODO: Establish gRPC connection
	return nil
}

// Teardown cleans up after testing
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	// TODO: Close gRPC connection
	return nil
}

// Name returns the adapter name
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// CreateInvitation creates a new invitation via gRPC
func (a *GRPCAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "gRPC", Operation: "CreateInvitation"}
}

// GetInvitationByToken retrieves an invitation by token via gRPC
func (a *GRPCAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "gRPC", Operation: "GetInvitationByToken"}
}

// ListInvitations lists invitations for a tenant via gRPC
func (a *GRPCAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "gRPC", Operation: "ListInvitations"}
}

// RevokeInvitation revokes an invitation via gRPC
func (a *GRPCAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "gRPC", Operation: "RevokeInvitation"}
}

// AcceptInvitation accepts an invitation via gRPC
func (a *GRPCAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "gRPC", Operation: "AcceptInvitation"}
}

// =============================================================================
// QUIC Protocol Adapter
// =============================================================================

// QUICAdapter implements InvitationCommands using the QUIC API
type QUICAdapter struct {
	endpoint string
}

// NewQUICAdapter creates a new QUIC adapter
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint: GetQUICEndpoint(),
	}
}

// Setup prepares the adapter for testing
func (a *QUICAdapter) Setup(ctx context.Context) error {
	// TODO: Establish QUIC connection
	return nil
}

// Teardown cleans up after testing
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	// TODO: Close QUIC connection
	return nil
}

// Name returns the adapter name
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// CreateInvitation creates a new invitation via QUIC
func (a *QUICAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "QUIC", Operation: "CreateInvitation"}
}

// GetInvitationByToken retrieves an invitation by token via QUIC
func (a *QUICAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "QUIC", Operation: "GetInvitationByToken"}
}

// ListInvitations lists invitations for a tenant via QUIC
func (a *QUICAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "QUIC", Operation: "ListInvitations"}
}

// RevokeInvitation revokes an invitation via QUIC
func (a *QUICAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "QUIC", Operation: "RevokeInvitation"}
}

// AcceptInvitation accepts an invitation via QUIC
func (a *QUICAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "QUIC", Operation: "AcceptInvitation"}
}

// =============================================================================
// MCP Protocol Adapter
// =============================================================================

// MCPAdapter implements InvitationCommands using the MCP API
type MCPAdapter struct {
	endpoint string
}

// NewMCPAdapter creates a new MCP adapter
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
	}
}

// Setup prepares the adapter for testing
func (a *MCPAdapter) Setup(ctx context.Context) error {
	// TODO: Establish MCP connection
	return nil
}

// Teardown cleans up after testing
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	// TODO: Close MCP connection
	return nil
}

// Name returns the adapter name
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// CreateInvitation creates a new invitation via MCP
func (a *MCPAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "MCP", Operation: "CreateInvitation"}
}

// GetInvitationByToken retrieves an invitation by token via MCP
func (a *MCPAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "MCP", Operation: "GetInvitationByToken"}
}

// ListInvitations lists invitations for a tenant via MCP
func (a *MCPAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "MCP", Operation: "ListInvitations"}
}

// RevokeInvitation revokes an invitation via MCP
func (a *MCPAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "MCP", Operation: "RevokeInvitation"}
}

// AcceptInvitation accepts an invitation via MCP
func (a *MCPAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "MCP", Operation: "AcceptInvitation"}
}

// =============================================================================
// Unix Socket Protocol Adapter
// =============================================================================

// UnixAdapter implements InvitationCommands using the Unix socket API
type UnixAdapter struct {
	socketPath string
}

// NewUnixAdapter creates a new Unix socket adapter
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup prepares the adapter for testing
func (a *UnixAdapter) Setup(ctx context.Context) error {
	// TODO: Connect to Unix socket
	return nil
}

// Teardown cleans up after testing
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	// TODO: Close Unix socket connection
	return nil
}

// Name returns the adapter name
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// CreateInvitation creates a new invitation via Unix socket
func (a *UnixAdapter) CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "Unix", Operation: "CreateInvitation"}
}

// GetInvitationByToken retrieves an invitation by token via Unix socket
func (a *UnixAdapter) GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "Unix", Operation: "GetInvitationByToken"}
}

// ListInvitations lists invitations for a tenant via Unix socket
func (a *UnixAdapter) ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "Unix", Operation: "ListInvitations"}
}

// RevokeInvitation revokes an invitation via Unix socket
func (a *UnixAdapter) RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "Unix", Operation: "RevokeInvitation"}
}

// AcceptInvitation accepts an invitation via Unix socket
func (a *UnixAdapter) AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error) {
	return nil, ErrAdapterNotImplemented{Adapter: "Unix", Operation: "AcceptInvitation"}
}
