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
// This file implements the CLI and REST adapters; sdk_adapters.go drives gRPC,
// QUIC, MCP and Unix through the platform SDK.
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

// ErrConnectionFailed indicates the SDK client could not connect on a transport
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection to %s failed: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error { return e.Err }

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
