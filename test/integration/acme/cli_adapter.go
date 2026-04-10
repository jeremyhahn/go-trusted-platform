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

// Package acme provides integration test adapters for ACME certificate services.
// This file implements the ACMECommands interface using the platformctl CLI binary.

//go:build integration

package acme

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements ACMECommands using the platformctl CLI binary.
// This adapter executes CLI commands and parses JSON output to test
// the complete CLI workflow in integration tests.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads configuration from environment variables with sensible defaults.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists and is executable.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	// Check if binary exists
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	// Verify binary works by running version command
	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Command Execution
// =============================================================================

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Create context with timeout if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	// Build command with common flags
	fullArgs := []string{
		"--output", "json",
	}

	// Add socket path if specified and not default
	if c.socketPath != "" && c.socketPath != DefaultPlatformdSocket {
		fullArgs = append(fullArgs, "--socket", c.socketPath)
	}

	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Include stderr in error for debugging
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCallFailed{
			Protocol: "CLI",
			Method:   strings.Join(args, " "),
			Err:      fmt.Errorf("%w: %s", err, output),
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Account Management Commands
// =============================================================================

// AccountCreate creates a new ACME account via CLI.
func (c *CLIAdapter) AccountCreate(ctx context.Context, opts AccountCreateOptions) (*AccountCreateResult, error) {
	args := []string{"acme", "account", "create"}

	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}

	if opts.DirectoryURL != "" {
		args = append(args, "--directory", opts.DirectoryURL)
	}

	if opts.TermsOfService {
		args = append(args, "--accept-tos")
	}

	if opts.ExternalAccountID != "" {
		args = append(args, "--eab-kid", opts.ExternalAccountID)
	}

	if opts.ExternalAccountKey != "" {
		args = append(args, "--eab-hmac-key", opts.ExternalAccountKey)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliAccountCreateResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AccountCreate", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// AccountList lists ACME accounts via CLI.
func (c *CLIAdapter) AccountList(ctx context.Context, opts AccountListOptions) (*AccountListResult, error) {
	args := []string{"acme", "account", "list"}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}

	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliAccountListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AccountList", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// AccountDelete deletes an ACME account via CLI.
func (c *CLIAdapter) AccountDelete(ctx context.Context, accountID string) (*AccountDeleteResult, error) {
	args := []string{"acme", "account", "delete", accountID, "--confirm"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliAccountDeleteResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AccountDelete", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Order Management Commands
// =============================================================================

// OrderCreate creates an ACME order via CLI.
func (c *CLIAdapter) OrderCreate(ctx context.Context, opts OrderCreateOptions) (*OrderCreateResult, error) {
	args := []string{"acme", "order", "create"}

	if opts.AccountID != "" {
		args = append(args, "--account", opts.AccountID)
	}

	for _, id := range opts.Identifiers {
		args = append(args, "--identifier", fmt.Sprintf("%s:%s", id.Type, id.Value))
	}

	if !opts.NotBefore.IsZero() {
		args = append(args, "--not-before", opts.NotBefore.Format(time.RFC3339))
	}

	if !opts.NotAfter.IsZero() {
		args = append(args, "--not-after", opts.NotAfter.Format(time.RFC3339))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliOrderCreateResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "OrderCreate", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// OrderList lists ACME orders via CLI.
func (c *CLIAdapter) OrderList(ctx context.Context, opts OrderListOptions) (*OrderListResult, error) {
	args := []string{"acme", "order", "list"}

	if opts.AccountID != "" {
		args = append(args, "--account", opts.AccountID)
	}

	if opts.Status != "" {
		args = append(args, "--status", opts.Status)
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}

	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliOrderListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "OrderList", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// OrderGet retrieves an ACME order via CLI.
func (c *CLIAdapter) OrderGet(ctx context.Context, orderID string) (*OrderGetResult, error) {
	args := []string{"acme", "order", "get", orderID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliOrderGetResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "OrderGet", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Certificate Commands
// =============================================================================

// CertificateRequest requests a certificate via CLI.
func (c *CLIAdapter) CertificateRequest(ctx context.Context, opts CertificateRequestOptions) (*CertificateRequestResult, error) {
	args := []string{"acme", "renew"}

	// Subject fields
	if opts.CommonName != "" {
		args = append(args, "--cn", opts.CommonName)
	}

	if opts.Organization != "" {
		args = append(args, "--organization", opts.Organization)
	}

	if opts.OrganizationalUnit != "" {
		args = append(args, "--organizational-unit", opts.OrganizationalUnit)
	}

	if opts.Country != "" {
		args = append(args, "--country", opts.Country)
	}

	if opts.Province != "" {
		args = append(args, "--province", opts.Province)
	}

	if opts.Locality != "" {
		args = append(args, "--locality", opts.Locality)
	}

	if opts.StreetAddress != "" {
		args = append(args, "--street-address", opts.StreetAddress)
	}

	if opts.PostalCode != "" {
		args = append(args, "--postal-code", opts.PostalCode)
	}

	// SAN fields
	for _, san := range opts.SANsDNS {
		args = append(args, "--sans-dns", san)
	}

	for _, san := range opts.SANsEmails {
		args = append(args, "--sans-email", san)
	}

	for _, san := range opts.SANsIPs {
		args = append(args, "--sans-ip", san)
	}

	// Authorization options
	if opts.AuthorizationType != "" {
		args = append(args, "--authz", opts.AuthorizationType)
	}

	if opts.ChallengeType != "" {
		args = append(args, "--challenge", opts.ChallengeType)
	}

	// ACME options
	if opts.DirectoryURL != "" {
		args = append(args, "--directory", opts.DirectoryURL)
	}

	if opts.CACert != "" {
		args = append(args, "--ca-cert", opts.CACert)
	}

	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliCertificateRequestResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CertificateRequest", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// CertificateRenew renews a certificate via CLI.
func (c *CLIAdapter) CertificateRenew(ctx context.Context, opts CertificateRenewOptions) (*CertificateRenewResult, error) {
	args := []string{"acme", "renew"}

	// Subject fields
	if opts.CommonName != "" {
		args = append(args, "--cn", opts.CommonName)
	}

	if opts.Organization != "" {
		args = append(args, "--organization", opts.Organization)
	}

	if opts.OrganizationalUnit != "" {
		args = append(args, "--organizational-unit", opts.OrganizationalUnit)
	}

	if opts.Country != "" {
		args = append(args, "--country", opts.Country)
	}

	if opts.Province != "" {
		args = append(args, "--province", opts.Province)
	}

	if opts.Locality != "" {
		args = append(args, "--locality", opts.Locality)
	}

	if opts.StreetAddress != "" {
		args = append(args, "--street-address", opts.StreetAddress)
	}

	if opts.PostalCode != "" {
		args = append(args, "--postal-code", opts.PostalCode)
	}

	// SAN fields
	for _, san := range opts.SANsDNS {
		args = append(args, "--sans-dns", san)
	}

	for _, san := range opts.SANsEmails {
		args = append(args, "--sans-email", san)
	}

	for _, san := range opts.SANsIPs {
		args = append(args, "--sans-ip", san)
	}

	// Authorization options
	if opts.AuthorizationType != "" {
		args = append(args, "--authz", opts.AuthorizationType)
	}

	if opts.ChallengeType != "" {
		args = append(args, "--challenge", opts.ChallengeType)
	}

	// ACME options
	if opts.DirectoryURL != "" {
		args = append(args, "--directory", opts.DirectoryURL)
	}

	if opts.CACert != "" {
		args = append(args, "--ca-cert", opts.CACert)
	}

	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliCertificateRenewResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CertificateRenew", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// CertificateRevoke revokes a certificate via CLI.
func (c *CLIAdapter) CertificateRevoke(ctx context.Context, opts CertificateRevokeOptions) (*CertificateRevokeResult, error) {
	args := []string{"acme", "certificate", "revoke"}

	if opts.CertificateURL != "" {
		args = append(args, "--url", opts.CertificateURL)
	}

	if opts.SerialNumber != "" {
		args = append(args, "--serial", opts.SerialNumber)
	}

	if opts.Reason > 0 {
		args = append(args, "--reason", strconv.Itoa(opts.Reason))
	}

	args = append(args, "--confirm")

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliCertificateRevokeResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CertificateRevoke", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Challenge Commands
// =============================================================================

// ChallengeEnroll01 executes the enroll-01 custom challenge via CLI.
func (c *CLIAdapter) ChallengeEnroll01(ctx context.Context, opts ChallengeEnroll01Options) (*ChallengeEnroll01Result, error) {
	args := []string{"acme", "challenge", "enroll-01"}

	if opts.OrderID != "" {
		args = append(args, "--order", opts.OrderID)
	}

	if opts.AccountID != "" {
		args = append(args, "--account", opts.AccountID)
	}

	if opts.DeviceSerial != "" {
		args = append(args, "--device-serial", opts.DeviceSerial)
	}

	if opts.DeviceModel != "" {
		args = append(args, "--device-model", opts.DeviceModel)
	}

	if opts.TPMHandle != 0 {
		args = append(args, "--tpm-handle", fmt.Sprintf("0x%08X", opts.TPMHandle))
	}

	if opts.AttestKeyPEM != "" {
		args = append(args, "--attest-key", opts.AttestKeyPEM)
	}

	if len(opts.QuoteData) > 0 {
		args = append(args, "--quote", base64.StdEncoding.EncodeToString(opts.QuoteData))
	}

	// PCR values are passed as comma-separated index:value pairs
	if len(opts.PCRValues) > 0 {
		var pcrPairs []string
		for idx, val := range opts.PCRValues {
			pcrPairs = append(pcrPairs, fmt.Sprintf("%d:%s", idx, base64.StdEncoding.EncodeToString(val)))
		}
		args = append(args, "--pcrs", strings.Join(pcrPairs, ","))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliChallengeEnroll01Response
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ChallengeEnroll01", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

// Account response types

type cliAccountCreateResponse struct {
	AccountID    string `json:"account_id,omitempty"`
	Status       string `json:"status,omitempty"`
	Email        string `json:"email,omitempty"`
	DirectoryURL string `json:"directory_url,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
}

func (r *cliAccountCreateResponse) toResult() *AccountCreateResult {
	return &AccountCreateResult{
		AccountID:    r.AccountID,
		Status:       r.Status,
		Email:        r.Email,
		DirectoryURL: r.DirectoryURL,
		CreatedAt:    time.Unix(r.CreatedAt, 0),
		KeyID:        r.KeyID,
	}
}

type cliAccountListResponse struct {
	Accounts   []cliAccountSummary `json:"accounts,omitempty"`
	TotalCount int32               `json:"total_count,omitempty"`
	HasMore    bool                `json:"has_more,omitempty"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type cliAccountSummary struct {
	AccountID    string `json:"account_id,omitempty"`
	Status       string `json:"status,omitempty"`
	Email        string `json:"email,omitempty"`
	DirectoryURL string `json:"directory_url,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
}

func (r *cliAccountListResponse) toResult() *AccountListResult {
	result := &AccountListResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, acc := range r.Accounts {
		result.Accounts = append(result.Accounts, AccountSummary{
			AccountID:    acc.AccountID,
			Status:       acc.Status,
			Email:        acc.Email,
			DirectoryURL: acc.DirectoryURL,
			CreatedAt:    time.Unix(acc.CreatedAt, 0),
		})
	}

	return result
}

type cliAccountDeleteResponse struct {
	AccountID string `json:"account_id,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

func (r *cliAccountDeleteResponse) toResult() *AccountDeleteResult {
	return &AccountDeleteResult{
		AccountID: r.AccountID,
		Deleted:   r.Deleted,
	}
}

// Order response types

type cliOrderCreateResponse struct {
	OrderID        string               `json:"order_id,omitempty"`
	Status         string               `json:"status,omitempty"`
	Expires        int64                `json:"expires,omitempty"`
	Identifiers    []cliOrderIdentifier `json:"identifiers,omitempty"`
	Authorizations []string             `json:"authorizations,omitempty"`
	Finalize       string               `json:"finalize,omitempty"`
	CreatedAt      int64                `json:"created_at,omitempty"`
}

type cliOrderIdentifier struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

func (r *cliOrderCreateResponse) toResult() *OrderCreateResult {
	result := &OrderCreateResult{
		OrderID:        r.OrderID,
		Status:         r.Status,
		Expires:        time.Unix(r.Expires, 0),
		Authorizations: r.Authorizations,
		Finalize:       r.Finalize,
		CreatedAt:      time.Unix(r.CreatedAt, 0),
	}

	for _, id := range r.Identifiers {
		result.Identifiers = append(result.Identifiers, OrderIdentifier{
			Type:  id.Type,
			Value: id.Value,
		})
	}

	return result
}

type cliOrderListResponse struct {
	Orders     []cliOrderSummary `json:"orders,omitempty"`
	TotalCount int32             `json:"total_count,omitempty"`
	HasMore    bool              `json:"has_more,omitempty"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

type cliOrderSummary struct {
	OrderID     string               `json:"order_id,omitempty"`
	Status      string               `json:"status,omitempty"`
	Expires     int64                `json:"expires,omitempty"`
	Identifiers []cliOrderIdentifier `json:"identifiers,omitempty"`
	CreatedAt   int64                `json:"created_at,omitempty"`
}

func (r *cliOrderListResponse) toResult() *OrderListResult {
	result := &OrderListResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, o := range r.Orders {
		summary := OrderSummary{
			OrderID:   o.OrderID,
			Status:    o.Status,
			Expires:   time.Unix(o.Expires, 0),
			CreatedAt: time.Unix(o.CreatedAt, 0),
		}
		for _, id := range o.Identifiers {
			summary.Identifiers = append(summary.Identifiers, OrderIdentifier{
				Type:  id.Type,
				Value: id.Value,
			})
		}
		result.Orders = append(result.Orders, summary)
	}

	return result
}

type cliOrderGetResponse struct {
	OrderID        string                 `json:"order_id,omitempty"`
	Status         string                 `json:"status,omitempty"`
	Expires        int64                  `json:"expires,omitempty"`
	Identifiers    []cliOrderIdentifier   `json:"identifiers,omitempty"`
	Authorizations []cliAuthorizationInfo `json:"authorizations,omitempty"`
	Finalize       string                 `json:"finalize,omitempty"`
	Certificate    string                 `json:"certificate,omitempty"`
	CreatedAt      int64                  `json:"created_at,omitempty"`
	UpdatedAt      int64                  `json:"updated_at,omitempty"`
}

type cliAuthorizationInfo struct {
	URL        string             `json:"url,omitempty"`
	Status     string             `json:"status,omitempty"`
	Identifier cliOrderIdentifier `json:"identifier,omitempty"`
	Challenges []cliChallengeInfo `json:"challenges,omitempty"`
	Expires    int64              `json:"expires,omitempty"`
}

type cliChallengeInfo struct {
	Type      string `json:"type,omitempty"`
	URL       string `json:"url,omitempty"`
	Status    string `json:"status,omitempty"`
	Token     string `json:"token,omitempty"`
	Validated int64  `json:"validated,omitempty"`
}

func (r *cliOrderGetResponse) toResult() *OrderGetResult {
	result := &OrderGetResult{
		OrderID:     r.OrderID,
		Status:      r.Status,
		Expires:     time.Unix(r.Expires, 0),
		Finalize:    r.Finalize,
		Certificate: r.Certificate,
		CreatedAt:   time.Unix(r.CreatedAt, 0),
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}

	for _, id := range r.Identifiers {
		result.Identifiers = append(result.Identifiers, OrderIdentifier{
			Type:  id.Type,
			Value: id.Value,
		})
	}

	for _, auth := range r.Authorizations {
		authInfo := AuthorizationInfo{
			URL:    auth.URL,
			Status: auth.Status,
			Identifier: OrderIdentifier{
				Type:  auth.Identifier.Type,
				Value: auth.Identifier.Value,
			},
			Expires: time.Unix(auth.Expires, 0),
		}
		for _, ch := range auth.Challenges {
			authInfo.Challenges = append(authInfo.Challenges, ChallengeInfo{
				Type:      ch.Type,
				URL:       ch.URL,
				Status:    ch.Status,
				Token:     ch.Token,
				Validated: time.Unix(ch.Validated, 0),
			})
		}
		result.Authorizations = append(result.Authorizations, authInfo)
	}

	return result
}

// Certificate response types

type cliCertificateRequestResponse struct {
	OrderID        string `json:"order_id,omitempty"`
	Status         string `json:"status,omitempty"`
	CertificateURL string `json:"certificate_url,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	NotBefore      int64  `json:"not_before,omitempty"`
	NotAfter       int64  `json:"not_after,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Subject        string `json:"subject,omitempty"`
}

func (r *cliCertificateRequestResponse) toResult() *CertificateRequestResult {
	return &CertificateRequestResult{
		OrderID:        r.OrderID,
		Status:         r.Status,
		CertificateURL: r.CertificateURL,
		CertificatePEM: r.CertificatePEM,
		ChainPEM:       r.ChainPEM,
		NotBefore:      time.Unix(r.NotBefore, 0),
		NotAfter:       time.Unix(r.NotAfter, 0),
		SerialNumber:   r.SerialNumber,
		Issuer:         r.Issuer,
		Subject:        r.Subject,
	}
}

type cliCertificateRenewResponse struct {
	OrderID        string `json:"order_id,omitempty"`
	Status         string `json:"status,omitempty"`
	CertificateURL string `json:"certificate_url,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	ChainPEM       string `json:"chain_pem,omitempty"`
	NotBefore      int64  `json:"not_before,omitempty"`
	NotAfter       int64  `json:"not_after,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	Subject        string `json:"subject,omitempty"`
	RenewedAt      int64  `json:"renewed_at,omitempty"`
}

func (r *cliCertificateRenewResponse) toResult() *CertificateRenewResult {
	return &CertificateRenewResult{
		OrderID:        r.OrderID,
		Status:         r.Status,
		CertificateURL: r.CertificateURL,
		CertificatePEM: r.CertificatePEM,
		ChainPEM:       r.ChainPEM,
		NotBefore:      time.Unix(r.NotBefore, 0),
		NotAfter:       time.Unix(r.NotAfter, 0),
		SerialNumber:   r.SerialNumber,
		Issuer:         r.Issuer,
		Subject:        r.Subject,
		RenewedAt:      time.Unix(r.RenewedAt, 0),
	}
}

type cliCertificateRevokeResponse struct {
	CertificateURL string `json:"certificate_url,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	Revoked        bool   `json:"revoked,omitempty"`
	RevokedAt      int64  `json:"revoked_at,omitempty"`
	Reason         int    `json:"reason,omitempty"`
}

func (r *cliCertificateRevokeResponse) toResult() *CertificateRevokeResult {
	return &CertificateRevokeResult{
		CertificateURL: r.CertificateURL,
		SerialNumber:   r.SerialNumber,
		Revoked:        r.Revoked,
		RevokedAt:      time.Unix(r.RevokedAt, 0),
		Reason:         r.Reason,
	}
}

// Challenge response types

type cliChallengeEnroll01Response struct {
	Status         string `json:"status,omitempty"`
	Validated      bool   `json:"validated,omitempty"`
	ValidatedAt    int64  `json:"validated_at,omitempty"`
	CertificateURL string `json:"certificate_url,omitempty"`
	DeviceID       string `json:"device_id,omitempty"`
	AttestationOK  bool   `json:"attestation_ok,omitempty"`
	PCRsVerified   bool   `json:"pcrs_verified,omitempty"`
}

func (r *cliChallengeEnroll01Response) toResult() *ChallengeEnroll01Result {
	return &ChallengeEnroll01Result{
		Status:         r.Status,
		Validated:      r.Validated,
		ValidatedAt:    time.Unix(r.ValidatedAt, 0),
		CertificateURL: r.CertificateURL,
		DeviceID:       r.DeviceID,
		AttestationOK:  r.AttestationOK,
		PCRsVerified:   r.PCRsVerified,
	}
}

// Ensure CLIAdapter implements ACMECommands interface.
var _ ACMECommands = (*CLIAdapter)(nil)
