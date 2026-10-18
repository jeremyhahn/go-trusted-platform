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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
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
	configDir      string
	configPath     string
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

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path

	// Verify binary works by running version command
	_, err = c.runCommand(ctx, "version")
	if err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	return os.RemoveAll(c.configDir)
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

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath)
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
	// acme register has one flag, --email (pkg/cli/commands/acme/register.go):
	// it takes no --directory or --ca-cert, so opts.DirectoryURL is not
	// passed, and it has no external account binding flags.
	if opts.ExternalAccountID != "" || opts.ExternalAccountKey != "" {
		return nil, ErrCLIFlagNotDocumented{Verb: "register", Option: "external account binding"}
	}

	args := []string{"acme", "register"}

	if opts.Email != "" {
		args = append(args, "--email", opts.Email)
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

// AccountList has no platformctl verb: the CLI registers an account but
// does not list them (docs/ca/cli.md §3).
func (c *CLIAdapter) AccountList(_ context.Context, _ AccountListOptions) (*AccountListResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "AccountList"}
}

// AccountDelete has no platformctl verb (docs/ca/cli.md §3).
func (c *CLIAdapter) AccountDelete(_ context.Context, _ string) (*AccountDeleteResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "AccountDelete"}
}

// =============================================================================
// Order Management Commands
// =============================================================================

// OrderCreate has no platformctl verb: acme renew places and finalizes the
// order in one step (docs/ca/cli.md §3).
func (c *CLIAdapter) OrderCreate(_ context.Context, _ OrderCreateOptions) (*OrderCreateResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "OrderCreate"}
}

// OrderList has no platformctl verb (docs/ca/cli.md §3).
func (c *CLIAdapter) OrderList(_ context.Context, _ OrderListOptions) (*OrderListResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "OrderList"}
}

// OrderGet has no platformctl verb (docs/ca/cli.md §3).
func (c *CLIAdapter) OrderGet(_ context.Context, _ string) (*OrderGetResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "OrderGet"}
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

// CertificateRevoke has no platformctl verb (docs/ca/cli.md §3).
func (c *CLIAdapter) CertificateRevoke(_ context.Context, _ CertificateRevokeOptions) (*CertificateRevokeResult, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "CertificateRevoke"}
}

// =============================================================================
// Challenge Commands
// =============================================================================

// ChallengeEnroll01 has no platformctl verb: device challenges are chosen
// with acme renew --challenge (docs/ca/cli.md §3).
func (c *CLIAdapter) ChallengeEnroll01(_ context.Context, _ ChallengeEnroll01Options) (*ChallengeEnroll01Result, error) {
	return nil, ErrCLIVerbNotDocumented{Operation: "ChallengeEnroll01"}
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

// Ensure CLIAdapter implements ACMECommands interface.
var _ ACMECommands = (*CLIAdapter)(nil)
