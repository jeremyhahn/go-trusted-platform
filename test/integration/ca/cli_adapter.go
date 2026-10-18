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

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements CACommands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath   string
	socketPath   string
	grpcEndpoint string
	configPath   string
	configDir    string
}

// NewCLIAdapter creates a new CLI protocol adapter instance.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	socketPath := resolveCLISocketPath()

	grpcEndpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if grpcEndpoint == "" {
		grpcEndpoint = GetServiceEndpoints().PlatformGRPC
	}

	return &CLIAdapter{
		binaryPath:   binaryPath,
		socketPath:   socketPath,
		grpcEndpoint: grpcEndpoint,
	}
}

// resolveCLISocketPath resolves the Unix socket path using the three-fallback
// convention: PLATFORMD_SOCKET → PLATFORM_UNIX_SOCKET → PLATFORM_SOCKET_PATH → default.
func resolveCLISocketPath() string {
	if v := os.Getenv("PLATFORMD_SOCKET"); v != "" {
		return v
	}
	if v := os.Getenv("PLATFORM_UNIX_SOCKET"); v != "" {
		return v
	}
	if v := os.Getenv("PLATFORM_SOCKET_PATH"); v != "" {
		return v
	}
	return GetServiceEndpoints().PlatformUnix
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup initializes the CLI adapter by locating the platformctl binary
// and creating a temporary config file for connecting to the test daemon.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	// Check if the binary exists and is executable
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	c.binaryPath = binaryPath

	// Re-read env vars in case they were set by TestMain after NewCLIAdapter
	c.socketPath = resolveCLISocketPath()
	if grpcEndpoint := os.Getenv(EnvPlatformGRPCEndpoint); grpcEndpoint != "" {
		c.grpcEndpoint = grpcEndpoint
	}

	// Create a temporary config file for CLI to connect to test daemon
	if configErr := c.createTestConfig(); configErr != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: configErr}
	}

	// Verify connectivity by running a simple command
	_, err = c.runCommand(ctx, "ca", "info", "--output", "json")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	return nil
}

// Teardown performs cleanup of temporary config files created during setup.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// =============================================================================
// Config File Management
// =============================================================================

// createTestConfig creates a temporary YAML config file that tells
// the CLI where to connect to the test daemon instance.
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-ca-test-*")
	if err != nil {
		return ErrCLIConfigCreationFailed{Cause: err}
	}
	c.configDir = tmpDir

	// The kms verbs the CA suite runs (`kms key csr`) open the CLI's
	// quicbaas client. The shared harness config points it at platformd's
	// gRPC listener with the harness mTLS files (docs/kms/cli.md §3).
	configPath, writeErr := helpers.WriteLocalCLIConfig(tmpDir, c.socketPath, c.grpcEndpoint)
	if writeErr != nil {
		return ErrCLIConfigCreationFailed{Cause: writeErr}
	}

	c.configPath = configPath
	return nil
}

// =============================================================================
// Command Execution
// =============================================================================

// ErrCLICommandFailed indicates a CLI command execution failure.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	return fmt.Sprintf("CLI command '%s' failed: %s: %v", e.Command, e.Output, e.Err)
}

func (e ErrCLICommandFailed) Unwrap() error {
	return e.Err
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Prepend config and context flags if we have a config file
	var fullArgs []string
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath, "--context", "integration-test")
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Domain JSON Types
//
// The CLI outputs domain types from sdk/go/services/ca/types.go serialized with
// encoding/json. Timestamps are RFC3339 strings (time.Time), status and
// key_algorithm are strings, and bytes fields (pem/der) are base64-encoded strings.
// =============================================================================

// cliCertSummary mirrors casvc.CertificateSummary JSON output.
type cliCertSummary struct {
	Serial       string    `json:"serial"`
	CommonName   string    `json:"common_name"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	KeyAlgorithm string    `json:"key_algorithm"`
}

// cliKeyStoreInfo mirrors casvc.KeyStoreInfo JSON output.
type cliKeyStoreInfo struct {
	Type         string   `json:"type"`
	Available    bool     `json:"available"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// cliSubject mirrors casvc.Subject JSON output.
type cliSubject struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization,omitempty"`
}

// cliSANs mirrors casvc.SubjectAlternativeNames JSON output.
type cliSANs struct {
	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	EmailAddresses []string `json:"email_addresses,omitempty"`
}

// cliCertificate mirrors casvc.Certificate JSON output.
type cliCertificate struct {
	Serial             string      `json:"serial"`
	Subject            *cliSubject `json:"subject,omitempty"`
	Issuer             string      `json:"issuer"`
	NotBefore          time.Time   `json:"not_before"`
	NotAfter           time.Time   `json:"not_after"`
	Status             string      `json:"status"`
	KeyAlgorithm       string      `json:"key_algorithm"`
	SignatureAlgorithm string      `json:"signature_algorithm"`
	IsCa               bool        `json:"is_ca"`
	FingerprintSha256  string      `json:"fingerprint_sha256,omitempty"`
	SANs               *cliSANs    `json:"sans,omitempty"`
	Pem                []byte      `json:"pem,omitempty"`
	Der                []byte      `json:"der,omitempty"`
}

// cliRevokedCertEntry mirrors casvc.RevokedCertEntry JSON output.
type cliRevokedCertEntry struct {
	Serial         string    `json:"serial"`
	RevocationTime time.Time `json:"revocation_time"`
	Reason         string    `json:"reason"`
}

// =============================================================================
// Enum Conversion
// =============================================================================

// parseCertStatusString converts a domain CertificateStatus string to CertificateStatus.
var certStatusStringMap = map[string]CertificateStatus{
	"UNSPECIFIED": CertificateStatusUnspecified,
	"VALID":       CertificateStatusValid,
	"REVOKED":     CertificateStatusRevoked,
	"EXPIRED":     CertificateStatusExpired,
	"PENDING":     CertificateStatusPending,
}

func parseCertStatusString(s string) CertificateStatus {
	if v, ok := certStatusStringMap[strings.ToUpper(s)]; ok {
		return v
	}
	return CertificateStatusUnspecified
}

// parseRevocationReasonString converts a domain RevocationReason string to RevocationReason.
func parseRevocationReasonString(reason string) RevocationReason {
	reasonMap := map[string]RevocationReason{
		"UNSPECIFIED":            RevocationReasonUnspecified,
		"KEY_COMPROMISE":         RevocationReasonKeyCompromise,
		"CA_COMPROMISE":          RevocationReasonCACompromise,
		"AFFILIATION_CHANGED":    RevocationReasonAffiliationChanged,
		"SUPERSEDED":             RevocationReasonSuperseded,
		"CESSATION_OF_OPERATION": RevocationReasonCessationOfOperation,
		"CERTIFICATE_HOLD":       RevocationReasonCertificateHold,
		"PRIVILEGE_WITHDRAWN":    RevocationReasonPrivilegeWithdrawn,
	}
	if r, ok := reasonMap[strings.ToUpper(reason)]; ok {
		return r
	}
	return RevocationReasonUnspecified
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via CLI.
// The CLI prints *casvc.CAInfo directly (no wrapper object).
func (c *CLIAdapter) Info(ctx context.Context) (*InfoResult, error) {
	output, err := c.runCommand(ctx, "ca", "info", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca info", Err: err}
	}

	// The CLI prints *casvc.CAInfo directly (fields at top level, no ca_info wrapper).
	var resp struct {
		IsInitialized       bool               `json:"is_initialized"`
		CommonName          string             `json:"common_name"`
		IsIntermediate      bool               `json:"is_intermediate"`
		DefaultAlgorithm    string             `json:"default_algorithm"`
		DefaultValidityDays int32              `json:"default_validity_days"`
		RootCert            *cliCertSummary    `json:"root_cert,omitempty"`
		Intermediates       []*cliCertSummary  `json:"intermediates,omitempty"`
		KeyStores           []*cliKeyStoreInfo `json:"key_stores,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca info", Err: err}
	}

	result := &InfoResult{
		CommonName:          resp.CommonName,
		IsInitialized:       resp.IsInitialized,
		IsIntermediate:      resp.IsIntermediate,
		DefaultAlgorithm:    resp.DefaultAlgorithm,
		DefaultValidityDays: resp.DefaultValidityDays,
	}

	if resp.RootCert != nil {
		rc := resp.RootCert
		result.RootCertificate = &CertificateSummary{
			Serial:       rc.Serial,
			CommonName:   rc.CommonName,
			Issuer:       rc.Issuer,
			KeyAlgorithm: rc.KeyAlgorithm,
			Status:       parseCertStatusString(rc.Status),
			NotBefore:    rc.NotBefore,
			NotAfter:     rc.NotAfter,
		}
	}

	for _, inter := range resp.Intermediates {
		if inter == nil {
			continue
		}
		cs := CertificateSummary{
			Serial:       inter.Serial,
			CommonName:   inter.CommonName,
			Issuer:       inter.Issuer,
			KeyAlgorithm: inter.KeyAlgorithm,
			Status:       parseCertStatusString(inter.Status),
			NotBefore:    inter.NotBefore,
			NotAfter:     inter.NotAfter,
		}
		result.Intermediates = append(result.Intermediates, cs)
	}

	for _, ks := range resp.KeyStores {
		if ks == nil {
			continue
		}
		result.KeyStores = append(result.KeyStores, KeyStoreInfo{
			Type:         ks.Type,
			Available:    ks.Available,
			Capabilities: ks.Capabilities,
		})
	}

	return result, nil
}

// =============================================================================
// CA Init Operations
// =============================================================================

// Init initializes the CA via CLI.
func (c *CLIAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	args := []string{"ca", "init", "--output", "json"}

	if opts.Force {
		args = append(args, "--force")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca init", Err: err}
	}

	// CLI prints *casvc.CAInfo on success; treat any valid JSON as success.
	var raw json.RawMessage
	if jsonErr := json.Unmarshal(output, &raw); jsonErr != nil {
		// Non-JSON but command succeeded → treat as success
		return &InitResult{Success: true}, nil
	}

	return &InitResult{Success: true}, nil
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via CLI.
func (c *CLIAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
	args := []string{"ca", "issue", opts.CommonName, opts.StoreType, opts.Algorithm, "--output", "json"}

	if len(opts.SANsDNS) > 0 {
		args = append(args, "--sans-dns", strings.Join(opts.SANsDNS, ","))
	}
	if len(opts.SANsIPs) > 0 {
		args = append(args, "--sans-ips", strings.Join(opts.SANsIPs, ","))
	}
	if len(opts.SANsEmail) > 0 {
		args = append(args, "--sans-email", strings.Join(opts.SANsEmail, ","))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca issue", Err: err}
	}
	return parseCLIIssueResult(output, "ca issue")
}

// SignCSR certifies opts.CSRPEM through 'ca sign-csr', which reads the CSR
// from a file.
func (c *CLIAdapter) SignCSR(ctx context.Context, opts SignCSROptions) (*IssueCertificateResult, error) {
	csrFile, err := os.CreateTemp("", "ca-sign-csr-*.csr")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca sign-csr", Err: err}
	}
	defer os.Remove(csrFile.Name())

	if _, err := csrFile.WriteString(opts.CSRPEM); err != nil {
		csrFile.Close()
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca sign-csr", Err: err}
	}
	if err := csrFile.Close(); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca sign-csr", Err: err}
	}

	args := []string{"ca", "sign-csr", csrFile.Name(), "--output", "json"}
	if opts.ValidDays > 0 {
		args = append(args, "--valid-days", fmt.Sprintf("%d", opts.ValidDays))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca sign-csr", Err: err}
	}
	return parseCLIIssueResult(output, "ca sign-csr")
}

// parseCLIIssueResult decodes the *casvc.IssueCertificateResult that both
// 'ca issue' and 'ca sign-csr' print: {certificate: {...}}.
func parseCLIIssueResult(output []byte, method string) (*IssueCertificateResult, error) {
	var resp struct {
		Certificate *cliCertificate `json:"certificate,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: method, Err: err}
	}

	result := &IssueCertificateResult{}

	if resp.Certificate != nil {
		cert := convertCLICertificate(resp.Certificate)
		result.Certificate = cert
		result.Success = cert.Serial != ""
	}

	return result, nil
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via CLI.
func (c *CLIAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	identifier := opts.Serial
	if identifier == "" && opts.CommonName != "" {
		identifier = opts.CommonName
	}
	if identifier == "" {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: ErrInvalidSerial{Serial: "<empty>"}}
	}

	args := []string{"ca", "certificate", identifier, "--output", "json"}

	if opts.IncludePEM {
		args = append(args, "--pem")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: err}
	}

	// CLI prints *casvc.Certificate directly (no wrapper).
	var cert cliCertificate

	if err := json.Unmarshal(output, &cert); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: err}
	}

	if cert.Serial == "" {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: ErrCertificateNotFound{Identifier: identifier}}
	}

	return &GetCertificateResult{
		Certificate: convertCLICertificate(&cert),
	}, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via CLI.
func (c *CLIAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
	args := []string{"ca", "list", "--output", "json"}

	if opts.Status != "" && opts.Status != "all" {
		args = append(args, "--status", opts.Status)
	}
	if opts.Issuer != "" {
		args = append(args, "--issuer", opts.Issuer)
	}
	if opts.Limit > 0 {
		args = append(args, "--page-size", fmt.Sprintf("%d", opts.Limit))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca list", Err: err}
	}

	// CLI prints *casvc.ListCertificatesResult:
	// {certificates: [...], page, total_pages, total_items}
	var resp struct {
		Certificates []*cliCertSummary `json:"certificates"`
		Page         uint32            `json:"page"`
		TotalPages   uint32            `json:"total_pages"`
		TotalItems   uint64            `json:"total_items"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca list", Err: err}
	}

	result := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(resp.Certificates)),
		Total:        int32(resp.TotalItems),
	}

	for _, cert := range resp.Certificates {
		if cert == nil {
			continue
		}
		cs := CertificateSummary{
			Serial:       cert.Serial,
			CommonName:   cert.CommonName,
			Issuer:       cert.Issuer,
			KeyAlgorithm: cert.KeyAlgorithm,
			Status:       parseCertStatusString(cert.Status),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
		}
		result.Certificates = append(result.Certificates, cs)
	}

	return result, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via CLI.
// The CLI "ca verify" command takes a path to a PEM certificate file.
// When called with a serial or PEM bytes, the adapter fetches/writes to a temp
// file first.
func (c *CLIAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	var certPath string
	var tempFile string

	if opts.CertPath != "" {
		certPath = opts.CertPath
	} else if len(opts.CertificatePEM) > 0 {
		tmpFile, err := os.CreateTemp("", "ca-verify-*.pem")
		if err != nil {
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
		}
		tempFile = tmpFile.Name()
		if _, writeErr := tmpFile.Write(opts.CertificatePEM); writeErr != nil {
			tmpFile.Close()
			os.Remove(tempFile)
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: writeErr}
		}
		tmpFile.Close()
		certPath = tempFile
	} else if opts.Serial != "" {
		pemData, err := c.fetchCertPEM(ctx, opts.Serial)
		if err != nil {
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
		}
		tmpFile, err := os.CreateTemp("", "ca-verify-*.pem")
		if err != nil {
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
		}
		tempFile = tmpFile.Name()
		if _, writeErr := tmpFile.Write(pemData); writeErr != nil {
			tmpFile.Close()
			os.Remove(tempFile)
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: writeErr}
		}
		tmpFile.Close()
		certPath = tempFile
	} else {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: ErrInvalidSerial{Serial: "<empty>"}}
	}

	if tempFile != "" {
		defer os.Remove(tempFile)
	}

	args := []string{"ca", "verify", certPath, "--output", "json"}

	if !opts.CheckCRL {
		args = append(args, "--crl=false")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
	}

	// CLI prints *casvc.VerifyCertificateResult: {valid, chain, errors, warnings}
	var resp struct {
		Valid    bool     `json:"valid"`
		Chain    []string `json:"chain,omitempty"`
		Errors   []string `json:"errors,omitempty"`
		Warnings []string `json:"warnings,omitempty"`
		Revoked  bool     `json:"revoked"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
	}

	return &VerifyCertificateResult{
		Valid:         resp.Valid,
		Revoked:       resp.Revoked,
		ChainValid:    resp.Valid && len(resp.Errors) == 0,
		ChainLength:   len(resp.Chain),
		ChainSubjects: resp.Chain,
		Errors:        resp.Errors,
		Warnings:      resp.Warnings,
	}, nil
}

// fetchCertPEM retrieves the PEM data for a certificate by its serial number.
func (c *CLIAdapter) fetchCertPEM(ctx context.Context, serial string) ([]byte, error) {
	output, err := c.runCommand(ctx, "ca", "certificate", serial, "--pem", "--output", "json")
	if err != nil {
		return nil, err
	}

	// CLI prints *casvc.Certificate directly.
	var cert cliCertificate
	if err := json.Unmarshal(output, &cert); err != nil {
		return nil, err
	}

	if len(cert.Pem) == 0 {
		return nil, ErrCertificateNotFound{Identifier: serial}
	}

	return cert.Pem, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via CLI.
func (c *CLIAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	serial := opts.Serial
	if serial == "" {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca revoke", Err: ErrInvalidSerial{Serial: "<empty>"}}
	}

	args := []string{"ca", "revoke", serial, "--output", "json"}

	if opts.DeleteKeys {
		args = append(args, "--delete-keys")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca revoke", Err: err}
	}

	// CLI prints *casvc.RevokeCertificateResult:
	// {serial, reason (string), revoked_at (RFC3339 time.Time), success, message}
	var resp struct {
		Serial    string    `json:"serial"`
		Reason    string    `json:"reason"`
		RevokedAt time.Time `json:"revoked_at"`
		Success   bool      `json:"success"`
		Message   string    `json:"message,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca revoke", Err: err}
	}

	return &RevokeCertificateResult{
		Serial:    resp.Serial,
		Status:    CertificateStatusRevoked,
		Reason:    parseRevocationReasonString(resp.Reason),
		Success:   resp.Success,
		Message:   resp.Message,
		RevokedAt: resp.RevokedAt,
	}, nil
}

// =============================================================================
// Certificate Renew Operations
// =============================================================================

// RenewCertificate renews a certificate via CLI.
func (c *CLIAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
	args := []string{"ca", "renew", opts.Serial, "--output", "json"}

	if opts.ValidDays > 0 {
		args = append(args, "--days", fmt.Sprintf("%d", opts.ValidDays))
	}
	if opts.Force {
		args = append(args, "--force")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca renew", Err: err}
	}

	// CLI prints *casvc.RenewCertificateResult: {new_certificate: {...}}
	var resp struct {
		NewCertificate *cliCertificate `json:"new_certificate,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca renew", Err: err}
	}

	result := &RenewCertificateResult{}

	if resp.NewCertificate != nil {
		result.NewCertificate = convertCLICertificate(resp.NewCertificate)
		result.Success = result.NewCertificate.Serial != ""
	}

	return result, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via CLI.
func (c *CLIAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	args := []string{"ca", "crl", "--output", "json"}
	if opts.IncludeEntries {
		args = append(args, "--entries")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl", Err: err}
	}

	// CLI prints *casvc.CRL directly:
	// {last_update (time.Time), next_update (time.Time), revoked_count, revoked_certs, data}
	var resp struct {
		LastUpdate   time.Time              `json:"last_update"`
		NextUpdate   time.Time              `json:"next_update"`
		RevokedCount int32                  `json:"revoked_count"`
		RevokedCerts []*cliRevokedCertEntry `json:"revoked_certs,omitempty"`
		Data         []byte                 `json:"data,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl", Err: err}
	}

	result := &GetCRLResult{
		RevokedCount: resp.RevokedCount,
		ThisUpdate:   resp.LastUpdate,
		NextUpdate:   resp.NextUpdate,
		Data:         resp.Data,
	}

	for _, entry := range resp.RevokedCerts {
		if entry == nil {
			continue
		}
		result.RevokedCerts = append(result.RevokedCerts, RevokedCertEntry{
			Serial:         entry.Serial,
			Reason:         parseRevocationReasonString(entry.Reason),
			RevocationTime: entry.RevocationTime,
		})
	}

	if err := result.setIssuerFromData("CLI"); err != nil {
		return nil, err
	}

	return result, nil
}

// GenerateCRL generates a new CRL via CLI.
// Note: the CLI's "ca crl" command does not have a generate subcommand; it
// fetches the current CRL. This method falls through to GetCRL.
func (c *CLIAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	output, err := c.runCommand(ctx, "ca", "crl", "generate", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl generate", Err: err}
	}

	var raw json.RawMessage
	if jsonErr := json.Unmarshal(output, &raw); jsonErr != nil {
		return &GenerateCRLResult{Success: true}, nil
	}

	return &GenerateCRLResult{Success: true}, nil
}

// ExportCRL exports the CRL via CLI.
func (c *CLIAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	cmdOutput, err := c.runCommand(ctx, "ca", "crl", "export", "--output", output)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl export", Err: err}
	}

	// The export command writes the CRL to a file and prints a success message
	// (not JSON). Stat the output file to get the size.
	_ = cmdOutput

	info, statErr := os.Stat(output)
	if statErr != nil {
		return &ExportCRLResult{Success: true, FilePath: output}, nil
	}

	return &ExportCRLResult{
		Success:  true,
		FilePath: output,
		Size:     info.Size(),
	}, nil
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via the consolidated `ca bundle` CLI command.
func (c *CLIAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	targetPath := output
	var tempFile string

	if targetPath == "" {
		tmpFile, err := os.CreateTemp("", "ca-bundle-*.pem")
		if err != nil {
			return nil, ErrCallFailed{Protocol: "CLI", Method: "ca bundle", Err: err}
		}
		tempFile = tmpFile.Name()
		tmpFile.Close()
		targetPath = tempFile
	}

	if tempFile != "" {
		defer os.Remove(tempFile)
	}

	args := []string{"ca", "bundle", "--output", targetPath}
	_, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca bundle", Err: err}
	}

	bundleData, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca bundle", Err: err}
	}

	// Count certificates in the PEM bundle
	certCount := int32(0)
	remaining := bundleData
	for {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certCount++
		}
	}

	result := &ExportBundleResult{
		Success:   certCount > 0,
		CertCount: certCount,
		Size:      int64(len(bundleData)),
	}

	if output != "" {
		result.FilePath = output
	}

	return result, nil
}

// =============================================================================
// Install/Uninstall Operations
// =============================================================================

// InstallCACertificates installs CA certificates via CLI.
func (c *CLIAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	output, err := c.runCommand(ctx, "ca", "install-ca-certificates", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca install-ca-certificates", Err: err}
	}

	var raw json.RawMessage
	if jsonErr := json.Unmarshal(output, &raw); jsonErr != nil {
		return &InstallCACertificatesResult{Success: true}, nil
	}

	return &InstallCACertificatesResult{Success: true}, nil
}

// UninstallCACertificates uninstalls CA certificates via CLI.
func (c *CLIAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	output, err := c.runCommand(ctx, "ca", "uninstall-ca-certificates", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca uninstall-ca-certificates", Err: err}
	}

	var raw json.RawMessage
	if jsonErr := json.Unmarshal(output, &raw); jsonErr != nil {
		return &UninstallCACertificatesResult{Success: true}, nil
	}

	return &UninstallCACertificatesResult{Success: true}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertCLICertificate converts a cliCertificate to the common test Certificate type.
func convertCLICertificate(cc *cliCertificate) *Certificate {
	if cc == nil {
		return nil
	}

	cert := &Certificate{
		Serial:             cc.Serial,
		Issuer:             cc.Issuer,
		NotBefore:          cc.NotBefore,
		NotAfter:           cc.NotAfter,
		Status:             parseCertStatusString(cc.Status),
		KeyAlgorithm:       cc.KeyAlgorithm,
		SignatureAlgorithm: cc.SignatureAlgorithm,
		IsCA:               cc.IsCa,
		FingerprintSHA256:  cc.FingerprintSha256,
		PEM:                cc.Pem,
		DER:                cc.Der,
	}

	if cc.Subject != nil {
		cert.Subject = Subject{
			CommonName:   cc.Subject.CommonName,
			Organization: cc.Subject.Organization,
		}
	}

	if cc.SANs != nil {
		cert.SANsDNS = cc.SANs.DNSNames
		cert.SANsIPs = cc.SANs.IPAddresses
		cert.SANsEmail = cc.SANs.EmailAddresses
	}

	return cert
}

// parseStatusString converts a string status to CertificateStatus.
// Retained for backward compatibility.
func parseStatusString(status string) CertificateStatus {
	return parseCertStatusString(status)
}

// Ensure CLIAdapter implements CACommands interface.
var _ CACommands = (*CLIAdapter)(nil)
