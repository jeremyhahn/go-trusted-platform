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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

	socketPath := os.Getenv("PLATFORMD_SOCKET")
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformUnix
	}

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
	if socketPath := os.Getenv("PLATFORMD_SOCKET"); socketPath != "" {
		c.socketPath = socketPath
	}
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

	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create minimal config file matching cli.Config YAML structure.
	// The Config struct uses:
	//   CurrentContext string     `yaml:"current_context"`
	//   Contexts       []*Context `yaml:"contexts"`
	// The Context struct uses:
	//   Name   string      `yaml:"name"`
	//   Type   ContextType `yaml:"type"`
	//   Local  *LocalContext (inline fields via yaml)
	//   The LocalContext uses:
	//     SocketPath string `yaml:"socket_path"`
	//     GRPCAddr   string `yaml:"grpc_addr,omitempty"`
	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)

	if writeErr := os.WriteFile(configPath, []byte(configContent), 0600); writeErr != nil {
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
// Protobuf JSON Types
//
// The CLI outputs protobuf messages serialized with encoding/json (NOT protojson).
// Timestamps serialize as {"seconds": N, "nanos": N}, enums as integers,
// and nested messages as JSON objects.
// =============================================================================

// protoTimestamp represents a protobuf Timestamp serialized via encoding/json.
type protoTimestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

// toTime converts a protoTimestamp to a Go time.Time.
func (t *protoTimestamp) toTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos))
}

// protoSubject represents a protobuf Subject message serialized via encoding/json.
type protoSubject struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
	Address            string `json:"address"`
	PostalCode         string `json:"postal_code"`
}

// protoSANs represents protobuf SubjectAlternativeNames serialized via encoding/json.
type protoSANs struct {
	DNSNames       []string `json:"dns_names"`
	IPAddresses    []string `json:"ip_addresses"`
	EmailAddresses []string `json:"email_addresses"`
	URIs           []string `json:"uris"`
}

// protoStatus represents a protobuf Status message serialized via encoding/json.
type protoStatus struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// protoCertSummary represents a protobuf CertificateSummary serialized via encoding/json.
type protoCertSummary struct {
	Serial       string          `json:"serial"`
	CommonName   string          `json:"common_name"`
	Issuer       string          `json:"issuer"`
	NotBefore    *protoTimestamp `json:"not_before"`
	NotAfter     *protoTimestamp `json:"not_after"`
	Status       int32           `json:"status"`
	KeyAlgorithm int32           `json:"key_algorithm"`
}

// protoCertificate represents a protobuf Certificate serialized via encoding/json.
type protoCertificate struct {
	Serial             string          `json:"serial"`
	Subject            *protoSubject   `json:"subject"`
	Issuer             string          `json:"issuer"`
	NotBefore          *protoTimestamp `json:"not_before"`
	NotAfter           *protoTimestamp `json:"not_after"`
	Status             int32           `json:"status"`
	KeyAlgorithm       int32           `json:"key_algorithm"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	IsCA               bool            `json:"is_ca"`
	MaxPathLen         int32           `json:"max_path_len"`
	Sans               *protoSANs      `json:"sans"`
	KeyUsage           []string        `json:"key_usage"`
	ExtKeyUsage        []string        `json:"ext_key_usage"`
	PEM                json.RawMessage `json:"pem"`
	DER                json.RawMessage `json:"der"`
	FingerprintSHA256  string          `json:"fingerprint_sha256"`
}

// protoKeyStoreInfo represents a protobuf KeyStoreInfo serialized via encoding/json.
type protoKeyStoreInfo struct {
	Type         string   `json:"type"`
	Available    bool     `json:"available"`
	Capabilities []string `json:"capabilities"`
}

// =============================================================================
// Protobuf Enum Conversion
// =============================================================================

// protoCertStatusMap converts protobuf CertificateStatus enum integers to CertificateStatus.
var protoCertStatusMap = map[int32]CertificateStatus{
	0: CertificateStatusUnspecified,
	1: CertificateStatusValid,
	2: CertificateStatusRevoked,
	3: CertificateStatusExpired,
	4: CertificateStatusPending,
}

// protoKeyAlgorithmMap converts protobuf KeyAlgorithm enum integers to string names.
var protoKeyAlgorithmMap = map[int32]string{
	0:  "KEY_ALGORITHM_UNSPECIFIED",
	1:  "RSA-2048",
	2:  "RSA-3072",
	3:  "RSA-4096",
	4:  "ECDSA-P256",
	5:  "ECDSA-P384",
	6:  "ECDSA-P521",
	7:  "ED25519",
	8:  "DILITHIUM2",
	9:  "DILITHIUM3",
	10: "DILITHIUM5",
}

// protoRevocationReasonMap converts protobuf RevocationReason enum integers to RevocationReason.
var protoRevocationReasonMap = map[int32]RevocationReason{
	0:  RevocationReasonUnspecified,
	1:  RevocationReasonKeyCompromise,
	2:  RevocationReasonCACompromise,
	3:  RevocationReasonAffiliationChanged,
	4:  RevocationReasonSuperseded,
	5:  RevocationReasonCessationOfOperation,
	6:  RevocationReasonCertificateHold,
	8:  RevocationReasonRemoveFromCRL,
	9:  RevocationReasonPrivilegeWithdrawn,
	10: RevocationReasonAACompromise,
}

// parseCertStatusEnum converts a protobuf CertificateStatus enum int to CertificateStatus.
func parseCertStatusEnum(status int32) CertificateStatus {
	if s, ok := protoCertStatusMap[status]; ok {
		return s
	}
	return CertificateStatusUnspecified
}

// parseKeyAlgorithmEnum converts a protobuf KeyAlgorithm enum int to a human-readable string.
func parseKeyAlgorithmEnum(alg int32) string {
	if name, ok := protoKeyAlgorithmMap[alg]; ok {
		return name
	}
	return "UNKNOWN"
}

// parseRevocationReasonEnum converts a protobuf RevocationReason enum int to RevocationReason.
func parseRevocationReasonEnum(reason int32) RevocationReason {
	if r, ok := protoRevocationReasonMap[reason]; ok {
		return r
	}
	return RevocationReasonUnspecified
}

// decodePEMBytes decodes the PEM field from protobuf JSON. Protobuf bytes fields
// are serialized as base64 strings by encoding/json.
func decodePEMBytes(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var b64 string
	if err := json.Unmarshal(raw, &b64); err != nil {
		return nil
	}
	if b64 == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Might already be raw PEM text
		return []byte(b64)
	}
	return decoded
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via CLI.
func (c *CLIAdapter) Info(ctx context.Context) (*InfoResult, error) {
	output, err := c.runCommand(ctx, "ca", "info", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca info", Err: err}
	}

	// The CLI outputs GetCAInfoResponse which wraps CAInfo inside ca_info.
	var resp struct {
		CAInfo *struct {
			CommonName          string               `json:"common_name"`
			IsInitialized       bool                 `json:"is_initialized"`
			IsIntermediate      bool                 `json:"is_intermediate"`
			DefaultAlgorithm    string               `json:"default_algorithm"`
			DefaultValidityDays int32                `json:"default_validity_days"`
			RootCert            *protoCertSummary    `json:"root_cert"`
			Intermediates       []*protoCertSummary  `json:"intermediates"`
			KeyStores           []*protoKeyStoreInfo `json:"key_stores"`
		} `json:"ca_info"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca info", Err: err}
	}

	if resp.CAInfo == nil {
		return &InfoResult{}, nil
	}

	result := &InfoResult{
		CommonName:          resp.CAInfo.CommonName,
		IsInitialized:       resp.CAInfo.IsInitialized,
		IsIntermediate:      resp.CAInfo.IsIntermediate,
		DefaultAlgorithm:    resp.CAInfo.DefaultAlgorithm,
		DefaultValidityDays: resp.CAInfo.DefaultValidityDays,
	}

	if resp.CAInfo.RootCert != nil {
		rc := resp.CAInfo.RootCert
		result.RootCertificate = &CertificateSummary{
			Serial:       rc.Serial,
			CommonName:   rc.CommonName,
			Issuer:       rc.Issuer,
			KeyAlgorithm: parseKeyAlgorithmEnum(rc.KeyAlgorithm),
			Status:       parseCertStatusEnum(rc.Status),
			NotBefore:    rc.NotBefore.toTime(),
			NotAfter:     rc.NotAfter.toTime(),
		}
	}

	for _, inter := range resp.CAInfo.Intermediates {
		if inter == nil {
			continue
		}
		cs := CertificateSummary{
			Serial:       inter.Serial,
			CommonName:   inter.CommonName,
			Issuer:       inter.Issuer,
			KeyAlgorithm: parseKeyAlgorithmEnum(inter.KeyAlgorithm),
			Status:       parseCertStatusEnum(inter.Status),
			NotBefore:    inter.NotBefore.toTime(),
			NotAfter:     inter.NotAfter.toTime(),
		}
		result.Intermediates = append(result.Intermediates, cs)
	}

	for _, ks := range resp.CAInfo.KeyStores {
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

	var resp struct {
		Status *protoStatus `json:"status"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &InitResult{Success: true}, nil
	}

	result := &InitResult{Success: true}
	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	return result, nil
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

	// The CLI outputs IssueCertificateResponse which has:
	//   status: {success: bool, message: string}
	//   certificate: protobuf Certificate
	//   timestamp: protobuf Timestamp
	var resp struct {
		Status      *protoStatus      `json:"status"`
		Certificate *protoCertificate `json:"certificate"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca issue", Err: err}
	}

	result := &IssueCertificateResult{}
	if resp.Status != nil {
		result.Success = resp.Status.Success
	}

	if resp.Certificate != nil {
		cert := convertProtoCertificate(resp.Certificate)
		result.Certificate = cert
		// If status wasn't set via Status field, infer from certificate presence
		if resp.Status == nil {
			result.Success = cert.Serial != ""
		}
	}

	return result, nil
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via CLI.
// The CLI command "ca certificate" accepts exactly 1 arg: the serial number.
// The gRPC backend also accepts common name as the serial field for CN-based lookup.
func (c *CLIAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	// Determine the identifier to pass as the single positional argument.
	// The CLI "ca certificate" command takes exactly 1 arg which is passed to
	// the backend as the serial field. The backend's findCertByIdentifier()
	// accepts both hex serial numbers and common names.
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

	// The CLI outputs GetCertificateResponse which has:
	//   certificate: protobuf Certificate
	//   timestamp: protobuf Timestamp
	var resp struct {
		Certificate *protoCertificate `json:"certificate"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: err}
	}

	if resp.Certificate == nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca certificate", Err: ErrCertificateNotFound{Identifier: identifier}}
	}

	return &GetCertificateResult{
		Certificate: convertProtoCertificate(resp.Certificate),
	}, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via CLI.
// The CLI "ca list" command uses --page and --page-size for pagination (no --limit flag).
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

	// The CLI outputs ListCertificatesResponse which has:
	//   certificates: []CertificateSummary (protobuf)
	//   pagination: PaginationResponse
	//   timestamp: protobuf Timestamp
	var resp struct {
		Certificates []*protoCertSummary `json:"certificates"`
		Pagination   *struct {
			TotalItems uint64 `json:"total_items"`
		} `json:"pagination"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca list", Err: err}
	}

	result := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(resp.Certificates)),
	}

	if resp.Pagination != nil {
		result.Total = int32(resp.Pagination.TotalItems)
	}

	for _, cert := range resp.Certificates {
		if cert == nil {
			continue
		}
		cs := CertificateSummary{
			Serial:       cert.Serial,
			CommonName:   cert.CommonName,
			Issuer:       cert.Issuer,
			KeyAlgorithm: parseKeyAlgorithmEnum(cert.KeyAlgorithm),
			Status:       parseCertStatusEnum(cert.Status),
			NotBefore:    cert.NotBefore.toTime(),
			NotAfter:     cert.NotAfter.toTime(),
		}
		result.Certificates = append(result.Certificates, cs)
	}

	return result, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via CLI.
// The CLI "ca verify" command takes exactly 1 arg: a path to a PEM certificate file.
// It does NOT support --serial. When called with a serial number, the adapter first
// retrieves the certificate PEM via "ca certificate", saves it to a temp file,
// then calls "ca verify" with that file.
func (c *CLIAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	var certPath string
	var tempFile string

	if opts.CertPath != "" {
		// Direct file path provided
		certPath = opts.CertPath
	} else if len(opts.CertificatePEM) > 0 {
		// PEM data provided directly - write to temp file
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
		// Serial provided - fetch the certificate PEM first, then verify it
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

	// Clean up temp file when done
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

	// The CLI outputs VerifyCertificateResponse which has:
	//   status: {success: bool, message: string}
	//   valid: bool
	//   chain: []string
	//   errors: []string
	//   warnings: []string
	//   timestamp: protobuf Timestamp
	var resp struct {
		Status   *protoStatus `json:"status"`
		Valid    bool         `json:"valid"`
		Chain    []string     `json:"chain"`
		Errors   []string     `json:"errors"`
		Warnings []string     `json:"warnings"`
		Revoked  bool         `json:"revoked"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca verify", Err: err}
	}

	result := &VerifyCertificateResult{
		Valid:         resp.Valid,
		Revoked:       resp.Revoked,
		ChainValid:    resp.Valid && len(resp.Errors) == 0,
		ChainLength:   len(resp.Chain),
		ChainSubjects: resp.Chain,
		Errors:        resp.Errors,
		Warnings:      resp.Warnings,
	}

	return result, nil
}

// fetchCertPEM retrieves the PEM data for a certificate by its serial number.
func (c *CLIAdapter) fetchCertPEM(ctx context.Context, serial string) ([]byte, error) {
	output, err := c.runCommand(ctx, "ca", "certificate", serial, "--pem", "--output", "json")
	if err != nil {
		return nil, err
	}

	var resp struct {
		Certificate *protoCertificate `json:"certificate"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, err
	}

	if resp.Certificate == nil {
		return nil, ErrCertificateNotFound{Identifier: serial}
	}

	pemData := decodePEMBytes(resp.Certificate.PEM)
	if len(pemData) == 0 {
		return nil, ErrCertificateNotFound{Identifier: serial}
	}

	return pemData, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via CLI.
// The CLI "ca revoke" command takes exactly 1 arg: the serial number (positional, not --serial).
func (c *CLIAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	// Determine the serial to pass as the positional argument
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

	// The CLI outputs RevokeCertificateResponse which has:
	//   status: {success: bool, message: string}
	//   serial: string
	//   certificate_status: int (CertificateStatus enum)
	//   revoked_at: {seconds: N, nanos: N}
	//   reason: int (RevocationReason enum)
	//   timestamp: {seconds: N, nanos: N}
	var resp struct {
		Status            *protoStatus    `json:"status"`
		Serial            string          `json:"serial"`
		CertificateStatus int32           `json:"certificate_status"`
		RevokedAt         *protoTimestamp `json:"revoked_at"`
		Reason            int32           `json:"reason"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca revoke", Err: err}
	}

	result := &RevokeCertificateResult{
		Serial: resp.Serial,
		Status: parseCertStatusEnum(resp.CertificateStatus),
		Reason: parseRevocationReasonEnum(resp.Reason),
	}

	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	if resp.RevokedAt != nil {
		result.RevokedAt = resp.RevokedAt.toTime()
	}

	return result, nil
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

	// The CLI outputs RenewCertificateResponse which has:
	//   status: {success: bool, message: string}
	//   old_certificate: protobuf Certificate
	//   new_certificate: protobuf Certificate
	//   timestamp: protobuf Timestamp
	var resp struct {
		Status         *protoStatus      `json:"status"`
		OldCertificate *protoCertificate `json:"old_certificate"`
		NewCertificate *protoCertificate `json:"new_certificate"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca renew", Err: err}
	}

	result := &RenewCertificateResult{}

	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	if resp.OldCertificate != nil {
		result.OldCertificate = convertProtoCertificate(resp.OldCertificate)
	}

	if resp.NewCertificate != nil {
		result.NewCertificate = convertProtoCertificate(resp.NewCertificate)
		if resp.Status == nil {
			result.Success = result.NewCertificate.Serial != ""
		}
	}

	return result, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via CLI.
func (c *CLIAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	output, err := c.runCommand(ctx, "ca", "crl", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl", Err: err}
	}

	// The CLI outputs GetCRLResponse which has:
	//   crl: { data, last_update, next_update, revoked_count, revoked_certs }
	//   timestamp: protobuf Timestamp
	var resp struct {
		CRL *struct {
			LastUpdate   *protoTimestamp `json:"last_update"`
			NextUpdate   *protoTimestamp `json:"next_update"`
			RevokedCount int32           `json:"revoked_count"`
			RevokedCerts []struct {
				Serial         string          `json:"serial"`
				RevocationTime *protoTimestamp `json:"revocation_time"`
				Reason         int32           `json:"reason"`
			} `json:"revoked_certs"`
		} `json:"crl"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl", Err: err}
	}

	result := &GetCRLResult{}

	if resp.CRL != nil {
		result.RevokedCount = resp.CRL.RevokedCount
		if resp.CRL.LastUpdate != nil {
			result.ThisUpdate = resp.CRL.LastUpdate.toTime()
		}
		if resp.CRL.NextUpdate != nil {
			result.NextUpdate = resp.CRL.NextUpdate.toTime()
		}

		for _, cert := range resp.CRL.RevokedCerts {
			rce := RevokedCertEntry{
				Serial: cert.Serial,
				Reason: parseRevocationReasonEnum(cert.Reason),
			}
			if cert.RevocationTime != nil {
				rce.RevocationTime = cert.RevocationTime.toTime()
			}
			result.RevokedCerts = append(result.RevokedCerts, rce)
		}
	}

	return result, nil
}

// GenerateCRL generates a new CRL via CLI.
func (c *CLIAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	output, err := c.runCommand(ctx, "ca", "crl", "generate", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl generate", Err: err}
	}

	var resp struct {
		Status *protoStatus `json:"status"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &GenerateCRLResult{Success: true}, nil
	}

	result := &GenerateCRLResult{Success: true}
	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	return result, nil
}

// ExportCRL exports the CRL via CLI.
func (c *CLIAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	cmdOutput, err := c.runCommand(ctx, "ca", "crl", "export", "--output", output, "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca crl export", Err: err}
	}

	var resp struct {
		Success  bool   `json:"success"`
		FilePath string `json:"file_path"`
		Size     int64  `json:"size"`
		Message  string `json:"message"`
	}

	if err := json.Unmarshal(cmdOutput, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &ExportCRLResult{Success: true, FilePath: output}, nil
	}

	return &ExportCRLResult{
		Success:  resp.Success,
		FilePath: resp.FilePath,
		Size:     resp.Size,
		Message:  resp.Message,
	}, nil
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via the consolidated `ca bundle` CLI command.
// The unified `bundle` command writes PEM data to stdout by default and to a file
// when --output is provided. This adapter always uses --output so it can read the
// resulting PEM and count the certificates inside the bundle.
func (c *CLIAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	// Always need a file path because the `ca bundle` CLI writes PEM to a file when --output is set
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

	// Clean up temp file when done (only if we created it)
	if tempFile != "" {
		defer os.Remove(tempFile)
	}

	// `ca bundle --output <path>` writes PEM bytes to the file. The local
	// --output flag on `bundle` overrides the persistent --output format flag
	// for this subcommand, so we cannot request JSON here.
	args := []string{"ca", "bundle", "--output", targetPath}
	_, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca bundle", Err: err}
	}

	// Read the file produced by the CLI to determine cert count and size.
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

	var resp struct {
		Status *protoStatus `json:"status"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &InstallCACertificatesResult{Success: true}, nil
	}

	result := &InstallCACertificatesResult{Success: true}
	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	return result, nil
}

// UninstallCACertificates uninstalls CA certificates via CLI.
func (c *CLIAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	output, err := c.runCommand(ctx, "ca", "uninstall-ca-certificates", "--output", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ca uninstall-ca-certificates", Err: err}
	}

	var resp struct {
		Status *protoStatus `json:"status"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If we can't parse JSON but command succeeded, assume success
		return &UninstallCACertificatesResult{Success: true}, nil
	}

	result := &UninstallCACertificatesResult{Success: true}
	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertProtoCertificate converts a protobuf Certificate JSON representation
// to the common test Certificate type.
func convertProtoCertificate(pc *protoCertificate) *Certificate {
	if pc == nil {
		return nil
	}

	cert := &Certificate{
		Serial:             pc.Serial,
		Issuer:             pc.Issuer,
		Status:             parseCertStatusEnum(pc.Status),
		KeyAlgorithm:       parseKeyAlgorithmEnum(pc.KeyAlgorithm),
		SignatureAlgorithm: pc.SignatureAlgorithm,
		IsCA:               pc.IsCA,
		MaxPathLen:         pc.MaxPathLen,
		KeyUsage:           pc.KeyUsage,
		ExtKeyUsage:        pc.ExtKeyUsage,
		FingerprintSHA256:  pc.FingerprintSHA256,
		PEM:                decodePEMBytes(pc.PEM),
		DER:                decodePEMBytes(pc.DER),
	}

	if pc.NotBefore != nil {
		cert.NotBefore = pc.NotBefore.toTime()
	}
	if pc.NotAfter != nil {
		cert.NotAfter = pc.NotAfter.toTime()
	}

	if pc.Subject != nil {
		cert.Subject = Subject{
			CommonName:         pc.Subject.CommonName,
			Organization:       pc.Subject.Organization,
			OrganizationalUnit: pc.Subject.OrganizationalUnit,
			Country:            pc.Subject.Country,
			Province:           pc.Subject.Province,
			Locality:           pc.Subject.Locality,
			Address:            pc.Subject.Address,
			PostalCode:         pc.Subject.PostalCode,
		}
	}

	if pc.Sans != nil {
		cert.SANsDNS = pc.Sans.DNSNames
		cert.SANsIPs = pc.Sans.IPAddresses
		cert.SANsEmail = pc.Sans.EmailAddresses
		cert.SANsURIs = pc.Sans.URIs
	}

	return cert
}

// parseStatusString converts a string status to CertificateStatus.
func parseStatusString(status string) CertificateStatus {
	statusMap := map[string]CertificateStatus{
		"valid":   CertificateStatusValid,
		"active":  CertificateStatusValid,
		"revoked": CertificateStatusRevoked,
		"expired": CertificateStatusExpired,
		"pending": CertificateStatusPending,
	}
	if s, ok := statusMap[strings.ToLower(status)]; ok {
		return s
	}
	return CertificateStatusUnspecified
}

// parseRevocationReasonString converts a string reason to RevocationReason.
func parseRevocationReasonString(reason string) RevocationReason {
	reasonMap := map[string]RevocationReason{
		"key_compromise":         RevocationReasonKeyCompromise,
		"keycompromise":          RevocationReasonKeyCompromise,
		"ca_compromise":          RevocationReasonCACompromise,
		"cacompromise":           RevocationReasonCACompromise,
		"affiliation_changed":    RevocationReasonAffiliationChanged,
		"affiliationchanged":     RevocationReasonAffiliationChanged,
		"superseded":             RevocationReasonSuperseded,
		"cessation_of_operation": RevocationReasonCessationOfOperation,
		"cessationofoperation":   RevocationReasonCessationOfOperation,
		"certificate_hold":       RevocationReasonCertificateHold,
		"certificatehold":        RevocationReasonCertificateHold,
		"remove_from_crl":        RevocationReasonRemoveFromCRL,
		"removefromcrl":          RevocationReasonRemoveFromCRL,
		"privilege_withdrawn":    RevocationReasonPrivilegeWithdrawn,
		"privilegewithdrawn":     RevocationReasonPrivilegeWithdrawn,
		"aa_compromise":          RevocationReasonAACompromise,
		"aacompromise":           RevocationReasonAACompromise,
	}
	if r, ok := reasonMap[strings.ToLower(reason)]; ok {
		return r
	}
	return RevocationReasonUnspecified
}

// Ensure CLIAdapter implements CACommands interface.
var _ CACommands = (*CLIAdapter)(nil)
