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

// Package kms provides integration test adapters for KMS services.
// This file implements the KMSCommands interface using the platformctl CLI binary.

//go:build integration

package kms

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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Environment Variables
// =============================================================================

const (
	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// DefaultPlatformctlBinary is the default binary name when not specified.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultCommandTimeout is the default timeout for CLI commands.
	DefaultCommandTimeout = 30 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLICommandFailed is returned when a CLI command fails to execute.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI command %q failed: %v", e.Command, e.Err)
}

// ErrCLIVerifyExitMismatch is returned when a verify verb's exit status
// disagrees with the verdict it printed: a failed verification must exit
// non-zero and a passed one must exit zero.
type ErrCLIVerifyExitMismatch struct {
	Operation string
	Valid     bool
	Err       error
}

func (e ErrCLIVerifyExitMismatch) Error() string {
	return fmt.Sprintf("CLI %s printed valid=%t but exited with error %v", e.Operation, e.Valid, e.Err)
}

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

// ErrCLIFieldDecodeFailed is returned when a field of the CLI's JSON output
// is not in its documented encoding (base64, Unix seconds or RFC 3339).
type ErrCLIFieldDecodeFailed struct {
	Operation string
	Field     string
	Value     string
	Err       error
}

func (e ErrCLIFieldDecodeFailed) Error() string {
	return fmt.Sprintf("failed to decode %s.%s %q: %v", e.Operation, e.Field, e.Value, e.Err)
}

func (e ErrCLIFieldDecodeFailed) Unwrap() error {
	return e.Err
}

const (
	// cliOutputEnv selects platformctl's output format (docs/kms/cli.md §3).
	cliOutputEnv = "PLATFORMCTL_OUTPUT"

	// cliTimestampUnset is the crypto verbs' timestamp when the server set
	// none.
	cliTimestampUnset = "-"

	// cliDEKAlgorithm is the one algorithm kms dek create makes
	// (docs/kms/cli.md §7).
	cliDEKAlgorithm = "AES-256-GCM"
)

// decodeCLIBase64 decodes a base64 field of the CLI's JSON output.
func decodeCLIBase64(operation, field, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrCLIFieldDecodeFailed{Operation: operation, Field: field, Value: value, Err: err}
	}
	return decoded, nil
}

// parseCLIUnixTimestamp reads a crypto verb's timestamp: Unix seconds, or
// "-" when unset, which reads as the zero time.
func parseCLIUnixTimestamp(operation, value string) (time.Time, error) {
	if value == "" || value == cliTimestampUnset {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, ErrCLIFieldDecodeFailed{Operation: operation, Field: "timestamp", Value: value, Err: err}
	}
	return time.Unix(seconds, 0), nil
}

// parseCLIRFC3339 reads a metadata or policy timestamp: RFC 3339, or empty
// when unset, which reads as the zero time.
func parseCLIRFC3339(operation, field, value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, ErrCLIFieldDecodeFailed{Operation: operation, Field: field, Value: value, Err: err}
	}
	return parsed, nil
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements KMSCommands using the platformctl CLI binary.
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

// NewCLIAdapterWithConfig creates a CLI adapter with explicit configuration.
func NewCLIAdapterWithConfig(binaryPath, socketPath string, timeout time.Duration) *CLIAdapter {
	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		commandTimeout: timeout,
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
	stdout, err := c.runCommandStdout(ctx, args...)
	if err != nil {
		return nil, err
	}
	return stdout, nil
}

// runVerifyCommand runs a verify verb and checks that its exit status matches
// the verdict it printed. A failed verification prints the verdict and exits
// non-zero, so it is returned as a result rather than as a command failure.
func (c *CLIAdapter) runVerifyCommand(ctx context.Context, operation string, stdin []byte, result any, valid func() bool, args ...string) error {
	stdout, runErr := c.runCommandInput(ctx, stdin, args...)
	if err := json.Unmarshal(stdout, result); err != nil {
		if runErr != nil {
			return runErr
		}
		return ErrCLIOutputParseFailed{Operation: operation, Output: string(stdout), Err: err}
	}
	if valid() == (runErr != nil) {
		return ErrCLIVerifyExitMismatch{Operation: operation, Valid: valid(), Err: runErr}
	}
	return nil
}

// runCommandStdout runs the CLI and returns its stdout even when the command
// fails, alongside ErrCLICommandFailed.
func (c *CLIAdapter) runCommandStdout(ctx context.Context, args ...string) ([]byte, error) {
	return c.runCommandInput(ctx, nil, args...)
}

// runCommandInput runs platformctl with stdin as the command's standard
// input (none when nil) and returns its stdout. JSON is selected through
// PLATFORMCTL_OUTPUT, never --output: the crypto verbs declare their own
// -o/--output (an output file) that shadows the global flag
// (docs/kms/cli.md §3).
func (c *CLIAdapter) runCommandInput(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	// Create context with timeout if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	var fullArgs []string
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath)
	}

	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)
	cmd.Env = append(os.Environ(), cliOutputEnv+"=json")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

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
		return stdout.Bytes(), ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Key Management Commands
// =============================================================================

// cliKeyAlgorithms maps the suite's protocol-neutral AES names to the
// spellings platformctl documents (docs/kms/cli.md §5): the CLI names an AES
// key by its size alone and rejects "AES-256-GCM". Every other suite name is
// already a spelling the CLI accepts, in any case.
var cliKeyAlgorithms = map[string]string{
	"AES-128-GCM": "aes-128",
	"AES-192-GCM": "aes-192",
	"AES-256-GCM": "aes-256",
}

// cliKeyAlgorithm returns the platformctl spelling of a suite algorithm name.
func cliKeyAlgorithm(algorithm string) string {
	if spelling, ok := cliKeyAlgorithms[algorithm]; ok {
		return spelling
	}
	return algorithm
}

// KeyGenerate generates a new cryptographic key via CLI.
func (c *CLIAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	args := []string{"kms", "key", "generate", opts.KeyID}

	if opts.Algorithm != "" {
		args = append(args, "--algorithm", cliKeyAlgorithm(opts.Algorithm))
	}

	if opts.Purpose != "" {
		args = append(args, "--purpose", opts.Purpose)
	}

	if opts.Exportable {
		args = append(args, "--exportable")
	}

	if opts.DeletionProtection {
		args = append(args, "--deletion-protection")
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	if opts.Owner != "" {
		args = append(args, "--owner", opts.Owner)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyGenerateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyGenerate", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyGet retrieves key information via CLI.
func (c *CLIAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	args := []string{"kms", "key", "get", keyID}

	if version > 0 {
		args = append(args, "--version", strconv.FormatUint(version, 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyGetResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyGet", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyList lists all keys via CLI.
func (c *CLIAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	args := []string{"kms", "key", "list"}

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

	var result cliKeyListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyList", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyDelete deletes a key via CLI.
func (c *CLIAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	args := []string{"kms", "key", "delete", keyID}

	if opts.Force {
		args = append(args, "--force")
	}

	if opts.PendingWindowDays > 0 {
		args = append(args, "--pending-days", strconv.FormatInt(int64(opts.PendingWindowDays), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyDeleteResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyDelete", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyRotate rotates an existing key via CLI.
func (c *CLIAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	// --retain-old defaults to true, so the value is always spelled out.
	args := []string{"kms", "key", "rotate", keyID, "--retain-old=" + strconv.FormatBool(retainOldVersion)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyRotateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyRotate", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyVersions lists all versions of a key via CLI.
func (c *CLIAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	args := []string{"kms", "key", "versions", keyID}

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

	var result cliKeyVersionsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyVersions", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyStatus updates the status of a key via CLI.
func (c *CLIAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	action := "disable"
	if enabled {
		action = "enable"
	}

	args := []string{"kms", "key", "status", action, keyID}

	if version > 0 {
		args = append(args, "--version", strconv.FormatUint(version, 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyStatus", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// KeyRevoke revokes a key via CLI.
func (c *CLIAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	args := []string{"kms", "key", "revoke", keyID}

	if reason != "" {
		args = append(args, "--reason", reason)
	}

	// revoke prints only a success line (docs/kms/cli.md §5), so the
	// resulting status is read back from the key's metadata.
	if _, err := c.runCommand(ctx, args...); err != nil {
		return nil, err
	}

	metadata, err := c.KeyMetadata(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     metadata.KeyID,
		Status:    metadata.Status,
		RevokedAt: metadata.UpdatedAt,
	}, nil
}

// KeyMetadata retrieves key metadata via CLI.
func (c *CLIAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	args := []string{"kms", "key", "metadata", "get", keyID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyMetadataResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyMetadata", Output: string(output), Err: err}
	}

	return result.toResult()
}

// KeyMetadataUpdate updates key metadata via CLI.
func (c *CLIAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	args := []string{"kms", "key", "metadata", "update", keyID}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	for k, v := range opts.Tags {
		args = append(args, "--tag", fmt.Sprintf("%s=%s", k, v))
	}

	for _, tag := range opts.RemoveTags {
		args = append(args, "--remove-tag", tag)
	}

	// update prints a success line ahead of its JSON, so the stored
	// metadata is read back with `metadata get` instead.
	if _, err := c.runCommand(ctx, args...); err != nil {
		return nil, err
	}

	metadata, err := c.KeyMetadata(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return &KeyMetadataUpdateResult{
		KeyID:     metadata.KeyID,
		Name:      metadata.Name,
		UpdatedAt: metadata.UpdatedAt,
		Tags:      metadata.Tags,
	}, nil
}

// KeyPolicy retrieves key policy via CLI.
func (c *CLIAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	args := []string{"kms", "key", "policy", "get", keyID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyPolicyResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyPolicy", Output: string(output), Err: err}
	}

	return result.toResult()
}

// KeyPolicySet sets key policy via CLI.
func (c *CLIAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	args := []string{"kms", "key", "policy", "set", keyID}

	for _, op := range opts.Operations {
		args = append(args, "--operation", op)
	}

	for _, p := range opts.AllowPrincipals {
		args = append(args, "--allow-principal", p)
	}

	for _, p := range opts.DenyPrincipals {
		args = append(args, "--deny-principal", p)
	}

	if opts.ExpiresIn != "" {
		args = append(args, "--expires-in", opts.ExpiresIn)
	}

	if opts.RotationRequired {
		args = append(args, "--rotation-required")
	}

	if opts.MaxUsageCount > 0 {
		args = append(args, "--max-usage", strconv.FormatUint(opts.MaxUsageCount, 10))
	}

	if opts.RequireMFA {
		args = append(args, "--require-mfa")
	}

	// policy set prints only a success line (docs/kms/cli.md §5), so the
	// stored policy is read back with `policy get`.
	if _, err := c.runCommand(ctx, args...); err != nil {
		return nil, err
	}

	policy, err := c.KeyPolicy(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         policy.KeyID,
		PolicyVersion: policy.Version,
		UpdatedAt:     policy.UpdatedAt,
	}, nil
}

// KeyAlgorithms lists supported algorithms via CLI.
func (c *CLIAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	args := []string{"kms", "key", "algorithms"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliKeyAlgorithmsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "KeyAlgorithms", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// Crypto Commands
// =============================================================================

// CryptoEncrypt encrypts data via CLI.
func (c *CLIAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	args := []string{"kms", "crypto", "encrypt", "--key-id", opts.KeyID}

	if len(opts.Context) > 0 {
		args = append(args, "--context", string(opts.Context))
	}

	if len(opts.Nonce) > 0 {
		args = append(args, "--nonce", base64.StdEncoding.EncodeToString(opts.Nonce))
	}

	// The plaintext travels raw on stdin.
	output, err := c.runCommandInput(ctx, opts.Plaintext, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoEncryptResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoEncrypt", Output: string(output), Err: err}
	}

	return result.toResult()
}

// CryptoDecrypt decrypts data via CLI.
func (c *CLIAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	args := []string{"kms", "crypto", "decrypt", "--key-id", opts.KeyID}

	if len(opts.Nonce) > 0 {
		args = append(args, "--nonce", base64.StdEncoding.EncodeToString(opts.Nonce))
	}

	if len(opts.Context) > 0 {
		args = append(args, "--context", string(opts.Context))
	}

	if opts.KeyVersion > 0 {
		args = append(args, "--key-version", strconv.FormatUint(opts.KeyVersion, 10))
	}

	// The ciphertext travels base64 on stdin (--base64-input defaults on).
	ciphertext := []byte(base64.StdEncoding.EncodeToString(opts.Ciphertext))
	output, err := c.runCommandInput(ctx, ciphertext, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoDecryptResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoDecrypt", Output: string(output), Err: err}
	}

	return result.toResult()
}

// CryptoSign signs data via CLI.
func (c *CLIAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	args := []string{"kms", "crypto", "sign", "--key-id", opts.KeyID}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash", opts.HashAlgorithm)
	}

	// The message travels raw on stdin.
	output, err := c.runCommandInput(ctx, opts.Message, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoSignResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoSign", Output: string(output), Err: err}
	}

	return result.toResult()
}

// CryptoVerify verifies a signature via CLI.
func (c *CLIAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	args := []string{"kms", "crypto", "verify", "--key-id", opts.KeyID,
		"--signature", base64.StdEncoding.EncodeToString(opts.Signature)}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash", opts.HashAlgorithm)
	}

	if opts.KeyVersion > 0 {
		args = append(args, "--key-version", strconv.FormatUint(opts.KeyVersion, 10))
	}

	// The message travels raw on stdin.
	var result cliCryptoVerifyResponse
	valid := func() bool { return result.Valid }
	if err := c.runVerifyCommand(ctx, "CryptoVerify", opts.Message, &result, valid, args...); err != nil {
		return nil, err
	}

	return result.toResult()
}

// CryptoHash computes a cryptographic hash via CLI.
func (c *CLIAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	args := []string{"kms", "crypto", "hash", "--format", "base64"}

	if algorithm != "" {
		args = append(args, "--algorithm", algorithm)
	}

	// The data travels raw on stdin.
	output, err := c.runCommandInput(ctx, data, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoHashResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoHash", Output: string(output), Err: err}
	}

	return result.toResult()
}

// CryptoHMAC generates an HMAC via CLI.
func (c *CLIAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	args := []string{"kms", "crypto", "hmac", "generate", "--key-id", opts.KeyID}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash", opts.HashAlgorithm)
	}

	// The message travels raw on stdin.
	output, err := c.runCommandInput(ctx, opts.Message, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoHMACResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoHMAC", Output: string(output), Err: err}
	}

	return result.toResult()
}

// CryptoVerifyHMAC verifies an HMAC via CLI.
func (c *CLIAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	args := []string{"kms", "crypto", "hmac", "verify", "--key-id", opts.KeyID,
		"--hmac", base64.StdEncoding.EncodeToString(opts.HMAC)}

	if opts.HashAlgorithm != "" {
		args = append(args, "--hash", opts.HashAlgorithm)
	}

	if opts.KeyVersion > 0 {
		args = append(args, "--key-version", strconv.FormatUint(opts.KeyVersion, 10))
	}

	// The message travels raw on stdin.
	var result cliCryptoVerifyHMACResponse
	valid := func() bool { return result.Valid }
	if err := c.runVerifyCommand(ctx, "CryptoVerifyHMAC", opts.Message, &result, valid, args...); err != nil {
		return nil, err
	}

	return result.toResult()
}

// CryptoRandom generates random bytes via CLI.
func (c *CLIAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	args := []string{"kms", "crypto", "random", "--bytes", strconv.Itoa(numBytes)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliCryptoRandomResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CryptoRandom", Output: string(output), Err: err}
	}

	return result.toResult()
}

// =============================================================================
// DEK Commands
// =============================================================================

// DEKCreate creates a new DEK via CLI.
func (c *CLIAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	// kms dek create has no algorithm, description or limit flags
	// (docs/kms/cli.md §7): it always creates AES-256-GCM, and the limits
	// are set afterwards with kms dek set-safety.
	if opts.Algorithm != "" && opts.Algorithm != cliDEKAlgorithm {
		return nil, ErrCLINoFlag{Operation: "DEKCreate", Flag: "--algorithm"}
	}
	if opts.Description != "" {
		return nil, ErrCLINoFlag{Operation: "DEKCreate", Flag: "--description"}
	}

	output, err := c.runCommand(ctx, "kms", "dek", "create", opts.Path)
	if err != nil {
		return nil, err
	}

	var dek cliDEK
	if err := json.Unmarshal(output, &dek); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKCreate", Output: string(output), Err: err}
	}

	if opts.MaxOperations > 0 || opts.MaxBytes > 0 || opts.WarningPercent > 0 {
		if err := c.dekSetSafety(ctx, opts); err != nil {
			return nil, err
		}
	}

	return dek.toCreateResult()
}

// dekSetSafety sends a DEK's usage limits with kms dek set-safety, which
// prints only a success line.
func (c *CLIAdapter) dekSetSafety(ctx context.Context, opts DEKCreateOptions) error {
	args := []string{"kms", "dek", "set-safety", opts.Path}

	if opts.MaxOperations > 0 {
		args = append(args, "--max-operations", strconv.FormatUint(opts.MaxOperations, 10))
	}

	if opts.MaxBytes > 0 {
		args = append(args, "--max-bytes", strconv.FormatUint(opts.MaxBytes, 10))
	}

	if opts.WarningPercent > 0 {
		args = append(args, "--warn-percent", strconv.FormatInt(int64(opts.WarningPercent), 10))
	}

	_, err := c.runCommand(ctx, args...)
	return err
}

// DEKGet retrieves DEK metadata via CLI.
func (c *CLIAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	output, err := c.runCommand(ctx, "kms", "dek", "get", path)
	if err != nil {
		return nil, err
	}

	var dek cliDEK
	if err := json.Unmarshal(output, &dek); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKGet", Output: string(output), Err: err}
	}

	return dek.toGetResult("DEKGet")
}

// DEKList lists DEKs via CLI.
func (c *CLIAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	// kms dek list --cursor refuses with ErrDEKSDKGap (docs/kms/cli.md §7).
	if opts.Cursor != "" {
		return nil, ErrCLINoFlag{Operation: "DEKList", Flag: "--cursor"}
	}

	args := []string{"kms", "dek", "list"}

	if opts.Prefix != "" {
		args = append(args, "--prefix", opts.Prefix)
	}

	if opts.Recursive {
		args = append(args, "--recursive")
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliDEKListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKList", Output: string(output), Err: err}
	}

	return result.toResult()
}

// DEKDelete deletes a DEK via CLI.
func (c *CLIAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	if opts.MigrateTo != "" {
		return nil, ErrCLINoFlag{Operation: "DEKDelete", Flag: "--migrate-to"}
	}

	args := []string{"kms", "dek", "delete", path}

	if opts.Force {
		args = append(args, "--force")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliDEKDeleteResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKDelete", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// DEKRotate rotates a DEK via CLI.
func (c *CLIAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	// kms dek rotate always rotates in the foreground (docs/kms/cli.md §7).
	if background {
		return nil, ErrCLINoFlag{Operation: "DEKRotate", Flag: "--background"}
	}

	output, err := c.runCommand(ctx, "kms", "dek", "rotate", path)
	if err != nil {
		return nil, err
	}

	var result cliDEKRotateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKRotate", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// DEKStatus retrieves DEK status via CLI.
func (c *CLIAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	output, err := c.runCommand(ctx, "kms", "dek", "status", path)
	if err != nil {
		return nil, err
	}

	var result cliDEKStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DEKStatus", Output: string(output), Err: err}
	}

	return result.toResult()
}

// =============================================================================
// Secrets Commands
// =============================================================================

// SecretsStore stores a secret via CLI.
func (c *CLIAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	args := []string{"kms", "secrets", "store", opts.Name}

	// Encode data as base64 for CLI input
	data := base64.StdEncoding.EncodeToString(opts.Data)
	args = append(args, "--data", data, "--base64")

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	if opts.TenantID != "" {
		args = append(args, "--tenant-id", opts.TenantID)
	}

	if opts.KeyID != "" {
		args = append(args, "--key-id", opts.KeyID)
	}

	if opts.Algorithm != "" {
		args = append(args, "--algorithm", opts.Algorithm)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsStoreResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsStore", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsGet retrieves a secret via CLI.
func (c *CLIAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	args := []string{"kms", "secrets", "get", name}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsGetResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsGet", Output: string(output), Err: err}
	}

	return result.toResult()
}

// SecretsList lists secrets via CLI.
func (c *CLIAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	args := []string{"kms", "secrets", "list"}

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

	var result cliSecretsListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsList", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsDelete deletes a secret via CLI.
func (c *CLIAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	args := []string{"kms", "secrets", "delete", name}

	if permanent {
		args = append(args, "--permanent")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsDeleteResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsDelete", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsRotate rotates a secret via CLI.
func (c *CLIAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	args := []string{"kms", "secrets", "rotate", opts.Name}

	// Encode new data as base64 for CLI input
	data := base64.StdEncoding.EncodeToString(opts.NewData)
	args = append(args, "--data", data, "--base64")

	if opts.TenantID != "" {
		args = append(args, "--tenant-id", opts.TenantID)
	}

	if opts.KeyID != "" {
		args = append(args, "--key-id", opts.KeyID)
	}

	if opts.Algorithm != "" {
		args = append(args, "--algorithm", opts.Algorithm)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsRotateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsRotate", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsVersions lists secret versions via CLI.
func (c *CLIAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	args := []string{"kms", "secrets", "versions", name}

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

	var result cliSecretsVersionsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsVersions", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsVersion retrieves a specific secret version via CLI.
func (c *CLIAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	args := []string{"kms", "secrets", "version", name, strconv.FormatUint(version, 10)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsVersionResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsVersion", Output: string(output), Err: err}
	}

	return result.toResult()
}

// SecretsRollback rolls back a secret to a previous version via CLI.
func (c *CLIAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	args := []string{"kms", "secrets", "rollback", name, strconv.FormatUint(targetVersion, 10)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsRollbackResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsRollback", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SecretsStatus updates secret status via CLI.
func (c *CLIAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	args := []string{"kms", "secrets", "status", name}

	if enabled {
		args = append(args, "--enable")
	} else {
		args = append(args, "--disable")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSecretsStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SecretsStatus", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

// Key response types

type cliKeyGenerateResponse struct {
	Key      *cliKeyInfo     `json:"key,omitempty"`
	Metadata *cliKeyMetadata `json:"metadata,omitempty"`
}

type cliKeyInfo struct {
	KeyID     string `json:"key_id,omitempty"`
	Version   uint64 `json:"version,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Status    string `json:"status,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

type cliKeyMetadata struct {
	Name               string   `json:"name,omitempty"`
	Description        string   `json:"description,omitempty"`
	Exportable         bool     `json:"exportable,omitempty"`
	DeletionProtection bool     `json:"deletion_protection,omitempty"`
	Owner              string   `json:"owner,omitempty"`
	Usage              []string `json:"usage,omitempty"`
	UpdatedAt          int64    `json:"updated_at,omitempty"`
	LastUsedAt         int64    `json:"last_used_at,omitempty"`
}

func (r *cliKeyGenerateResponse) toResult() *KeyGenerateResult {
	result := &KeyGenerateResult{}
	if r.Key != nil {
		result.KeyID = r.Key.KeyID
		result.Version = r.Key.Version
		result.Algorithm = r.Key.Algorithm
		result.Status = r.Key.Status
		result.CreatedAt = time.Unix(r.Key.CreatedAt, 0)
	}
	if r.Metadata != nil {
		result.Name = r.Metadata.Name
		result.Description = r.Metadata.Description
		result.Exportable = r.Metadata.Exportable
		result.DeletionProtection = r.Metadata.DeletionProtection
	}
	return result
}

type cliKeyGetResponse struct {
	Key      *cliKeyInfo     `json:"key,omitempty"`
	Metadata *cliKeyMetadata `json:"metadata,omitempty"`
}

func (r *cliKeyGetResponse) toResult() *KeyGetResult {
	result := &KeyGetResult{}
	if r.Key != nil {
		result.KeyID = r.Key.KeyID
		result.Version = r.Key.Version
		result.Algorithm = r.Key.Algorithm
		result.Status = r.Key.Status
		result.CreatedAt = time.Unix(r.Key.CreatedAt, 0)
	}
	if r.Metadata != nil {
		result.Name = r.Metadata.Name
		result.Description = r.Metadata.Description
		result.Owner = r.Metadata.Owner
		result.Exportable = r.Metadata.Exportable
		result.DeletionProtection = r.Metadata.DeletionProtection
		result.Usage = r.Metadata.Usage
		result.UpdatedAt = time.Unix(r.Metadata.UpdatedAt, 0)
		result.LastUsedAt = time.Unix(r.Metadata.LastUsedAt, 0)
	}
	return result
}

type cliKeyListResponse struct {
	Keys       []cliKeyInfo `json:"keys,omitempty"`
	TotalCount int32        `json:"total_count,omitempty"`
	HasMore    bool         `json:"has_more,omitempty"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

func (r *cliKeyListResponse) toResult() *KeyListResult {
	result := &KeyListResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, k := range r.Keys {
		result.Keys = append(result.Keys, KeySummary{
			KeyID:     k.KeyID,
			Version:   k.Version,
			Algorithm: k.Algorithm,
			Status:    k.Status,
			CreatedAt: time.Unix(k.CreatedAt, 0),
		})
	}
	return result
}

type cliKeyDeleteResponse struct {
	KeyID        string `json:"key_id,omitempty"`
	Status       string `json:"status,omitempty"`
	DeletionDate int64  `json:"deletion_date,omitempty"`
}

func (r *cliKeyDeleteResponse) toResult() *KeyDeleteResult {
	return &KeyDeleteResult{
		KeyID:        r.KeyID,
		Status:       r.Status,
		DeletionDate: time.Unix(r.DeletionDate, 0),
	}
}

type cliKeyRotateResponse struct {
	KeyID      string `json:"key_id,omitempty"`
	OldVersion uint64 `json:"old_version,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

func (r *cliKeyRotateResponse) toResult() *KeyRotateResult {
	return &KeyRotateResult{
		KeyID:      r.KeyID,
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
		RotatedAt:  time.Unix(r.Timestamp, 0),
	}
}

type cliKeyVersionsResponse struct {
	KeyID      string              `json:"key_id,omitempty"`
	Versions   []cliKeyVersionInfo `json:"versions,omitempty"`
	HasMore    bool                `json:"has_more,omitempty"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

type cliKeyVersionInfo struct {
	Version    uint64 `json:"version,omitempty"`
	Algorithm  string `json:"algorithm,omitempty"`
	Status     string `json:"status,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	DisabledAt int64  `json:"disabled_at,omitempty"`
}

func (r *cliKeyVersionsResponse) toResult() *KeyVersionsResult {
	result := &KeyVersionsResult{
		KeyID:      r.KeyID,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, v := range r.Versions {
		result.Versions = append(result.Versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  v.Algorithm,
			Status:     v.Status,
			CreatedAt:  time.Unix(v.CreatedAt, 0),
			DisabledAt: time.Unix(v.DisabledAt, 0),
		})
	}
	return result
}

type cliKeyStatusResponse struct {
	KeyID     string `json:"key_id,omitempty"`
	Version   uint64 `json:"version,omitempty"`
	Status    string `json:"status,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

func (r *cliKeyStatusResponse) toResult() *KeyStatusResult {
	return &KeyStatusResult{
		KeyID:     r.KeyID,
		Version:   r.Version,
		Status:    r.Status,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

// cliKeyMetadataResponse mirrors `kms key metadata get`; its timestamps
// are RFC 3339 strings and it carries no rotation policy.
type cliKeyMetadataResponse struct {
	KeyID              string            `json:"key_id,omitempty"`
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	Algorithm          string            `json:"algorithm,omitempty"`
	Status             string            `json:"status,omitempty"`
	Version            uint64            `json:"version,omitempty"`
	Exportable         bool              `json:"exportable,omitempty"`
	DeletionProtection bool              `json:"deletion_protection,omitempty"`
	Usage              []string          `json:"usage,omitempty"`
	Owner              string            `json:"owner,omitempty"`
	CreatedAt          string            `json:"created_at,omitempty"`
	UpdatedAt          string            `json:"updated_at,omitempty"`
	LastUsedAt         string            `json:"last_used_at,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
}

func (r *cliKeyMetadataResponse) toResult() (*KeyMetadataResult, error) {
	const operation = "KeyMetadata"
	createdAt, err := parseCLIRFC3339(operation, "created_at", r.CreatedAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := parseCLIRFC3339(operation, "updated_at", r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	lastUsedAt, err := parseCLIRFC3339(operation, "last_used_at", r.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &KeyMetadataResult{
		KeyID:              r.KeyID,
		Name:               r.Name,
		Description:        r.Description,
		Algorithm:          r.Algorithm,
		Status:             r.Status,
		Version:            r.Version,
		Exportable:         r.Exportable,
		DeletionProtection: r.DeletionProtection,
		Usage:              r.Usage,
		Owner:              r.Owner,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
		LastUsedAt:         lastUsedAt,
		Tags:               r.Tags,
	}, nil
}

// cliKeyPolicyResponse mirrors `kms key policy get`; its timestamps are
// RFC 3339 strings.
type cliKeyPolicyResponse struct {
	KeyID             string   `json:"key_id,omitempty"`
	Version           int32    `json:"version,omitempty"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string `json:"denied_principals,omitempty"`
	ExpiresAt         string   `json:"expires_at,omitempty"`
	RotationRequired  bool     `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64   `json:"max_usage_count,omitempty"`
	RequireMFA        bool     `json:"require_mfa,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
}

func (r *cliKeyPolicyResponse) toResult() (*KeyPolicyResult, error) {
	const operation = "KeyPolicy"
	expiresAt, err := parseCLIRFC3339(operation, "expires_at", r.ExpiresAt)
	if err != nil {
		return nil, err
	}
	updatedAt, err := parseCLIRFC3339(operation, "updated_at", r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &KeyPolicyResult{
		KeyID:             r.KeyID,
		Version:           r.Version,
		AllowedOperations: r.AllowedOperations,
		AllowedPrincipals: r.AllowedPrincipals,
		DeniedPrincipals:  r.DeniedPrincipals,
		ExpiresAt:         expiresAt,
		RotationRequired:  r.RotationRequired,
		MaxUsageCount:     r.MaxUsageCount,
		RequireMFA:        r.RequireMFA,
		UpdatedAt:         updatedAt,
	}, nil
}

type cliKeyAlgorithmsResponse struct {
	Algorithms []string `json:"algorithms,omitempty"`
}

func (r *cliKeyAlgorithmsResponse) toResult() *KeyAlgorithmsResult {
	return &KeyAlgorithmsResult{
		Algorithms: r.Algorithms,
	}
}

// Crypto response types

type cliCryptoEncryptResponse struct {
	KeyID      string `json:"key_id,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

func (r *cliCryptoEncryptResponse) toResult() (*CryptoEncryptResult, error) {
	const operation = "CryptoEncrypt"
	ciphertext, err := decodeCLIBase64(operation, "ciphertext", r.Ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := decodeCLIBase64(operation, "nonce", r.Nonce)
	if err != nil {
		return nil, err
	}
	timestamp, err := parseCLIUnixTimestamp(operation, r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoEncryptResult{
		KeyID:      r.KeyID,
		KeyVersion: r.KeyVersion,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Timestamp:  timestamp,
	}, nil
}

// cliCryptoDecryptResponse carries the plaintext raw, not base64
// (docs/kms/cli.md §6).
type cliCryptoDecryptResponse struct {
	KeyID      string `json:"key_id,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

func (r *cliCryptoDecryptResponse) toResult() (*CryptoDecryptResult, error) {
	timestamp, err := parseCLIUnixTimestamp("CryptoDecrypt", r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoDecryptResult{
		KeyID:      r.KeyID,
		KeyVersion: r.KeyVersion,
		Plaintext:  []byte(r.Plaintext),
		Timestamp:  timestamp,
	}, nil
}

type cliCryptoSignResponse struct {
	KeyID         string `json:"key_id,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
	Signature     string `json:"signature,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

func (r *cliCryptoSignResponse) toResult() (*CryptoSignResult, error) {
	const operation = "CryptoSign"
	signature, err := decodeCLIBase64(operation, "signature", r.Signature)
	if err != nil {
		return nil, err
	}
	timestamp, err := parseCLIUnixTimestamp(operation, r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoSignResult{
		KeyID:         r.KeyID,
		KeyVersion:    r.KeyVersion,
		Signature:     signature,
		HashAlgorithm: r.HashAlgorithm,
		Timestamp:     timestamp,
	}, nil
}

type cliCryptoVerifyResponse struct {
	KeyID      string `json:"key_id,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
	Valid      bool   `json:"valid,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

func (r *cliCryptoVerifyResponse) toResult() (*CryptoVerifyResult, error) {
	timestamp, err := parseCLIUnixTimestamp("CryptoVerify", r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoVerifyResult{
		KeyID:      r.KeyID,
		KeyVersion: r.KeyVersion,
		Valid:      r.Valid,
		Timestamp:  timestamp,
	}, nil
}

type cliCryptoHashResponse struct {
	Algorithm string `json:"algorithm,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

func (r *cliCryptoHashResponse) toResult() (*CryptoHashResult, error) {
	const operation = "CryptoHash"
	hash, err := decodeCLIBase64(operation, "hash", r.Hash)
	if err != nil {
		return nil, err
	}
	timestamp, err := parseCLIUnixTimestamp(operation, r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoHashResult{
		Algorithm: r.Algorithm,
		Hash:      hash,
		Timestamp: timestamp,
	}, nil
}

type cliCryptoHMACResponse struct {
	KeyID         string `json:"key_id,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
	HMAC          string `json:"hmac,omitempty"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
}

func (r *cliCryptoHMACResponse) toResult() (*CryptoHMACResult, error) {
	const operation = "CryptoHMAC"
	hmac, err := decodeCLIBase64(operation, "hmac", r.HMAC)
	if err != nil {
		return nil, err
	}
	timestamp, err := parseCLIUnixTimestamp(operation, r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoHMACResult{
		KeyID:         r.KeyID,
		KeyVersion:    r.KeyVersion,
		HMAC:          hmac,
		HashAlgorithm: r.HashAlgorithm,
		Timestamp:     timestamp,
	}, nil
}

type cliCryptoVerifyHMACResponse struct {
	KeyID      string `json:"key_id,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
	Valid      bool   `json:"valid,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
}

func (r *cliCryptoVerifyHMACResponse) toResult() (*CryptoVerifyHMACResult, error) {
	timestamp, err := parseCLIUnixTimestamp("CryptoVerifyHMAC", r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoVerifyHMACResult{
		KeyID:      r.KeyID,
		KeyVersion: r.KeyVersion,
		Valid:      r.Valid,
		Timestamp:  timestamp,
	}, nil
}

type cliCryptoRandomResponse struct {
	RandomBytes string `json:"random_bytes,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

func (r *cliCryptoRandomResponse) toResult() (*CryptoRandomResult, error) {
	const operation = "CryptoRandom"
	randomBytes, err := decodeCLIBase64(operation, "random_bytes", r.RandomBytes)
	if err != nil {
		return nil, err
	}
	timestamp, err := parseCLIUnixTimestamp(operation, r.Timestamp)
	if err != nil {
		return nil, err
	}
	return &CryptoRandomResult{
		RandomBytes: randomBytes,
		Timestamp:   timestamp,
	}, nil
}

// DEK response types

// cliDEK is a DEK as the kms dek verbs print it (docs/kms/cli.md §7): flat
// snake_case fields, with RFC 3339 times omitted when unset.
type cliDEK struct {
	Path           string `json:"path"`
	Algorithm      string `json:"algorithm"`
	Version        uint64 `json:"version"`
	Status         string `json:"status"`
	IsDefault      bool   `json:"is_default"`
	CreatedAt      string `json:"created_at,omitempty"`
	RotatedAt      string `json:"rotated_at,omitempty"`
	UsageCount     uint64 `json:"usage_count"`
	BytesUsed      uint64 `json:"bytes_used"`
	MaxUsageCount  uint64 `json:"max_usage_count"`
	MaxBytesUsed   uint64 `json:"max_bytes_used"`
	WarningPercent int32  `json:"warning_percent"`
	Description    string `json:"description,omitempty"`
	BackendType    string `json:"backend_type,omitempty"`
}

// times parses the DEK's created_at and rotated_at.
func (d *cliDEK) times(operation string) (createdAt, rotatedAt time.Time, err error) {
	createdAt, err = parseCLIRFC3339(operation, "created_at", d.CreatedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	rotatedAt, err = parseCLIRFC3339(operation, "rotated_at", d.RotatedAt)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return createdAt, rotatedAt, nil
}

func (d *cliDEK) toCreateResult() (*DEKCreateResult, error) {
	createdAt, _, err := d.times("DEKCreate")
	if err != nil {
		return nil, err
	}
	return &DEKCreateResult{
		Path:        d.Path,
		Algorithm:   d.Algorithm,
		Version:     d.Version,
		CreatedAt:   createdAt,
		Description: d.Description,
	}, nil
}

func (d *cliDEK) toGetResult(operation string) (*DEKGetResult, error) {
	createdAt, rotatedAt, err := d.times(operation)
	if err != nil {
		return nil, err
	}
	return &DEKGetResult{
		Path:           d.Path,
		Algorithm:      d.Algorithm,
		Version:        d.Version,
		Status:         d.Status,
		IsDefault:      d.IsDefault,
		CreatedAt:      createdAt,
		RotatedAt:      rotatedAt,
		Description:    d.Description,
		BackendType:    d.BackendType,
		UsageCount:     d.UsageCount,
		BytesUsed:      d.BytesUsed,
		MaxUsageCount:  d.MaxUsageCount,
		MaxBytesUsed:   d.MaxBytesUsed,
		WarningPercent: d.WarningPercent,
	}, nil
}

// cliDEKListResponse is kms dek list's output. The CLI does not page, so
// there is no has_more or next cursor.
type cliDEKListResponse struct {
	DEKs       []cliDEK `json:"deks"`
	TotalCount int      `json:"total_count"`
}

func (r *cliDEKListResponse) toResult() (*DEKListResult, error) {
	result := &DEKListResult{}
	for i := range r.DEKs {
		d := &r.DEKs[i]
		createdAt, _, err := d.times("DEKList")
		if err != nil {
			return nil, err
		}
		result.DEKs = append(result.DEKs, DEKSummary{
			Path:      d.Path,
			Algorithm: d.Algorithm,
			Version:   d.Version,
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: createdAt,
		})
	}
	return result, nil
}

type cliDEKDeleteResponse struct {
	Path    string `json:"path,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

func (r *cliDEKDeleteResponse) toResult() *DEKDeleteResult {
	return &DEKDeleteResult{
		Path:    r.Path,
		Deleted: r.Deleted,
	}
}

type cliDEKRotateResponse struct {
	Path       string `json:"path,omitempty"`
	OldVersion uint64 `json:"old_version,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
}

func (r *cliDEKRotateResponse) toResult() *DEKRotateResult {
	return &DEKRotateResult{
		Path:       r.Path,
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
	}
}

// cliDEKReencryption is the reencryption object of kms dek status.
type cliDEKReencryption struct {
	InProgress    bool   `json:"in_progress"`
	TotalKeys     int64  `json:"total_keys"`
	ProcessedKeys int64  `json:"processed_keys"`
	FailedKeys    int64  `json:"failed_keys"`
	StartedAt     string `json:"started_at,omitempty"`
}

// cliDEKStatusResponse is kms dek status's output: the DEK plus its
// reencryption progress when there is any. The CLI prints no estimated
// completion time.
type cliDEKStatusResponse struct {
	cliDEK
	Reencryption *cliDEKReencryption `json:"reencryption,omitempty"`
}

func (r *cliDEKStatusResponse) toResult() (*DEKStatusResult, error) {
	dek, err := r.toGetResult("DEKStatus")
	if err != nil {
		return nil, err
	}
	result := &DEKStatusResult{
		Path:           dek.Path,
		Algorithm:      dek.Algorithm,
		Version:        dek.Version,
		Status:         dek.Status,
		IsDefault:      dek.IsDefault,
		CreatedAt:      dek.CreatedAt,
		RotatedAt:      dek.RotatedAt,
		Description:    dek.Description,
		BackendType:    dek.BackendType,
		UsageCount:     dek.UsageCount,
		BytesUsed:      dek.BytesUsed,
		MaxUsageCount:  dek.MaxUsageCount,
		MaxBytesUsed:   dek.MaxBytesUsed,
		WarningPercent: dek.WarningPercent,
	}
	if r.Reencryption != nil {
		startedAt, err := parseCLIRFC3339("DEKStatus", "reencryption.started_at", r.Reencryption.StartedAt)
		if err != nil {
			return nil, err
		}
		result.ReencryptionInProgress = r.Reencryption.InProgress
		result.TotalKeys = r.Reencryption.TotalKeys
		result.ProcessedKeys = r.Reencryption.ProcessedKeys
		result.FailedKeys = r.Reencryption.FailedKeys
		result.ReencryptionStartedAt = startedAt
	}
	return result, nil
}

// Secrets response types

type cliSecretsStoreResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Version   uint64 `json:"version,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliSecretsStoreResponse) toResult() *SecretsStoreResult {
	return &SecretsStoreResult{
		SecretID:  r.SecretID,
		Version:   r.Version,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliSecretsGetResponse struct {
	SecretID      string            `json:"secret_id,omitempty"`
	Version       uint64            `json:"version,omitempty"`
	Data          string            `json:"data,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Algorithm     string            `json:"algorithm,omitempty"`
	KeyIdentifier string            `json:"key_identifier,omitempty"`
	CreatedAt     int64             `json:"created_at,omitempty"`
	Timestamp     int64             `json:"timestamp,omitempty"`
}

func (r *cliSecretsGetResponse) toResult() (*SecretsGetResult, error) {
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret data: %w", err)
	}
	return &SecretsGetResult{
		SecretID:      r.SecretID,
		Version:       r.Version,
		Data:          data,
		Metadata:      r.Metadata,
		Algorithm:     r.Algorithm,
		KeyIdentifier: r.KeyIdentifier,
		CreatedAt:     time.Unix(r.CreatedAt, 0),
		Timestamp:     time.Unix(r.Timestamp, 0),
	}, nil
}

type cliSecretsListResponse struct {
	Secrets    []cliSecretSummary `json:"secrets,omitempty"`
	TotalCount int32              `json:"total_count,omitempty"`
	HasMore    bool               `json:"has_more,omitempty"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type cliSecretSummary struct {
	Name           string `json:"name,omitempty"`
	CurrentVersion uint64 `json:"current_version,omitempty"`
	Description    string `json:"description,omitempty"`
	Owner          string `json:"owner,omitempty"`
	CreatedAt      int64  `json:"created_at,omitempty"`
	UpdatedAt      int64  `json:"updated_at,omitempty"`
}

func (r *cliSecretsListResponse) toResult() *SecretsListResult {
	result := &SecretsListResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, s := range r.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      time.Unix(s.CreatedAt, 0),
			UpdatedAt:      time.Unix(s.UpdatedAt, 0),
		})
	}
	return result
}

type cliSecretsDeleteResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliSecretsDeleteResponse) toResult() *SecretsDeleteResult {
	return &SecretsDeleteResult{
		SecretID:  r.SecretID,
		Deleted:   r.Deleted,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliSecretsRotateResponse struct {
	SecretID   string `json:"secret_id,omitempty"`
	OldVersion uint64 `json:"old_version,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

func (r *cliSecretsRotateResponse) toResult() *SecretsRotateResult {
	return &SecretsRotateResult{
		SecretID:   r.SecretID,
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

type cliSecretsVersionsResponse struct {
	SecretID   string                 `json:"secret_id,omitempty"`
	Versions   []cliSecretVersionInfo `json:"versions,omitempty"`
	HasMore    bool                   `json:"has_more,omitempty"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type cliSecretVersionInfo struct {
	Version   uint64 `json:"version,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func (r *cliSecretsVersionsResponse) toResult() *SecretsVersionsResult {
	result := &SecretsVersionsResult{
		SecretID:   r.SecretID,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, v := range r.Versions {
		result.Versions = append(result.Versions, SecretVersionInfo{
			Version:   v.Version,
			CreatedAt: time.Unix(v.CreatedAt, 0),
			CreatedBy: v.CreatedBy,
			ExpiresAt: time.Unix(v.ExpiresAt, 0),
		})
	}
	return result
}

type cliSecretsVersionResponse struct {
	SecretID  string            `json:"secret_id,omitempty"`
	Version   uint64            `json:"version,omitempty"`
	Data      string            `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt int64             `json:"created_at,omitempty"`
	CreatedBy string            `json:"created_by,omitempty"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
	Timestamp int64             `json:"timestamp,omitempty"`
}

func (r *cliSecretsVersionResponse) toResult() (*SecretsVersionResult, error) {
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret data: %w", err)
	}
	return &SecretsVersionResult{
		SecretID:  r.SecretID,
		Version:   r.Version,
		Data:      data,
		Metadata:  r.Metadata,
		CreatedAt: time.Unix(r.CreatedAt, 0),
		CreatedBy: r.CreatedBy,
		ExpiresAt: time.Unix(r.ExpiresAt, 0),
		Timestamp: time.Unix(r.Timestamp, 0),
	}, nil
}

type cliSecretsRollbackResponse struct {
	SecretID   string `json:"secret_id,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

func (r *cliSecretsRollbackResponse) toResult() *SecretsRollbackResult {
	return &SecretsRollbackResult{
		SecretID:   r.SecretID,
		NewVersion: r.NewVersion,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

type cliSecretsStatusResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliSecretsStatusResponse) toResult() *SecretsStatusResult {
	return &SecretsStatusResult{
		SecretID:  r.SecretID,
		Status:    r.Status,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}
