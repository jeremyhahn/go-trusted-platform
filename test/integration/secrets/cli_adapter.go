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

// Package secrets provides integration test adapters for Secrets services.
// This file implements the SecretsCommands interface using the platformctl CLI binary.

//go:build integration

package secrets

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

func (e ErrCLICommandFailed) Unwrap() error {
	return e.Err
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

func (e ErrCLIOutputParseFailed) Unwrap() error {
	return e.Err
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

// CLIAdapter implements SecretsCommands using the platformctl CLI binary.
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
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Secrets Management Commands
// =============================================================================

// Store stores a new secret via CLI.
func (c *CLIAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	args := []string{"secrets", "store", opts.Name}

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

	for k, v := range opts.Tags {
		args = append(args, "--tag", fmt.Sprintf("%s=%s", k, v))
	}

	for k, v := range opts.Metadata {
		args = append(args, "--metadata", fmt.Sprintf("%s=%s", k, v))
	}

	if !opts.ExpiresAt.IsZero() {
		args = append(args, "--expires-at", opts.ExpiresAt.Format(time.RFC3339))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliStoreResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Store", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Get retrieves a secret via CLI.
func (c *CLIAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	args := []string{"secrets", "get", name}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Get", Output: string(output), Err: err}
	}

	return result.toResult()
}

// List lists secrets via CLI.
func (c *CLIAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := []string{"secrets", "list"}

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

	var result cliListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "List", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Delete deletes a secret via CLI.
func (c *CLIAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	args := []string{"secrets", "delete", name}

	if permanent {
		args = append(args, "--permanent")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliDeleteResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Delete", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Rotate rotates a secret via CLI.
func (c *CLIAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	args := []string{"secrets", "rotate", name}

	// Encode new data as base64 for CLI input
	data := base64.StdEncoding.EncodeToString(newData)
	args = append(args, "--data", data, "--base64")

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRotateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Rotate", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Versions lists secret versions via CLI.
func (c *CLIAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	args := []string{"secrets", "versions", name}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliVersionsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Versions", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Version retrieves a specific secret version via CLI.
func (c *CLIAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	args := []string{"secrets", "version", name, strconv.Itoa(version)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliVersionResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Version", Output: string(output), Err: err}
	}

	return result.toResult()
}

// Rollback rolls back a secret to a previous version via CLI.
func (c *CLIAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	args := []string{"secrets", "rollback", name, strconv.Itoa(targetVersion)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRollbackResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Rollback", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Status updates secret status via CLI.
func (c *CLIAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	args := []string{"secrets", "status", name}

	if enabled {
		args = append(args, "--enable")
	} else {
		args = append(args, "--disable")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Status", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Policy retrieves secret rotation policy via CLI.
func (c *CLIAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	args := []string{"secrets", "policy", "get", name}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliPolicyResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Policy", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// PolicySet sets secret rotation policy via CLI.
func (c *CLIAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	args := []string{"secrets", "policy", "set", name}

	if opts.Enabled {
		args = append(args, "--enable")
	} else {
		args = append(args, "--disable")
	}

	if opts.IntervalSeconds > 0 {
		args = append(args, "--interval", strconv.FormatInt(opts.IntervalSeconds, 10))
	}

	if opts.RetainVersions > 0 {
		args = append(args, "--retain-versions", strconv.FormatInt(int64(opts.RetainVersions), 10))
	}

	if opts.RotationLambda != "" {
		args = append(args, "--rotation-lambda", opts.RotationLambda)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliPolicySetResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "PolicySet", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// Prefix retrieves secrets by prefix via CLI.
func (c *CLIAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	args := []string{"secrets", "prefix", prefix}

	if includeData {
		args = append(args, "--include-data")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliPrefixResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Prefix", Output: string(output), Err: err}
	}

	return result.toResult()
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

type cliStoreResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Version   uint64 `json:"version,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliStoreResponse) toResult() *StoreResult {
	return &StoreResult{
		SecretID:  r.SecretID,
		Version:   r.Version,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliGetResponse struct {
	SecretID      string            `json:"secret_id,omitempty"`
	Version       uint64            `json:"version,omitempty"`
	Data          string            `json:"data,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Algorithm     string            `json:"algorithm,omitempty"`
	KeyIdentifier string            `json:"key_identifier,omitempty"`
	CreatedAt     int64             `json:"created_at,omitempty"`
	Timestamp     int64             `json:"timestamp,omitempty"`
}

func (r *cliGetResponse) toResult() (*GetResult, error) {
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret data: %w", err)
	}
	return &GetResult{
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

type cliListResponse struct {
	Secrets    []cliSecretSummary `json:"secrets,omitempty"`
	TotalCount int32              `json:"total_count,omitempty"`
	HasMore    bool               `json:"has_more,omitempty"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type cliSecretSummary struct {
	SecretID       string `json:"secret_id,omitempty"`
	Name           string `json:"name,omitempty"`
	CurrentVersion uint64 `json:"current_version,omitempty"`
	Description    string `json:"description,omitempty"`
	Owner          string `json:"owner,omitempty"`
	CreatedAt      int64  `json:"created_at,omitempty"`
	UpdatedAt      int64  `json:"updated_at,omitempty"`
}

func (r *cliListResponse) toResult() *ListResult {
	result := &ListResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, s := range r.Secrets {
		result.Secrets = append(result.Secrets, SecretSummary{
			SecretID:       s.SecretID,
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

type cliDeleteResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliDeleteResponse) toResult() *DeleteResult {
	return &DeleteResult{
		SecretID:  r.SecretID,
		Deleted:   r.Deleted,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliRotateResponse struct {
	SecretID   string `json:"secret_id,omitempty"`
	OldVersion uint64 `json:"old_version,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

func (r *cliRotateResponse) toResult() *RotateResult {
	return &RotateResult{
		SecretID:   r.SecretID,
		OldVersion: r.OldVersion,
		NewVersion: r.NewVersion,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

type cliVersionsResponse struct {
	SecretID   string           `json:"secret_id,omitempty"`
	Versions   []cliVersionInfo `json:"versions,omitempty"`
	HasMore    bool             `json:"has_more,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type cliVersionInfo struct {
	Version   uint64 `json:"version,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	DeletedAt int64  `json:"deleted_at,omitempty"`
}

func (r *cliVersionsResponse) toResult() *VersionsResult {
	result := &VersionsResult{
		SecretID:   r.SecretID,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for _, v := range r.Versions {
		result.Versions = append(result.Versions, VersionInfo{
			Version:   v.Version,
			CreatedAt: time.Unix(v.CreatedAt, 0),
			CreatedBy: v.CreatedBy,
			ExpiresAt: time.Unix(v.ExpiresAt, 0),
			DeletedAt: time.Unix(v.DeletedAt, 0),
		})
	}
	return result
}

type cliVersionResponse struct {
	SecretID  string            `json:"secret_id,omitempty"`
	Version   uint64            `json:"version,omitempty"`
	Data      string            `json:"data,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	CreatedAt int64             `json:"created_at,omitempty"`
	CreatedBy string            `json:"created_by,omitempty"`
	ExpiresAt int64             `json:"expires_at,omitempty"`
	Timestamp int64             `json:"timestamp,omitempty"`
}

func (r *cliVersionResponse) toResult() (*VersionResult, error) {
	data, err := base64.StdEncoding.DecodeString(r.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret data: %w", err)
	}
	return &VersionResult{
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

type cliRollbackResponse struct {
	SecretID   string `json:"secret_id,omitempty"`
	NewVersion uint64 `json:"new_version,omitempty"`
	Timestamp  int64  `json:"timestamp,omitempty"`
}

func (r *cliRollbackResponse) toResult() *RollbackResult {
	return &RollbackResult{
		SecretID:   r.SecretID,
		NewVersion: r.NewVersion,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

type cliStatusResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliStatusResponse) toResult() *StatusResult {
	return &StatusResult{
		SecretID:  r.SecretID,
		Status:    r.Status,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliPolicyResponse struct {
	SecretID        string `json:"secret_id,omitempty"`
	Enabled         bool   `json:"enabled,omitempty"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	NextRotation    int64  `json:"next_rotation,omitempty"`
	RetainVersions  int32  `json:"retain_versions,omitempty"`
	RotationLambda  string `json:"rotation_lambda,omitempty"`
	UpdatedAt       int64  `json:"updated_at,omitempty"`
}

func (r *cliPolicyResponse) toResult() *PolicyResult {
	return &PolicyResult{
		SecretID:        r.SecretID,
		Enabled:         r.Enabled,
		IntervalSeconds: r.IntervalSeconds,
		NextRotation:    time.Unix(r.NextRotation, 0),
		RetainVersions:  r.RetainVersions,
		RotationLambda:  r.RotationLambda,
		UpdatedAt:       time.Unix(r.UpdatedAt, 0),
	}
}

type cliPolicySetResponse struct {
	SecretID  string `json:"secret_id,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

func (r *cliPolicySetResponse) toResult() *PolicySetResult {
	return &PolicySetResult{
		SecretID:  r.SecretID,
		Timestamp: time.Unix(r.Timestamp, 0),
	}
}

type cliPrefixResponse struct {
	Secrets    map[string]cliPrefixSecretData `json:"secrets,omitempty"`
	TotalCount int32                          `json:"total_count,omitempty"`
	HasMore    bool                           `json:"has_more,omitempty"`
	NextCursor string                         `json:"next_cursor,omitempty"`
}

type cliPrefixSecretData struct {
	Data     string            `json:"data,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Version  int64             `json:"version,omitempty"`
}

func (r *cliPrefixResponse) toResult() (*PrefixResult, error) {
	result := &PrefixResult{
		Secrets:    make(map[string]PrefixSecretData),
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}
	for name, s := range r.Secrets {
		var data []byte
		var err error
		if s.Data != "" {
			data, err = base64.StdEncoding.DecodeString(s.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode secret data for %s: %w", name, err)
			}
		}
		result.Secrets[name] = PrefixSecretData{
			Data:     data,
			Metadata: s.Metadata,
			Version:  s.Version,
		}
	}
	return result, nil
}
