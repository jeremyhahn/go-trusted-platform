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
	"fmt"
	"os"
	"os/exec"
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

	// cliWaitDelay bounds how long a killed command's output pipes are
	// drained before Run returns.
	cliWaitDelay = 5 * time.Second
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

// ErrCLIBinaryVerifyFailed is returned when platformctl version fails during
// Setup.
type ErrCLIBinaryVerifyFailed struct {
	Path string
	Err  error
}

func (e ErrCLIBinaryVerifyFailed) Error() string {
	return fmt.Sprintf("platformctl binary %s failed verification: %v", e.Path, e.Err)
}

func (e ErrCLIBinaryVerifyFailed) Unwrap() error {
	return e.Err
}

// ErrCLIVersionNegative is returned when a caller names a negative secret
// version, which platformctl cannot address.
type ErrCLIVersionNegative struct {
	Version int
}

func (e ErrCLIVersionNegative) Error() string {
	return fmt.Sprintf("secret version %d is negative", e.Version)
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
		return ErrCLIBinaryVerifyFailed{Path: c.binaryPath, Err: err}
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
	// Every command gets its own timeout. The suite's context always carries
	// a deadline (10 minutes, go test's own limit), so applying the timeout
	// only to a deadline-free context left a hung platformctl to run until
	// the package panicked. A shorter caller deadline still wins.
	ctx, cancel := context.WithTimeout(ctx, c.commandTimeout)
	defer cancel()

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
	// Once the context kills platformctl, stop waiting for its output pipes:
	// a child process still holding them would otherwise keep Run blocked.
	cmd.WaitDelay = cliWaitDelay

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

// secrets runs the kms secrets verbs through this adapter's platformctl.
func (c *CLIAdapter) secrets() helpers.SecretsCLI {
	return helpers.SecretsCLI{Run: c.runCommand}
}

// Store stores a new secret via CLI. Metadata and tags both go as --tag, as on
// REST; the CLI has no flag for an expiry, a tenant, a key or an algorithm.
func (c *CLIAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	if err := storeNoFlag(opts); err != nil {
		return nil, err
	}
	stored, err := c.secrets().Store(ctx, opts.Name, opts.Data, opts.Description, mergeTags(opts.Metadata, opts.Tags))
	if err != nil {
		return nil, err
	}
	return &StoreResult{SecretID: stored.Name, Version: stored.Version}, nil
}

// storeNoFlag refuses the StoreOptions platformctl kms secrets store has no
// flag for.
func storeNoFlag(opts StoreOptions) error {
	const operation = "kms secrets store"
	switch {
	case !opts.ExpiresAt.IsZero():
		return helpers.ErrCLINoFlag{Operation: operation, Flag: "--expires-at"}
	case opts.TenantID != "":
		return helpers.ErrCLINoFlag{Operation: operation, Flag: "--tenant-id"}
	case opts.KeyID != "":
		return helpers.ErrCLINoFlag{Operation: operation, Flag: "--key-id"}
	case opts.Algorithm != "":
		return helpers.ErrCLINoFlag{Operation: operation, Flag: "--algorithm"}
	}
	return nil
}

// Get retrieves the current version of a secret via CLI.
func (c *CLIAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	secret, err := c.secrets().Get(ctx, name)
	if err != nil {
		return nil, err
	}
	return &GetResult{
		SecretID:  secret.Name,
		Version:   secret.Version,
		Data:      secret.Value,
		Metadata:  secret.Metadata,
		CreatedAt: secret.CreatedAt,
	}, nil
}

// List lists secret names via CLI; the CLI pages by --limit only.
func (c *CLIAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	if opts.Cursor != "" {
		return nil, helpers.ErrCLINoFlag{Operation: "kms secrets list", Flag: "--cursor"}
	}
	list, err := c.secrets().List(ctx, opts.Limit)
	if err != nil {
		return nil, err
	}
	summaries := make([]SecretSummary, 0, len(list.Secrets))
	for _, name := range list.Secrets {
		summaries = append(summaries, SecretSummary{SecretID: name, Name: name})
	}
	return &ListResult{
		Secrets:    summaries,
		TotalCount: int32(len(summaries)),
		HasMore:    list.HasMore,
	}, nil
}

// Delete deletes a secret via CLI. The CLI, like REST, has one delete that
// removes every version, so permanent changes nothing.
func (c *CLIAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	deleted, err := c.secrets().Delete(ctx, name)
	if err != nil {
		return nil, err
	}
	return &DeleteResult{SecretID: deleted.Name, Deleted: deleted.Deleted}, nil
}

// =============================================================================
// Version Management Commands
// =============================================================================

// Rotate rotates a secret to new data via CLI.
func (c *CLIAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	rotated, err := c.secrets().Rotate(ctx, name, newData)
	if err != nil {
		return nil, err
	}
	return &RotateResult{
		SecretID:   rotated.Name,
		OldVersion: rotated.OldVersion,
		NewVersion: rotated.NewVersion,
	}, nil
}

// Versions lists every version of a secret via CLI.
func (c *CLIAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	listed, err := c.secrets().Versions(ctx, name)
	if err != nil {
		return nil, err
	}
	versions := make([]VersionInfo, 0, len(listed.Versions))
	for _, v := range listed.Versions {
		versions = append(versions, VersionInfo{Version: v.Version, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy})
	}
	return &VersionsResult{SecretID: listed.Name, Versions: versions}, nil
}

// Version retrieves one version of a secret via CLI.
func (c *CLIAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	if version < 0 {
		return nil, ErrCLIVersionNegative{Version: version}
	}
	secret, err := c.secrets().Version(ctx, name, uint64(version))
	if err != nil {
		return nil, err
	}
	return &VersionResult{
		SecretID:  secret.Name,
		Version:   secret.Version,
		Data:      secret.Value,
		Metadata:  secret.Metadata,
		CreatedAt: secret.CreatedAt,
		CreatedBy: secret.CreatedBy,
	}, nil
}

// Rollback makes a copy of an earlier version the current one via CLI.
func (c *CLIAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	if targetVersion < 0 {
		return nil, ErrCLIVersionNegative{Version: targetVersion}
	}
	rolledBack, err := c.secrets().Rollback(ctx, name, uint64(targetVersion))
	if err != nil {
		return nil, err
	}
	return &RollbackResult{SecretID: rolledBack.Name, NewVersion: rolledBack.NewVersion}, nil
}

// =============================================================================
// Status and Policy Commands
// =============================================================================

// Status enables or disables a secret via CLI.
func (c *CLIAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	status, err := c.secrets().SetStatus(ctx, name, enabled)
	if err != nil {
		return nil, err
	}
	return &StatusResult{SecretID: status.Name, Status: status.Status}, nil
}

// Policy retrieves a secret's rotation policy via CLI.
func (c *CLIAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	policy, err := c.secrets().Policy(ctx, name)
	if err != nil {
		return nil, err
	}
	return &PolicyResult{
		SecretID:        policy.Name,
		Enabled:         policy.Enabled,
		IntervalSeconds: policy.IntervalSeconds,
		NextRotation:    policy.NextRotation,
		RetainVersions:  policy.RetainVersions,
		RotationLambda:  policy.RotationLambda,
	}, nil
}

// PolicySet sets a secret's rotation policy via CLI.
func (c *CLIAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	policy, err := c.secrets().SetPolicy(ctx, name, helpers.SecretsCLIPolicyOptions{
		Enabled:         opts.Enabled,
		IntervalSeconds: opts.IntervalSeconds,
		RetainVersions:  opts.RetainVersions,
		RotationLambda:  opts.RotationLambda,
	})
	if err != nil {
		return nil, err
	}
	return &PolicySetResult{SecretID: policy.Name}, nil
}

// =============================================================================
// Advanced Commands
// =============================================================================

// Prefix lists the secrets under prefix via CLI, with their values when
// includeData is set.
func (c *CLIAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	list, err := c.secrets().PrefixList(ctx, prefix, includeData)
	if err != nil {
		return nil, err
	}
	data := make(map[string]helpers.SecretsCLISecret, len(list.Data))
	for _, secret := range list.Data {
		data[secret.Name] = secret
	}
	secrets := make(map[string]PrefixSecretData, len(list.Secrets))
	for _, name := range list.Secrets {
		secret := data[name]
		secrets[name] = PrefixSecretData{
			Data:     secret.Value,
			Metadata: secret.Metadata,
			Version:  int64(secret.Version),
		}
	}
	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: int32(len(secrets)),
		HasMore:    list.HasMore,
	}, nil
}
