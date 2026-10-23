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

package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// CLIAdapter implements RegistryCommands using the platformctl CLI binary.
// This adapter executes CLI commands and parses JSON output to provide
// structured responses for integration testing.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	configDir      string
	configPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads configuration from environment variables:
//   - PLATFORMCTL_BINARY: Path to platformctl binary (default: "platformctl")
//   - PLATFORMD_SOCKET: Path to platformd Unix socket (default: "/var/run/platformd/platformd.sock")
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
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrAdapterConnectionFailed{Adapter: "CLI", URL: c.binaryPath, Err: err}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path

	// Verify binary works by running version command
	_, err = c.runCommand(ctx, "version")
	if err != nil {
		return ErrSetupFailed{Adapter: "CLI", Reason: "binary verification failed", Err: err}
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

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	fullArgs := []string{"--output", "json"}

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
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCommandFailed{Command: strings.Join(fullArgs, " "), Output: output, Err: err}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Image Management Commands
// =============================================================================

// Push pushes an image to the registry via CLI.
// Command: platformctl registry push <reference> [flags]
func (c *CLIAdapter) Push(ctx context.Context, ref string, opts PushOptions) (*PushResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}

	// platformctl streams the push envelope from --input; the annotations
	// travel in its manifest because the command has no annotation flag.
	payload, err := pushEnvelope(opts)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "registry-push-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "image.json")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		return nil, err
	}

	args := []string{"registry", "push", ref, "--input", input}

	if opts.Encrypt {
		args = append(args, "--encrypt")
		if opts.KeyID != "" {
			args = append(args, "--key-id", opts.KeyID)
		}
	}

	if opts.AllowOverwrite {
		args = append(args, "--overwrite")
	}

	if opts.SignImage {
		args = append(args, "--sign")
		if opts.SigningKeyID != "" {
			args = append(args, "--signing-key-id", opts.SigningKeyID)
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliPushResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Push", Err: err}
	}

	return result.toPushResult(), nil
}

// Pull pulls an image from the registry via CLI.
// Command: platformctl registry pull <reference> [flags]
func (c *CLIAdapter) Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}

	args := []string{"registry", "pull", ref}

	if opts.DecryptIfEncrypted {
		args = append(args, "--decrypt")
	}

	if opts.VerifySignature {
		args = append(args, "--verify")
	}

	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, ErrImageNotFound{Reference: ref}
		}
		return nil, err
	}

	var result cliPullResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Pull", Err: err}
	}

	return result.toPullResult(), nil
}

// List lists images in the registry via CLI.
// Command: platformctl registry list [flags]
func (c *CLIAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := []string{"registry", "list"}

	if opts.Repository != "" {
		args = append(args, "--repository", opts.Repository)
	}

	if opts.TagPrefix != "" {
		args = append(args, "--tag-prefix", opts.TagPrefix)
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(opts.Limit))
	}

	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	if opts.IncludeEncrypted {
		args = append(args, "--include-encrypted")
	}

	if opts.SortBy != "" {
		args = append(args, "--sort-by", opts.SortBy)
	}

	if opts.SortDesc {
		args = append(args, "--sort-desc")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "List", Err: err}
	}

	return result.toListResult(), nil
}

// Delete deletes an image from the registry via CLI.
// Command: platformctl registry delete <reference> [flags]
func (c *CLIAdapter) Delete(ctx context.Context, ref string, opts DeleteOptions) (*DeleteResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}

	args := []string{"registry", "delete", ref}

	if opts.Force {
		args = append(args, "--force")
	}

	if opts.DeleteLayers {
		args = append(args, "--delete-layers")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, ErrImageNotFound{Reference: ref}
		}
		return nil, err
	}

	var result cliDeleteResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Delete", Err: err}
	}

	return result.toDeleteResult(), nil
}

// Inspect inspects an image in the registry via CLI.
// Command: platformctl registry inspect <reference>
func (c *CLIAdapter) Inspect(ctx context.Context, ref string) (*InspectResult, error) {
	if ref == "" {
		return nil, ErrInvalidArgument{Argument: "reference", Reason: "reference cannot be empty"}
	}

	output, err := c.runCommand(ctx, "registry", "inspect", ref)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, ErrImageNotFound{Reference: ref}
		}
		return nil, err
	}

	var result cliInspectResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Inspect", Err: err}
	}

	return result.toInspectResult(), nil
}

// Status retrieves the registry status via CLI.
// Command: platformctl registry status
func (c *CLIAdapter) Status(ctx context.Context) (*StatusResult, error) {
	output, err := c.runCommand(ctx, "registry", "status")
	if err != nil {
		return nil, err
	}

	var result cliStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Status", Err: err}
	}

	status, err := result.toStatusResult()
	if err != nil {
		return nil, ErrInvalidResponse{Operation: "Status", Err: err}
	}
	return status, nil
}

// Tag has no platformctl registry command.
func (c *CLIAdapter) Tag(ctx context.Context, sourceRef, targetRef string) (*TagResult, error) {
	return nil, noSurface(c.Name(), opTag)
}

// VerifyClient has no platformctl registry command.
func (c *CLIAdapter) VerifyClient(ctx context.Context, opts VerifyClientOptions) (*VerifyClientResult, error) {
	return nil, noSurface(c.Name(), opVerifyClient)
}

// GetSession has no platformctl registry command.
func (c *CLIAdapter) GetSession(ctx context.Context, clientID string) (*SessionResult, error) {
	return nil, noSurface(c.Name(), opGetSession)
}

// InvalidateSession has no platformctl registry command.
func (c *CLIAdapter) InvalidateSession(ctx context.Context, clientID string) error {
	return noSurface(c.Name(), opInvalidateSession)
}

// EncryptImage has no platformctl registry command.
func (c *CLIAdapter) EncryptImage(ctx context.Context, ref string, keyID string) (*EncryptImageResult, error) {
	return nil, noSurface(c.Name(), opEncryptImage)
}

// DecryptImage has no platformctl registry command.
func (c *CLIAdapter) DecryptImage(ctx context.Context, ref string) (*DecryptImageResult, error) {
	return nil, noSurface(c.Name(), opDecryptImage)
}

// Compile-time interface check
var _ RegistryCommands = (*CLIAdapter)(nil)
