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

// Package container provides multi-protocol integration tests for the container orchestrator.
// This file contains the CLI protocol adapter that executes platformctl container commands.
package container

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// CLIAdapter implements ContainerCommands using the platformctl CLI binary.
// It executes container commands through the CLI and parses JSON output.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// Configuration is read from environment variables with sensible defaults.
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
// It also performs a connectivity check by running the version command.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrAdapterConnectionFailed{Adapter: "CLI", URL: c.binaryPath, Err: err}
	}

	// Verify binary works by running version command
	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return ErrAdapterConnectionFailed{Adapter: "CLI", URL: c.binaryPath, Err: err}
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	return nil
}

// runCommand executes a platformctl command and returns the output.
// It adds common flags (--output json, --socket) and handles timeouts.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	fullArgs := []string{"--output", "json"}

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
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCommandFailed{Command: strings.Join(fullArgs, " "), Output: output, Err: err}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Container Lifecycle Operations
// =============================================================================

// Create creates a new container via CLI.
// Supported options: name, image, command, environment, labels, workdir, user,
// privileged, network mode, memory, cpus, restart policy, and attestation.
func (c *CLIAdapter) Create(ctx context.Context, opts CreateOptions) (*Container, error) {
	if opts.Name == "" {
		return nil, ErrCommandFailed{Command: "container create", Output: "container name is required", Err: fmt.Errorf("empty name")}
	}
	if opts.Image == "" {
		return nil, ErrCommandFailed{Command: "container create", Output: "container image is required", Err: fmt.Errorf("empty image")}
	}

	args := []string{"container", "create", opts.Name, "--image", opts.Image}

	if len(opts.Command) > 0 {
		args = append(args, "--command", strings.Join(opts.Command, " "))
	}

	for k, v := range opts.Environment {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}

	for k, v := range opts.Labels {
		args = append(args, "--label", fmt.Sprintf("%s=%s", k, v))
	}

	if opts.WorkingDir != "" {
		args = append(args, "--workdir", opts.WorkingDir)
	}

	if opts.User != "" {
		args = append(args, "--user", opts.User)
	}

	if opts.Privileged {
		args = append(args, "--privileged")
	}

	if opts.NetworkMode != "" {
		args = append(args, "--network", opts.NetworkMode)
	}

	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.FormatInt(opts.Memory, 10))
	}

	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.FormatFloat(opts.CPUs, 'f', 2, 64))
	}

	if opts.RestartPolicy != "" {
		args = append(args, "--restart", opts.RestartPolicy)
	}

	if opts.AttestOnCreate {
		args = append(args, "--attest")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliContainerResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Create", Err: err}
	}

	return result.toContainer(), nil
}

// Start starts a container via CLI.
func (c *CLIAdapter) Start(ctx context.Context, id string) error {
	if id == "" {
		return ErrCommandFailed{Command: "container start", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	_, err := c.runCommand(ctx, "container", "start", id)
	return err
}

// Stop stops a container via CLI with the specified timeout.
func (c *CLIAdapter) Stop(ctx context.Context, id string, timeout time.Duration) error {
	if id == "" {
		return ErrCommandFailed{Command: "container stop", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	args := []string{"container", "stop", id}
	if timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(int(timeout.Seconds())))
	}
	_, err := c.runCommand(ctx, args...)
	return err
}

// Remove removes a container via CLI.
// If force is true, the container will be removed even if running.
func (c *CLIAdapter) Remove(ctx context.Context, id string, force bool) error {
	if id == "" {
		return ErrCommandFailed{Command: "container remove", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	args := []string{"container", "remove", id}
	if force {
		args = append(args, "--force")
	}
	_, err := c.runCommand(ctx, args...)
	return err
}

// Get retrieves container details via CLI.
func (c *CLIAdapter) Get(ctx context.Context, id string) (*Container, error) {
	if id == "" {
		return nil, ErrCommandFailed{Command: "container get", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	output, err := c.runCommand(ctx, "container", "get", id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, ErrContainerNotFound{ID: id}
		}
		return nil, err
	}

	var result cliContainerResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Get", Err: err}
	}

	return result.toContainer(), nil
}

// =============================================================================
// Container Listing
// =============================================================================

// List lists containers via CLI with filtering options.
// Supports: all, limit, state filter, name filter, and label filters.
func (c *CLIAdapter) List(ctx context.Context, opts ListOptions) ([]*Container, error) {
	args := []string{"container", "list"}

	if opts.All {
		args = append(args, "--all")
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(opts.Limit))
	}

	if opts.StateFilter != "" {
		args = append(args, "--state", string(opts.StateFilter))
	}

	if opts.NameFilter != "" {
		args = append(args, "--name", opts.NameFilter)
	}

	for k, v := range opts.Filters {
		args = append(args, "--filter", fmt.Sprintf("%s=%s", k, v))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliContainerListResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "List", Err: err}
	}

	containers := make([]*Container, len(result.Containers))
	for i, r := range result.Containers {
		containers[i] = r.toContainer()
	}

	return containers, nil
}

// =============================================================================
// Container Logs
// =============================================================================

// Logs retrieves container logs via CLI.
// Supports: stdout, stderr, tail, and timestamps options.
func (c *CLIAdapter) Logs(ctx context.Context, id string, opts LogOptions) ([]string, error) {
	if id == "" {
		return nil, ErrCommandFailed{Command: "container logs", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	args := []string{"container", "logs", id}

	if opts.Tail > 0 {
		args = append(args, "--tail", strconv.Itoa(opts.Tail))
	}

	if opts.Timestamps {
		args = append(args, "--timestamps")
	}

	if !opts.Stdout && opts.Stderr {
		args = append(args, "--stderr-only")
	}

	if opts.Stdout && !opts.Stderr {
		args = append(args, "--stdout-only")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliLogsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Logs", Err: err}
	}

	return result.Lines, nil
}

// =============================================================================
// Container Attestation
// =============================================================================

// Attest performs container attestation via CLI.
// Returns an attestation report including TPM quote, signature, and measurements.
func (c *CLIAdapter) Attest(ctx context.Context, id string) (*AttestationReport, error) {
	if id == "" {
		return nil, ErrCommandFailed{Command: "container attest", Output: "container ID is required", Err: fmt.Errorf("empty id")}
	}

	output, err := c.runCommand(ctx, "container", "attest", id)
	if err != nil {
		return nil, err
	}

	var result cliAttestationResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrInvalidResponse{Operation: "Attest", Err: err}
	}

	return result.toAttestationReport(), nil
}

// Ensure CLIAdapter implements ContainerCommands interface at compile time.
var _ ContainerCommands = (*CLIAdapter)(nil)
