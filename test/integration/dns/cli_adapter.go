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

// Package dns provides integration test adapters for DNS services.
// This file holds the suite's CLI leg: platformctl has no dns command group.

//go:build integration

package dns

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// cliNoSurfaceReason is where the missing CLI surface is recorded.
const cliNoSurfaceReason = "platformctl has no dns command group (docs/dns/cli.md, No CLI surface)"

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// ErrCLIDNSGroupPresent is returned when platformctl accepts the dns command
// group the docs declare missing. The suite must then drive it like every
// other transport, and docs/dns/cli.md must describe it.
type ErrCLIDNSGroupPresent struct {
	Output string
}

func (e ErrCLIDNSGroupPresent) Error() string {
	return fmt.Sprintf("platformctl accepts the dns command group docs/dns/cli.md declares missing (output: %s)", e.Output)
}

// CLIAdapter is the DNS suite's CLI leg. It does not implement DNSCommands:
// there are no DNS verbs to drive. It proves the gap is still the declared
// one, so the suite reports it as MISSING instead of calling verbs that do
// not exist.
type CLIAdapter struct {
	binaryPath string
	socketPath string
	configDir  string
	configPath string
}

// NewCLIAdapter creates the CLI leg from the harness environment.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	return &CLIAdapter{binaryPath: binaryPath, socketPath: socketPath}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists and runs.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path

	if _, err := c.run(ctx, "version"); err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}
	return nil
}

// Teardown removes the config Setup wrote.
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	return os.RemoveAll(c.configDir)
}

// ProbeDNSGroup returns nil when platformctl rejects "dns" as an unknown
// command, which is the declared gap, and ErrCLIDNSGroupPresent otherwise.
func (c *CLIAdapter) ProbeDNSGroup(ctx context.Context) error {
	output, err := c.run(ctx, "dns", "zone", "list")
	if err != nil && strings.Contains(output, `unknown command "dns"`) {
		return nil
	}
	return ErrCLIDNSGroupPresent{Output: output}
}

// run executes platformctl against the harness config and returns its
// combined output.
func (c *CLIAdapter) run(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultCommandTimeout)
	defer cancel()

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	fullArgs := append([]string{"--config", c.configPath}, args...)
	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}
