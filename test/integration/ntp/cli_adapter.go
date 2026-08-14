// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ntp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// CLIAdapter drives NTPCommands by shelling out to "platformctl ntp ...",
// the operator-facing surface, over the Unix socket.
type CLIAdapter struct {
	binaryPath string
	configDir  string
	configPath string
}

// NewCLIAdapter returns an unconfigured CLI adapter.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates platformctl and writes a temp config targeting the test
// daemon over the Unix socket.
func (c *CLIAdapter) Setup(context.Context) error {
	endpoints := GetServiceEndpoints()
	binaryPath := endpoints.PlatformCTL
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath

	tmpDir, err := os.MkdirTemp("", "platformctl-ntp-test-*")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.configDir = tmpDir
	c.configPath = filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, endpoints.PlatformUnix, endpoints.PlatformGRPC)
	if err := os.WriteFile(c.configPath, []byte(configContent), 0o600); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	return nil
}

// Teardown removes the temp config directory.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		removeErr := os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
		return removeErr
	}
	return nil
}

// run invokes platformctl with the shared config/context flags plus JSON
// output.
func (c *CLIAdapter) run(ctx context.Context, args ...string) ([]byte, error) {
	full := []string{"--config", c.configPath, "--context", "integration-test"}
	full = append(full, args...)
	full = append(full, "--output", "json")

	cmd := exec.CommandContext(ctx, c.binaryPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out := stdout.String()
		if stderr.Len() > 0 {
			out += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{Args: full, Output: out, Err: err}
	}
	return stdout.Bytes(), nil
}

// decode unmarshals CLI JSON output.
func (c *CLIAdapter) decode(args []string, out []byte, target any) error {
	if err := json.Unmarshal(out, target); err != nil {
		return ErrCLIDecodeFailed{Args: args, Output: string(out), Err: err}
	}
	return nil
}

// Status runs "platformctl ntp status".
func (c *CLIAdapter) Status(ctx context.Context) (*platformv1.NTPStatus, error) {
	args := []string{"ntp", "status"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	status := &platformv1.NTPStatus{}
	if err := c.decode(args, out, status); err != nil {
		return nil, err
	}
	return status, nil
}

// Sources runs "platformctl ntp sources".
func (c *CLIAdapter) Sources(ctx context.Context) ([]*platformv1.NTPSource, error) {
	args := []string{"ntp", "sources"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var sources []*platformv1.NTPSource
	if err := c.decode(args, out, &sources); err != nil {
		return nil, err
	}
	return sources, nil
}

// Step runs "platformctl ntp step".
func (c *CLIAdapter) Step(ctx context.Context) (*platformv1.NTPStatus, error) {
	args := []string{"ntp", "step"}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	status := &platformv1.NTPStatus{}
	if err := c.decode(args, out, status); err != nil {
		return nil, err
	}
	return status, nil
}

// Compile-time check: the CLI adapter satisfies the shared surface.
var _ NTPCommands = (*CLIAdapter)(nil)
