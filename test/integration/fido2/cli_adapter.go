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

package fido2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
)

// CLIAdapter drives FIDO2 operations by shelling out to "platformctl fido2 ...".
type CLIAdapter struct {
	binaryPath   string
	socketPath   string
	grpcEndpoint string
	configPath   string
	configDir    string
}

// NewCLIAdapter returns an unconfigured CLI adapter.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates platformctl and writes a temp config pointing at the daemon.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath

	c.socketPath = os.Getenv(EnvPlatformUnixSocket)
	if c.socketPath == "" {
		c.socketPath = GetServiceEndpoints().PlatformUnix
	}
	c.grpcEndpoint = os.Getenv(EnvPlatformGRPCEndpoint)
	if c.grpcEndpoint == "" {
		c.grpcEndpoint = GetServiceEndpoints().PlatformGRPC
	}

	tmpDir, err := os.MkdirTemp("", "platformctl-fido2-test-*")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.configDir = tmpDir
	c.configPath = filepath.Join(tmpDir, "config.yaml")
	content := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)
	return os.WriteFile(c.configPath, []byte(content), 0600)
}

// Teardown removes the temp config directory.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// runCommand executes platformctl with the shared config/context flags.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	var full []string
	if c.configPath != "" {
		full = append(full, "--config", c.configPath, "--context", "integration-test")
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, c.binaryPath, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		out := stdout.String()
		if stderr.Len() > 0 {
			out += "\nstderr: " + stderr.String()
		}
		return nil, ErrCallFailed{
			Protocol: "CLI",
			Method:   strings.Join(full, " "),
			Err:      fmt.Errorf("%w: %s", err, out),
		}
	}
	return stdout.Bytes(), nil
}

func decodeJSON(data []byte, target interface{}) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, target)
}

// ListDevices runs "platformctl fido2 list-devices".
func (c *CLIAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	_ = req
	out, err := c.runCommand(ctx, "fido2", "list-devices", "--output", "json")
	if err != nil {
		return nil, err
	}
	resp := &fido2sdk.ListDevicesResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 list-devices", Err: err}
	}
	return resp, nil
}

// WaitDevice runs "platformctl fido2 wait-device".
func (c *CLIAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	if req == nil {
		req = &fido2sdk.WaitDeviceRequest{}
	}
	args := []string{"fido2", "wait-device", "--output", "json"}
	if req.TimeoutSeconds > 0 {
		args = append(args, "--timeout", strconv.Itoa(int(req.TimeoutSeconds)))
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &fido2sdk.WaitDeviceResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 wait-device", Err: err}
	}
	return resp, nil
}

// Info runs "platformctl fido2 info".
func (c *CLIAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	if req == nil {
		req = &fido2sdk.InfoRequest{}
	}
	args := []string{"fido2", "info", "--output", "json", "--device", req.Device}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &fido2sdk.InfoResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 info", Err: err}
	}
	return resp, nil
}

// Register runs "platformctl fido2 register".
func (c *CLIAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	if req == nil {
		req = &fido2sdk.RegisterRequest{}
	}
	args := []string{"fido2", "register", "--output", "json", "--username", req.Username}
	if req.Role != "" {
		args = append(args, "--role", string(req.Role))
	}
	if req.RequirePIN {
		args = append(args, "--require-pin")
	}
	if req.RequireUV {
		args = append(args, "--require-uv")
	}
	if req.RPID != "" {
		args = append(args, "--rp-id", req.RPID)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &fido2sdk.RegisterResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 register", Err: err}
	}
	return resp, nil
}

// Authenticate runs "platformctl fido2 authenticate".
func (c *CLIAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	if req == nil {
		req = &fido2sdk.AuthenticateRequest{}
	}
	args := []string{"fido2", "authenticate", "--output", "json",
		"--credential-id", req.CredentialID,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &fido2sdk.AuthenticateResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "fido2 authenticate", Err: err}
	}
	return resp, nil
}

var _ FIDO2Commands = (*CLIAdapter)(nil)
