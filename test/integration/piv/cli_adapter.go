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

package piv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// CLIAdapter drives PIV operations by shelling out to "platformctl piv ...".
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

	tmpDir, err := os.MkdirTemp("", "platformctl-piv-test-*")
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

// ListDevices runs "platformctl piv list-devices".
func (c *CLIAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	_ = req
	out, err := c.runCommand(ctx, "piv", "list-devices", "--output", "json")
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.ListDevicesResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv list-devices", Err: err}
	}
	return resp, nil
}

// ListSlots runs "platformctl piv list-slots --device ...".
func (c *CLIAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	if req == nil {
		req = &pivsdk.ListSlotsRequest{}
	}
	args := []string{"piv", "list-slots", "--output", "json"}
	if req.Device != "" {
		args = append(args, "--device", req.Device)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.ListSlotsResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv list-slots", Err: err}
	}
	return resp, nil
}

// SlotInfo runs "platformctl piv info --slot ...".
func (c *CLIAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	if req == nil {
		req = &pivsdk.SlotInfoRequest{}
	}
	args := []string{"piv", "info", "--output", "json", "--slot", req.Slot}
	if req.Device != "" {
		args = append(args, "--device", req.Device)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.SlotInfoResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv info", Err: err}
	}
	return resp, nil
}

// Generate runs "platformctl piv generate".
func (c *CLIAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	if req == nil {
		req = &pivsdk.GenerateRequest{}
	}
	args := []string{"piv", "generate", "--output", "json",
		"--slot", req.Slot,
		"--algorithm", string(req.Algorithm),
		"--pin", req.PIN,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.GenerateResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv generate", Err: err}
	}
	return resp, nil
}

// Import runs "platformctl piv import --key-file ...".
func (c *CLIAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	if req == nil {
		req = &pivsdk.ImportRequest{}
	}
	tmpFile, err := os.CreateTemp("", "piv-key-*.pem")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv import", Err: err}
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(req.PrivateKeyPEM); err != nil {
		tmpFile.Close()
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv import", Err: err}
	}
	tmpFile.Close()

	args := []string{"piv", "import", "--output", "json",
		"--slot", req.Slot,
		"--key-file", tmpFile.Name(),
		"--pin", req.PIN,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.ImportResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv import", Err: err}
	}
	return resp, nil
}

// Sign runs "platformctl piv sign --input-file ...".
func (c *CLIAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	if req == nil {
		req = &pivsdk.SignRequest{}
	}
	tmpFile, err := os.CreateTemp("", "piv-sign-*.bin")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv sign", Err: err}
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(req.Payload); err != nil {
		tmpFile.Close()
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv sign", Err: err}
	}
	tmpFile.Close()

	args := []string{"piv", "sign", "--output", "json",
		"--slot", req.Slot,
		"--input-file", tmpFile.Name(),
		"--pin", req.PIN,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.SignResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv sign", Err: err}
	}
	return resp, nil
}

// Attest runs "platformctl piv attest --slot ...".
func (c *CLIAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	if req == nil {
		req = &pivsdk.AttestRequest{}
	}
	args := []string{"piv", "attest", "--output", "json", "--slot", req.Slot}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.AttestResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv attest", Err: err}
	}
	return resp, nil
}

// Reset runs "platformctl piv reset --device ... --yes-i-understand".
func (c *CLIAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	if req == nil {
		req = &pivsdk.ResetRequest{}
	}
	args := []string{"piv", "reset", "--output", "json",
		"--device", req.Device,
		"--yes-i-understand",
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &pivsdk.ResetResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "piv reset", Err: err}
	}
	return resp, nil
}

var _ PIVCommands = (*CLIAdapter)(nil)
