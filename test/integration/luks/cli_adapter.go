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

package luks

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

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
)

// CLIAdapter drives LUKS operations by shelling out to "platformctl luks ...".
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

	tmpDir, err := os.MkdirTemp("", "platformctl-luks-test-*")
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

// Status runs "platformctl luks status".
func (c *CLIAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	if req == nil {
		req = &lukssdk.StatusRequest{}
	}
	args := []string{"luks", "status", "--output", "json"}
	if req.Device != "" {
		args = append(args, "--device", req.Device)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.StatusResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks status", Err: err}
	}
	return resp, nil
}

// ListSlots runs "platformctl luks list-slots".
func (c *CLIAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	if req == nil {
		req = &lukssdk.ListSlotsRequest{}
	}
	args := []string{"luks", "list-slots", "--output", "json"}
	if req.Device != "" {
		args = append(args, "--device", req.Device)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.ListSlotsResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks list-slots", Err: err}
	}
	return resp, nil
}

// Info runs "platformctl luks info".
func (c *CLIAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	if req == nil {
		req = &lukssdk.InfoRequest{}
	}
	args := []string{"luks", "info", "--output", "json"}
	if req.Device != "" {
		args = append(args, "--device", req.Device)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.InfoResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks info", Err: err}
	}
	return resp, nil
}

// EnrollPassphrase runs "platformctl luks enroll-passphrase".
func (c *CLIAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollPassphraseRequest{}
	}
	args := []string{"luks", "enroll-passphrase", "--output", "json",
		"--device", req.Device,
		"--existing-passphrase", req.ExistingPassphrase,
		"--new-passphrase", req.NewPassphrase,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.EnrollPassphraseResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks enroll-passphrase", Err: err}
	}
	return resp, nil
}

// EnrollFIDO2 runs "platformctl luks enroll-fido2".
func (c *CLIAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	if req == nil {
		req = &lukssdk.EnrollFIDO2Request{}
	}
	args := []string{"luks", "enroll-fido2", "--output", "json",
		"--device", req.Device,
		"--existing-passphrase", req.ExistingPassphrase,
		"--credential-id", req.CredentialID,
	}
	if req.RequirePIN {
		args = append(args, "--require-pin")
	}
	if req.RequireUV {
		args = append(args, "--require-uv")
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.EnrollFIDO2Response{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks enroll-fido2", Err: err}
	}
	return resp, nil
}

// EnrollTPM runs "platformctl luks enroll-tpm".
func (c *CLIAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollTPMRequest{}
	}
	args := []string{"luks", "enroll-tpm", "--output", "json",
		"--device", req.Device,
		"--existing-passphrase", req.ExistingPassphrase,
	}
	if len(req.PCRs) > 0 {
		pcrs := make([]string, 0, len(req.PCRs))
		for _, p := range req.PCRs {
			pcrs = append(pcrs, strconv.Itoa(int(p)))
		}
		args = append(args, "--pcrs", strings.Join(pcrs, ","))
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.EnrollTPMResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks enroll-tpm", Err: err}
	}
	return resp, nil
}

// EnrollRecovery runs "platformctl luks enroll-recovery".
func (c *CLIAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollRecoveryRequest{}
	}
	args := []string{"luks", "enroll-recovery", "--output", "json",
		"--device", req.Device,
		"--existing-passphrase", req.ExistingPassphrase,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.EnrollRecoveryResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks enroll-recovery", Err: err}
	}
	return resp, nil
}

// RemoveKey runs "platformctl luks remove-key".
func (c *CLIAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	if req == nil {
		req = &lukssdk.RemoveKeyRequest{}
	}
	args := []string{"luks", "remove-key", "--output", "json",
		"--device", req.Device,
		"--slot", strconv.Itoa(int(req.Slot)),
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.RemoveKeyResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks remove-key", Err: err}
	}
	return resp, nil
}

// TestUnlock runs "platformctl luks test-unlock".
func (c *CLIAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	if req == nil {
		req = &lukssdk.TestUnlockRequest{}
	}
	args := []string{"luks", "test-unlock", "--output", "json",
		"--device", req.Device,
		"--slot", strconv.Itoa(int(req.Slot)),
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.TestUnlockResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks test-unlock", Err: err}
	}
	return resp, nil
}

// ChangePassphrase runs "platformctl luks change-passphrase".
func (c *CLIAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.ChangePassphraseRequest{}
	}
	args := []string{"luks", "change-passphrase", "--output", "json",
		"--device", req.Device,
		"--slot", strconv.Itoa(int(req.Slot)),
		"--old-passphrase", req.OldPassphrase,
		"--new-passphrase", req.NewPassphrase,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &lukssdk.ChangePassphraseResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "luks change-passphrase", Err: err}
	}
	return resp, nil
}

var _ LUKSCommands = (*CLIAdapter)(nil)
