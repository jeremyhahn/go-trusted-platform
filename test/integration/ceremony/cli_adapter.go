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

package ceremony

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

// CLIAdapter drives ceremony operations by shelling out to "platformctl
// ceremony ...". It reuses the same temp-config mechanism as the CA CLI
// adapter so a single daemon instance is targeted from every test.
type CLIAdapter struct {
	binaryPath   string
	socketPath   string
	grpcEndpoint string
	configPath   string
	configDir    string
}

// NewCLIAdapter returns an unconfigured CLI adapter. Setup locates platformctl
// and builds a temp YAML config file pointing it at the test daemon.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates the platformctl binary and writes a temporary config.
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

	if err := c.createTestConfig(); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	return nil
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

// createTestConfig creates a minimal platformctl config file targeting the
// test daemon. Same layout as the CA CLI adapter.
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-ceremony-test-*")
	if err != nil {
		return err
	}
	c.configDir = tmpDir
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return err
	}
	c.configPath = configPath
	return nil
}

// runCommand invokes platformctl with the shared config/context flags.
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

// decodeJSON unmarshals CLI JSON output into target.
func decodeJSON(data []byte, target interface{}) error {
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, target)
}

// Init runs "platformctl ceremony init".
func (c *CLIAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	if req == nil {
		req = &ceremonysdk.InitRequest{}
	}
	args := []string{"ceremony", "init", "--output", "json"}
	if req.SOPIN != "" {
		args = append(args, "--so-pin", req.SOPIN)
	}
	if req.UserPIN != "" {
		args = append(args, "--user-pin", req.UserPIN)
	}
	if req.Threshold != "" {
		args = append(args, "--threshold", req.Threshold)
	}
	if req.Hostname != "" {
		args = append(args, "--hostname", req.Hostname)
	}
	if len(req.SANs) > 0 {
		args = append(args, "--sans", strings.Join(req.SANs, ","))
	}
	if req.CredentialSealStrategy != "" {
		args = append(args, "--credential-seal-strategy", req.CredentialSealStrategy)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.InitResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony init", Err: err}
	}
	return resp, nil
}

// Status runs "platformctl ceremony status".
func (c *CLIAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	out, err := c.runCommand(ctx, "ceremony", "status", "--output", "json")
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.StatusResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony status", Err: err}
	}
	return resp, nil
}

// ClaimCertBegin runs "platformctl ceremony claim-cert begin".
func (c *CLIAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	if req == nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-cert begin", Err: fmt.Errorf("nil request")}
	}
	args := []string{"ceremony", "claim-cert", "begin", "--output", "json",
		"--username", req.Username,
	}
	if req.AuthenticatorType != "" {
		args = append(args, "--authenticator-type", string(req.AuthenticatorType))
	}
	if req.Slot != "" {
		args = append(args, "--slot", req.Slot)
	}
	if req.CredentialID != "" {
		args = append(args, "--credential-id", req.CredentialID)
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.ClaimCertBeginResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-cert begin", Err: err}
	}
	return resp, nil
}

// ClaimCertComplete runs "platformctl ceremony claim-cert complete".
func (c *CLIAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	if req == nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-cert complete", Err: fmt.Errorf("nil request")}
	}
	args := []string{"ceremony", "claim-cert", "complete", "--output", "json",
		"--username", req.Username,
		"--nonce", req.Nonce,
		"--signature", req.Signature,
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.ClaimCertCompleteResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-cert complete", Err: err}
	}
	return resp, nil
}

// ClaimShare runs "platformctl ceremony claim-share".
func (c *CLIAdapter) ClaimShare(ctx context.Context, req *ceremonysdk.ClaimShareRequest) (*ceremonysdk.ClaimShareResponse, error) {
	if req == nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-share", Err: fmt.Errorf("nil request")}
	}
	args := []string{"ceremony", "claim-share", "--output", "json", "--username", req.Username}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.ClaimShareResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony claim-share", Err: err}
	}
	return resp, nil
}

// SignCSR runs "platformctl ceremony sign-csr". The CLI expects a CSR file path;
// the adapter writes req.CSRPEM to a temp file and cleans it up on return.
func (c *CLIAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	if req == nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony sign-csr", Err: fmt.Errorf("nil request")}
	}
	tmpFile, err := os.CreateTemp("", "ceremony-csr-*.pem")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony sign-csr", Err: err}
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(req.CSRPEM); err != nil {
		tmpFile.Close()
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony sign-csr", Err: err}
	}
	tmpFile.Close()

	args := []string{"ceremony", "sign-csr", "--output", "json",
		"--username", req.Username,
		"--so-pin", req.SOPIN,
		"--csr-file", tmpFile.Name(),
	}
	if req.Role != "" {
		args = append(args, "--role", string(req.Role))
	}
	out, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	resp := &ceremonysdk.SignCSRResponse{}
	if err := decodeJSON(out, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "ceremony sign-csr", Err: err}
	}
	return resp, nil
}

var _ CeremonyCommands = (*CLIAdapter)(nil)
