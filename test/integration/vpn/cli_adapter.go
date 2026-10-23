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

package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// CLIAdapter drives VPNCommands by shelling out to "platformctl vpn ...",
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
	binaryPath := platformCTLPath()
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath

	dir, path, err := helpers.WriteTempLocalCLIConfig(helpers.GetSocketPath(), helpers.GetGRPCEndpoint())
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.configDir = dir
	c.configPath = path
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
	full := []string{"--config", c.configPath, "--context", helpers.CLIContextName}
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

// runInto invokes platformctl and decodes its JSON output into target.
func (c *CLIAdapter) runInto(ctx context.Context, target any, args ...string) error {
	out, err := c.run(ctx, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, target); err != nil {
		return ErrCLIDecodeFailed{Args: args, Output: string(out), Err: err}
	}
	return nil
}

// EnrolPeer runs "platformctl vpn peer enrol".
func (c *CLIAdapter) EnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (*platformv1.VPNPeer, error) {
	args := []string{"vpn", "peer", "enrol", deviceID, "--tenant", tenantID}
	for _, zone := range zones {
		args = append(args, "--zone", zone)
	}
	peer := &platformv1.VPNPeer{}
	if err := c.runInto(ctx, peer, args...); err != nil {
		return nil, err
	}
	return peer, nil
}

// ListPeers runs "platformctl vpn peer list".
func (c *CLIAdapter) ListPeers(ctx context.Context, tenantID string) ([]*platformv1.VPNPeer, error) {
	var peers []*platformv1.VPNPeer
	if err := c.runInto(ctx, &peers, "vpn", "peer", "list", "--tenant", tenantID); err != nil {
		return nil, err
	}
	return peers, nil
}

// RevokePeer runs "platformctl vpn peer revoke".
func (c *CLIAdapter) RevokePeer(ctx context.Context, tenantID, deviceID string) error {
	_, err := c.run(ctx, "vpn", "peer", "revoke", deviceID, "--tenant", tenantID)
	return err
}

// Status runs "platformctl vpn status".
func (c *CLIAdapter) Status(ctx context.Context, gatewayID string) ([]*platformv1.VPNGatewayStatus, error) {
	args := []string{"vpn", "status"}
	if gatewayID != "" {
		args = append(args, "--gateway", gatewayID)
	}
	var gateways []*platformv1.VPNGatewayStatus
	if err := c.runInto(ctx, &gateways, args...); err != nil {
		return nil, err
	}
	return gateways, nil
}

// GetPosturePolicy runs "platformctl vpn posture-policy get".
func (c *CLIAdapter) GetPosturePolicy(ctx context.Context, tenantID, name string) (*platformv1.VPNPosturePolicy, error) {
	policy := &platformv1.VPNPosturePolicy{}
	if err := c.runInto(ctx, policy, "vpn", "posture-policy", "get", name, "--tenant", tenantID); err != nil {
		return nil, err
	}
	return policy, nil
}

// SetPosturePolicy stages module in the adapter's temp directory and runs
// "platformctl vpn posture-policy set --file".
func (c *CLIAdapter) SetPosturePolicy(ctx context.Context, tenantID, name, module string) (*platformv1.VPNPosturePolicy, error) {
	file := filepath.Join(c.configDir, name+".rego")
	if err := os.WriteFile(file, []byte(module), 0o600); err != nil {
		return nil, ErrPostureModuleWrite{Path: file, Err: err}
	}
	policy := &platformv1.VPNPosturePolicy{}
	if err := c.runInto(ctx, policy, "vpn", "posture-policy", "set", name, "--tenant", tenantID, "--file", file); err != nil {
		return nil, err
	}
	return policy, nil
}

// DeletePosturePolicy runs "platformctl vpn posture-policy delete".
func (c *CLIAdapter) DeletePosturePolicy(ctx context.Context, tenantID, name string) error {
	_, err := c.run(ctx, "vpn", "posture-policy", "delete", name, "--tenant", tenantID)
	return err
}

// ListPosturePolicies runs "platformctl vpn posture-policy list".
func (c *CLIAdapter) ListPosturePolicies(ctx context.Context, tenantID string) ([]*platformv1.VPNPosturePolicy, error) {
	var policies []*platformv1.VPNPosturePolicy
	if err := c.runInto(ctx, &policies, "vpn", "posture-policy", "list", "--tenant", tenantID); err != nil {
		return nil, err
	}
	return policies, nil
}

// Compile-time check: the CLI adapter satisfies the shared surface.
var _ VPNCommands = (*CLIAdapter)(nil)
