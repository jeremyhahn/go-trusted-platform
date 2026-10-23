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

package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// CLIAdapter drives the provisioning session verbs by shelling out to
// "platformctl provision session ...". It reuses the temp-config mechanism
// shared by the ceremony/CA CLI adapters so a single daemon instance is
// targeted from every test. The CLI intentionally exposes only the session
// verbs on daemon transports; its pre-enrollment verbs (fetch-config /
// interactive) are raw-HTTP install-time flows, so this adapter implements
// SessionCommands.
type CLIAdapter struct {
	binaryPath   string
	socketPath   string
	grpcEndpoint string
	configPath   string
	configDir    string
}

// NewCLIAdapter returns an unconfigured CLI adapter. Setup locates
// platformctl and builds a temp YAML config file pointing it at the daemon.
func NewCLIAdapter() *CLIAdapter { return &CLIAdapter{} }

// Name returns "CLI".
func (c *CLIAdapter) Name() string { return "CLI" }

// Setup locates the platformctl binary and writes a temporary config.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := platformctlPath()
	if _, err := exec.LookPath(binaryPath); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	c.binaryPath = binaryPath
	c.socketPath = unixSocket()
	c.grpcEndpoint = grpcEndpoint()

	if err := c.createTestConfig(); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}
	return nil
}

// Teardown removes the temp config directory.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		if err := os.RemoveAll(c.configDir); err != nil {
			return err
		}
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// createTestConfig writes the shared harness platformctl config targeting
// the test daemon. Beyond the Unix socket it points the CLI's quicbaas client
// at platformd's gRPC listener with the harness mTLS files, which the kms
// verbs the fixture runs (`kms key csr`) open (docs/kms/cli.md §3).
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-provision-test-*")
	if err != nil {
		return err
	}
	c.configDir = tmpDir
	// The fixture's kms verbs (`kms key generate`, `kms key csr`) open the
	// CLI's quicbaas client. The shared harness config points it at
	// platformd's gRPC listener with the harness mTLS files
	// (docs/kms/cli.md §3).
	configPath, err := helpers.WriteLocalCLIConfig(tmpDir, c.socketPath, c.grpcEndpoint)
	if err != nil {
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

// cliSession mirrors the CLI JSON output shape for a provisioning session
// (pkg/cli/commands/provision/session.go sessionInfo): the uint64 profile
// ID serializes as a decimal string per the repo-wide convention.
type cliSession struct {
	ID         string `json:"id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	ProfileID  string `json:"profile_id"`
	Fulfilled  bool   `json:"fulfilled"`
	CreatedAt  string `json:"created_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// toPb converts the CLI session shape onto the shared pb session type so
// the scenario assertions are transport-agnostic.
func (s cliSession) toPb() (*platformv1.ProvisioningSession, error) {
	pb := &platformv1.ProvisioningSession{
		Id:         s.ID,
		EkSerial:   s.EKSerial,
		MacAddress: s.MACAddress,
		TenantId:   s.TenantID,
		Fulfilled:  s.Fulfilled,
	}
	if s.ProfileID != "" {
		id, err := strconv.ParseUint(s.ProfileID, 10, 64)
		if err != nil {
			return nil, ErrUnexpectedOutput{Method: "session", Err: err}
		}
		pb.ProfileId = id
	}
	return pb, nil
}

// ListSessions runs "platformctl provision session list -o json".
func (c *CLIAdapter) ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error) {
	out, err := c.runCommand(ctx, "provision", "session", "list", "-o", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		Total    int          `json:"total"`
		Sessions []cliSession `json:"sessions"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, ErrUnexpectedOutput{Method: "session list", Err: err}
	}
	sessions := make([]*platformv1.ProvisioningSession, 0, len(result.Sessions))
	for _, s := range result.Sessions {
		pb, convErr := s.toPb()
		if convErr != nil {
			return nil, convErr
		}
		sessions = append(sessions, pb)
	}
	return sessions, nil
}

// GetSession runs "platformctl provision session get <id> -o json".
func (c *CLIAdapter) GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error) {
	out, err := c.runCommand(ctx, "provision", "session", "get", sessionID, "-o", "json")
	if err != nil {
		return nil, err
	}
	var session cliSession
	if err := json.Unmarshal(out, &session); err != nil {
		return nil, ErrUnexpectedOutput{Method: "session get", Err: err}
	}
	return session.toPb()
}

// FulfillSession runs "platformctl provision session fulfill <id>
// --profile-id <uint64> -o json".
func (c *CLIAdapter) FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error) {
	out, err := c.runCommand(ctx, "provision", "session", "fulfill", sessionID,
		"--profile-id", strconv.FormatUint(profileID, 10), "-o", "json")
	if err != nil {
		return nil, err
	}
	var result struct {
		SessionID string `json:"session_id"`
		ProfileID string `json:"profile_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, ErrUnexpectedOutput{Method: "session fulfill", Err: err}
	}
	return &platformv1.FulfillSessionResponse{Status: result.Status}, nil
}

// PollSession runs "platformctl provision session poll <id>". The poll verb
// shadows the global --output flag with its config-file path flag, so the
// default output format is used; only the delivered-vs-pending status is
// mapped back onto the pb reply.
func (c *CLIAdapter) PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error) {
	out, err := c.runCommand(ctx, "provision", "session", "poll", sessionID)
	if err != nil {
		return nil, err
	}
	var result struct {
		SessionID string `json:"session_id"`
		Status    string `json:"status"`
		Config    string `json:"config,omitempty"`
	}
	// The default output format may be table; fall back to raw string
	// scanning when the output is not JSON.
	if jsonErr := json.Unmarshal(out, &result); jsonErr != nil {
		if strings.Contains(string(out), "pending") {
			return &platformv1.PollSessionResponse{
				Result: &platformv1.PollSessionResponse_PendingStatus{PendingStatus: "pending"},
			}, nil
		}
		return nil, ErrUnexpectedOutput{Method: "session poll", Err: jsonErr}
	}
	if result.Status == "pending" {
		return &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_PendingStatus{PendingStatus: "pending"},
		}, nil
	}
	return &platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_Delivered{
			Delivered: &platformv1.DeliveredConfig{
				ConfigJson: []byte(result.Config),
				Status:     result.Status,
			},
		},
	}, nil
}

// Compile-time interface check.
var _ SessionCommands = (*CLIAdapter)(nil)
