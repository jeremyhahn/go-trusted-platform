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

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// CLIAdapter drives OrchestratorCommands by shelling out to
// "platformctl orchestrator ...", the operator-facing surface, over the Unix
// socket. Every request field the adapter receives becomes the matching
// flag, so the scenario's filter and paging cases exercise each flag.
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

	tmpDir, err := os.MkdirTemp("", "platformctl-orchestrator-test-*")
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

// call invokes platformctl with the shared config/context flags plus JSON
// output and decodes the response into target.
func (c *CLIAdapter) call(ctx context.Context, target any, args ...string) error {
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
		return ErrCLICommandFailed{Args: full, Output: out, Err: err}
	}
	if err := json.Unmarshal(stdout.Bytes(), target); err != nil {
		return ErrCLIDecodeFailed{Args: full, Output: stdout.String(), Err: err}
	}
	return nil
}

// flag appends "--name value" when value is set.
func flag(args []string, name, value string) []string {
	if value == "" {
		return args
	}
	return append(args, "--"+name, value)
}

// pageFlags appends --limit and --offset for a set page.
func pageFlags(args []string, page *platformv1.OrchestratorPage) []string {
	if page == nil {
		return args
	}
	return append(args,
		"--limit", strconv.FormatInt(int64(page.GetLimit()), 10),
		"--offset", strconv.FormatInt(int64(page.GetOffset()), 10))
}

// Health runs "platformctl orchestrator health".
func (c *CLIAdapter) Health(ctx context.Context) (*platformv1.OrchestratorHealthResponse, error) {
	resp := &platformv1.OrchestratorHealthResponse{}
	return resp, c.call(ctx, resp, "orchestrator", "health")
}

// ListAgents runs "platformctl orchestrator agent list".
func (c *CLIAdapter) ListAgents(ctx context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	args := []string{"orchestrator", "agent", "list"}
	args = flag(args, "tenant", req.GetTenantId())
	args = flag(args, "status", req.GetStatus())
	args = flag(args, "host", req.GetHost())
	args = flag(args, "backend", req.GetBackend())
	args = pageFlags(args, req.GetPage())
	resp := &platformv1.ListOrchestratorAgentsResponse{}
	return resp, c.call(ctx, resp, args...)
}

// agentArgs builds "orchestrator agent <verb> <agent-id> [--tenant t]".
func agentArgs(verb, tenantID, agentID string) []string {
	return flag([]string{"orchestrator", "agent", verb, agentID}, "tenant", tenantID)
}

// GetAgent runs "platformctl orchestrator agent get".
func (c *CLIAdapter) GetAgent(ctx context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	resp := &platformv1.GetOrchestratorAgentResponse{}
	return resp, c.call(ctx, resp, agentArgs("get", req.GetTenantId(), req.GetAgentId())...)
}

// DisableAgent runs "platformctl orchestrator agent disable".
func (c *CLIAdapter) DisableAgent(ctx context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	resp := &platformv1.DisableOrchestratorAgentResponse{}
	return resp, c.call(ctx, resp, agentArgs("disable", req.GetTenantId(), req.GetAgentId())...)
}

// EnableAgent runs "platformctl orchestrator agent enable".
func (c *CLIAdapter) EnableAgent(ctx context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	resp := &platformv1.EnableOrchestratorAgentResponse{}
	return resp, c.call(ctx, resp, agentArgs("enable", req.GetTenantId(), req.GetAgentId())...)
}

// ListSessions runs "platformctl orchestrator session list".
func (c *CLIAdapter) ListSessions(ctx context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	args := []string{"orchestrator", "session", "list"}
	args = flag(args, "status", req.GetStatus())
	args = flag(args, "job", req.GetJobId())
	args = flag(args, "agent", req.GetAgentId())
	args = pageFlags(args, req.GetPage())
	resp := &platformv1.ListOrchestratorSessionsResponse{}
	return resp, c.call(ctx, resp, args...)
}

// CloseSession runs "platformctl orchestrator session close".
func (c *CLIAdapter) CloseSession(ctx context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	resp := &platformv1.CloseOrchestratorSessionResponse{}
	return resp, c.call(ctx, resp, "orchestrator", "session", "close", req.GetSessionId())
}

// ListJobs runs "platformctl orchestrator job list"; each status becomes one
// repeated --status flag.
func (c *CLIAdapter) ListJobs(ctx context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	args := []string{"orchestrator", "job", "list"}
	args = flag(args, "tenant", req.GetTenantId())
	for _, status := range req.GetStatuses() {
		args = flag(args, "status", status)
	}
	args = pageFlags(args, req.GetPage())
	resp := &platformv1.ListOrchestratorJobsResponse{}
	return resp, c.call(ctx, resp, args...)
}

// jobArgs builds "orchestrator job <verb> <job-id> [--tenant t]".
func jobArgs(verb, tenantID, jobID string) []string {
	return flag([]string{"orchestrator", "job", verb, jobID}, "tenant", tenantID)
}

// GetJob runs "platformctl orchestrator job get".
func (c *CLIAdapter) GetJob(ctx context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	resp := &platformv1.GetOrchestratorJobResponse{}
	return resp, c.call(ctx, resp, jobArgs("get", req.GetTenantId(), req.GetJobId())...)
}

// CancelJob runs "platformctl orchestrator job cancel".
func (c *CLIAdapter) CancelJob(ctx context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	resp := &platformv1.CancelOrchestratorJobResponse{}
	return resp, c.call(ctx, resp, jobArgs("cancel", req.GetTenantId(), req.GetJobId())...)
}

// Compile-time check: the CLI adapter satisfies the shared surface.
var _ OrchestratorCommands = (*CLIAdapter)(nil)
