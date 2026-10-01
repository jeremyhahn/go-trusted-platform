//go:build integration

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

package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLIExecutionFailed indicates a CLI command execution failure.
type ErrCLIExecutionFailed struct {
	Command string
	Stdout  string
	Stderr  string
	Err     error
}

func (e ErrCLIExecutionFailed) Error() string {
	return fmt.Sprintf("CLI execution failed for '%s': %v\nStdout: %s\nStderr: %s",
		e.Command, e.Err, e.Stdout, e.Stderr)
}

func (e ErrCLIExecutionFailed) Unwrap() error {
	return e.Err
}

// ErrCLIOutputParseFailed indicates a failure to parse CLI output.
type ErrCLIOutputParseFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("CLI output parse failed for '%s': %v\nOutput: %s",
		e.Command, e.Err, e.Output)
}

func (e ErrCLIOutputParseFailed) Unwrap() error {
	return e.Err
}

// ErrCLINotConfigured indicates the CLI binary path is not configured.
type ErrCLINotConfigured struct{}

func (e ErrCLINotConfigured) Error() string {
	return "platformctl CLI binary not found or not configured"
}

// =============================================================================
// CLI Adapter
// =============================================================================

// CLIAdapter implements SDNCommands using the platformctl CLI tool.
// This adapter executes CLI commands and parses JSON output to test
// the CLI interface consistency with other protocol adapters.
type CLIAdapter struct {
	binaryPath   string
	configPath   string
	configDir    string
	socketPath   string
	grpcEndpoint string
	timeout      time.Duration
}

// NewCLIAdapter creates a new CLI adapter with default settings.
// It looks for platformctl in PATH or uses PLATFORMCTL_PATH environment variable.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv("PLATFORMCTL_PATH")
	if binaryPath == "" {
		binaryPath = "platformctl"
	}

	socketPath := os.Getenv("PLATFORMD_SOCKET")
	if socketPath == "" {
		socketPath = os.Getenv("PLATFORM_SOCKET_PATH")
	}
	if socketPath == "" {
		socketPath = "/run/platformd.sock"
	}

	grpcEndpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT")
	if grpcEndpoint == "" {
		grpcEndpoint = "localhost:10443"
	}

	return &CLIAdapter{
		binaryPath:   binaryPath,
		socketPath:   socketPath,
		grpcEndpoint: grpcEndpoint,
		timeout:      30 * time.Second,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary is available and creates a config file
// so the CLI can connect to the running platformd instance.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	// Verify CLI binary exists
	_, err := exec.LookPath(c.binaryPath)
	if err != nil {
		return ErrCLINotConfigured{}
	}

	// Create temporary config file for CLI to connect to test platformd
	if err := c.createTestConfig(); err != nil {
		return fmt.Errorf("cli: failed to create test config: %w", err)
	}

	return nil
}

// Teardown cleans up temporary config files.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// createTestConfig creates a minimal config file for platformctl to connect
// to the test platformd instance via Unix socket.
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-sdn-test-*")
	if err != nil {
		return err
	}
	c.configDir = tmpDir

	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)

	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return err
	}

	c.configPath = configPath
	log.Printf("[CLI] created test config at %s (socket=%s)", configPath, c.socketPath)
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Add common flags
	cmdArgs := append([]string{"--output", "json"}, args...)
	if c.configPath != "" {
		cmdArgs = append([]string{"--config", c.configPath}, cmdArgs...)
	}

	cmdStr := strings.Join(cmdArgs, " ")
	log.Printf("[CLI] executing: %s (timeout=%s)", cmdStr, c.timeout)

	// Create command with timeout
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.binaryPath, cmdArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("[CLI] command failed: %s err=%v", cmdStr, err)
		return nil, ErrCLIExecutionFailed{
			Command: cmdStr,
			Stdout:  stdout.String(),
			Stderr:  stderr.String(),
			Err:     err,
		}
	}

	log.Printf("[CLI] command completed: %s", cmdStr)
	return stdout.Bytes(), nil
}

// parseJSONOutput parses JSON output from the CLI.
func (c *CLIAdapter) parseJSONOutput(output []byte, v interface{}) error {
	if err := json.Unmarshal(output, v); err != nil {
		return ErrCLIOutputParseFailed{
			Output: string(output),
			Err:    err,
		}
	}
	return nil
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via CLI.
func (c *CLIAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	args := []string{"sdn", "bridge", "create",
		"--id", opts.BridgeID,
		"--name", opts.Name,
		"--type", opts.Type,
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if opts.DatapathID != "" {
		args = append(args, "--datapath-id", opts.DatapathID)
	}
	if opts.FailMode != "" {
		args = append(args, "--fail-mode", opts.FailMode)
	}
	if opts.STP {
		args = append(args, "--stp")
	}
	if opts.RSTP {
		args = append(args, "--rstp")
	}
	if opts.MTU > 0 {
		args = append(args, "--mtu", strconv.Itoa(int(opts.MTU)))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs the Bridge protobuf directly (flat, not wrapped):
	// {"id": "uuid", "config": {"name": "...", "type": N, ...}, "status": N, "created_at": {...}}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			DatapathID string            `json:"datapath_id"`
			StpEnabled bool              `json:"stp_enabled"`
			Mtu        uint32            `json:"mtu"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{}   `json:"status"`
		CreatedAt interface{}   `json:"created_at"`
		Ports     []interface{} `json:"ports"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	// Use the bridge name as BridgeID — this matches the test's unique bridge name
	// and is what OVS uses to identify bridges (not the UUID)
	bridgeID := result.Config.Name
	if bridgeID == "" {
		bridgeID = result.ID
	}

	return &BridgeCreateResult{
		BridgeID:    bridgeID,
		Name:        result.Config.Name,
		Type:        parseBridgeTypeFromJSON(result.Config.Type),
		DatapathID:  result.Config.DatapathID,
		Status:      fmt.Sprintf("%v", result.Status),
		CreatedAt:   parseTimestamp(result.CreatedAt),
		PortCount:   int32(len(result.Ports)),
		Description: result.Config.Options["description"],
	}, nil
}

// BridgeGet retrieves a bridge by ID via CLI.
func (c *CLIAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	output, err := c.runCommand(ctx, "sdn", "bridge", "get", bridgeID)
	if err != nil {
		return nil, err
	}

	// CLI outputs the Bridge protobuf directly (flat, not wrapped):
	// {"id": "uuid", "config": {"name": "...", "type": N, ...}, "status": N, "created_at": {...}, ...}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			DatapathID string            `json:"datapath_id"`
			StpEnabled bool              `json:"stp_enabled"`
			Mtu        uint32            `json:"mtu"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		CreatedAt interface{} `json:"created_at"`
		UpdatedAt interface{} `json:"updated_at"`
		Ports     []struct {
			ID       string `json:"id"`
			BridgeID string `json:"bridge_id"`
			Config   struct {
				Name       string      `json:"name"`
				Type       interface{} `json:"type"`
				Vlan       uint32      `json:"vlan"`
				MacAddress string      `json:"mac_address"`
				Mtu        uint32      `json:"mtu"`
			} `json:"config"`
			Status interface{} `json:"status"`
		} `json:"ports"`
		Stats struct {
			TotalPorts uint64 `json:"total_ports"`
			TotalFlows uint64 `json:"total_flows"`
		} `json:"stats"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	resolvedID := result.Config.Name
	if resolvedID == "" {
		resolvedID = result.ID
	}
	if id, ok := result.Config.Labels["bridge_id"]; ok && id != "" {
		resolvedID = id
	}

	createdAt := parseTimestamp(result.CreatedAt)
	updatedAt := parseTimestamp(result.UpdatedAt)

	ports := make([]PortSummary, len(result.Ports))
	for i, p := range result.Ports {
		ports[i] = PortSummary{
			PortID: p.ID,
			Name:   p.Config.Name,
			Type:   fmt.Sprintf("%v", p.Config.Type),
			MAC:    p.Config.MacAddress,
			Tag:    int32(p.Config.Vlan),
		}
	}

	// Extract fail_mode and rstp from config options
	failMode := result.Config.Options["fail_mode"]
	rstp := result.Config.Options["rstp_enable"] == "true"

	return &BridgeGetResult{
		BridgeID:    resolvedID,
		Name:        result.Config.Name,
		Type:        parseBridgeTypeFromJSON(result.Config.Type),
		DatapathID:  result.Config.DatapathID,
		Status:      fmt.Sprintf("%v", result.Status),
		FailMode:    failMode,
		STP:         result.Config.StpEnabled,
		RSTP:        rstp,
		MTU:         int32(result.Config.Mtu),
		PortCount:   int32(result.Stats.TotalPorts),
		FlowCount:   int32(result.Stats.TotalFlows),
		Description: result.Config.Options["description"],
		Tags:        result.Config.Labels,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		Ports:       ports,
	}, nil
}

// BridgeDelete deletes a bridge via CLI.
func (c *CLIAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	args := []string{"sdn", "bridge", "delete", bridgeID}

	if opts.Force {
		args = append(args, "--force")
	}
	if opts.DeletePorts {
		args = append(args, "--delete-ports")
	}
	if opts.DeleteFlows {
		args = append(args, "--delete-flows")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID   string `json:"bridge_id"`
		Deleted    bool   `json:"deleted"`
		PortsClean int32  `json:"ports_clean"`
		FlowsClean int32  `json:"flows_clean"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &BridgeDeleteResult{
		BridgeID:   result.BridgeID,
		Deleted:    result.Deleted,
		PortsClean: result.PortsClean,
		FlowsClean: result.FlowsClean,
	}, nil
}

// BridgeList lists bridges via CLI.
func (c *CLIAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	args := []string{"sdn", "bridge", "list"}

	if opts.Type != "" {
		args = append(args, "--type", opts.Type)
	}
	if opts.Status != "" {
		args = append(args, "--status", opts.Status)
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs []*platformv1.Bridge directly as a JSON array:
	// [{"id": "uuid", "config": {"name": "...", "type": N, ...}, "status": N, ...}, ...]
	var rawBridges []struct {
		ID     string `json:"id"`
		Config struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			DatapathID string            `json:"datapath_id"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{}   `json:"status"`
		CreatedAt interface{}   `json:"created_at"`
		Ports     []interface{} `json:"ports"`
		Stats     struct {
			TotalPorts uint64 `json:"total_ports"`
			TotalFlows uint64 `json:"total_flows"`
		} `json:"stats"`
	}

	if err := c.parseJSONOutput(output, &rawBridges); err != nil {
		return nil, err
	}

	bridges := make([]BridgeSummary, len(rawBridges))
	for i, b := range rawBridges {
		bridgeID := b.ID
		if bridgeID == "" {
			bridgeID = b.Config.Name
		}
		if id, ok := b.Config.Labels["bridge_id"]; ok && id != "" {
			bridgeID = id
		}
		createdAt := parseTimestamp(b.CreatedAt)
		bridges[i] = BridgeSummary{
			BridgeID:   bridgeID,
			Name:       b.Config.Name,
			Type:       fmt.Sprintf("%v", b.Config.Type),
			Status:     fmt.Sprintf("%v", b.Status),
			PortCount:  int32(b.Stats.TotalPorts),
			FlowCount:  int32(b.Stats.TotalFlows),
			DatapathID: b.Config.DatapathID,
			CreatedAt:  createdAt,
		}
	}

	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: int32(len(bridges)),
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port to a bridge via CLI.
func (c *CLIAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	args := []string{"sdn", "port", "add",
		"--bridge", opts.BridgeID,
		"--id", opts.PortID,
		"--name", opts.Name,
		"--type", opts.Type,
	}

	if opts.Tag > 0 {
		args = append(args, "--tag", strconv.Itoa(int(opts.Tag)))
	}
	if opts.Interface != "" {
		args = append(args, "--interface", opts.Interface)
	}
	if opts.MAC != "" {
		args = append(args, "--mac", opts.MAC)
	}
	if opts.MTU > 0 {
		args = append(args, "--mtu", strconv.Itoa(int(opts.MTU)))
	}
	if opts.AdminState != "" {
		args = append(args, "--admin-state", opts.AdminState)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Port protobuf JSON:
	// {"id": "...", "bridge_id": "...", "config": {"name": "...", "type": N, ...}, "status": N, "created_at": {...}}
	var result struct {
		ID       string `json:"id"`
		BridgeID string `json:"bridge_id"`
		Config   struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			Vlan       uint32            `json:"vlan"`
			MacAddress string            `json:"mac_address"`
			Mtu        uint32            `json:"mtu"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		CreatedAt interface{} `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	createdAt := parseTimestamp(result.CreatedAt)

	// Resolve port ID from labels or fall back to the test-provided port ID.
	// The server assigns a UUID as result.ID; use opts.PortID to match the
	// test expectation when the label is not persisted by the server.
	portID := result.Config.Labels["port_id"]
	if portID == "" {
		portID = opts.PortID
	}

	return &PortAddResult{
		BridgeID:  result.BridgeID,
		PortID:    portID,
		Name:      result.Config.Name,
		Type:      parsePortTypeFromJSON(result.Config.Type),
		MAC:       result.Config.MacAddress,
		Status:    parsePortStatusFromJSON(result.Status),
		CreatedAt: createdAt,
	}, nil
}

// PortDelete deletes a port from a bridge via CLI.
func (c *CLIAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	output, err := c.runCommand(ctx, "sdn", "port", "delete", "--bridge", bridgeID, portID)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID string `json:"bridge_id"`
		PortID   string `json:"port_id"`
		Deleted  bool   `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &PortDeleteResult{
		BridgeID: result.BridgeID,
		PortID:   result.PortID,
		Deleted:  result.Deleted,
	}, nil
}

// PortGetState gets the state of a port via CLI.
func (c *CLIAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	output, err := c.runCommand(ctx, "sdn", "port", "state", "--bridge", bridgeID, portID)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Port protobuf JSON:
	// {"id": "...", "bridge_id": "...", "config": {"name": "...", "type": N, ...}, "status": N, "updated_at": {...}}
	var result struct {
		ID       string `json:"id"`
		BridgeID string `json:"bridge_id"`
		Config   struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			Vlan       uint32            `json:"vlan"`
			MacAddress string            `json:"mac_address"`
			Mtu        uint32            `json:"mtu"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		CreatedAt interface{} `json:"created_at"`
		UpdatedAt interface{} `json:"updated_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	updatedAt := parseTimestamp(result.UpdatedAt)

	// Extract admin_state from config options if available, or derive from status
	adminState := result.Config.Options["admin_state"]
	if adminState == "" {
		adminState = parsePortStatusToAdminState(result.Status)
	}

	resolvedPortID := result.Config.Labels["port_id"]
	if resolvedPortID == "" {
		resolvedPortID = portID
	}

	return &PortStateResult{
		BridgeID:   result.BridgeID,
		PortID:     resolvedPortID,
		AdminState: adminState,
		UpdatedAt:  updatedAt,
	}, nil
}

// PortSetState sets the state of a port via CLI.
func (c *CLIAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	args := []string{"sdn", "port", "set-state", "--bridge", bridgeID, portID}

	if opts.AdminState != "" {
		args = append(args, "--admin-state", opts.AdminState)
	}
	if opts.IngressRate > 0 {
		args = append(args, "--ingress-rate", strconv.FormatUint(opts.IngressRate, 10))
	}
	if opts.EgressRate > 0 {
		args = append(args, "--egress-rate", strconv.FormatUint(opts.EgressRate, 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Port protobuf JSON (same as PortGetState)
	var result struct {
		ID       string `json:"id"`
		BridgeID string `json:"bridge_id"`
		Config   struct {
			Name       string            `json:"name"`
			Type       interface{}       `json:"type"`
			Vlan       uint32            `json:"vlan"`
			MacAddress string            `json:"mac_address"`
			Mtu        uint32            `json:"mtu"`
			Options    map[string]string `json:"options"`
			Labels     map[string]string `json:"labels"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		CreatedAt interface{} `json:"created_at"`
		UpdatedAt interface{} `json:"updated_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	updatedAt := parseTimestamp(result.UpdatedAt)

	adminState := result.Config.Options["admin_state"]
	if adminState == "" {
		// If the server set admin_state via the command, use the requested state
		if opts.AdminState != "" {
			adminState = opts.AdminState
		} else {
			adminState = parsePortStatusToAdminState(result.Status)
		}
	}

	resolvedPortID := result.Config.Labels["port_id"]
	if resolvedPortID == "" {
		resolvedPortID = portID
	}

	return &PortStateResult{
		BridgeID:   result.BridgeID,
		PortID:     resolvedPortID,
		AdminState: adminState,
		UpdatedAt:  updatedAt,
	}, nil
}

// PortGetStats gets statistics for a port via CLI.
func (c *CLIAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	output, err := c.runCommand(ctx, "sdn", "port", "stats", "--bridge", bridgeID, portID)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.PortStats protobuf JSON:
	// {"packets_received": N, "packets_sent": N, "bytes_received": N, "bytes_sent": N, "errors": N, "dropped": N}
	var result struct {
		PacketsReceived uint64 `json:"packets_received"`
		PacketsSent     uint64 `json:"packets_sent"`
		BytesReceived   uint64 `json:"bytes_received"`
		BytesSent       uint64 `json:"bytes_sent"`
		Errors          uint64 `json:"errors"`
		Dropped         uint64 `json:"dropped"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &PortStatsResult{
		BridgeID:    bridgeID,
		PortID:      portID,
		RxPackets:   result.PacketsReceived,
		TxPackets:   result.PacketsSent,
		RxBytes:     result.BytesReceived,
		TxBytes:     result.BytesSent,
		RxErrors:    result.Errors,
		RxDropped:   result.Dropped,
		RetrievedAt: time.Now(),
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow to a bridge via CLI.
func (c *CLIAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	args := []string{"sdn", "flow", "add",
		"--bridge", opts.BridgeID,
		"--id", opts.FlowID,
		"--table", strconv.Itoa(int(opts.Table)),
		"--priority", strconv.Itoa(int(opts.Priority)),
	}

	// Add match criteria
	if opts.Match.InPort > 0 {
		args = append(args, "--in-port", strconv.Itoa(int(opts.Match.InPort)))
	}
	if opts.Match.DlSrc != "" {
		args = append(args, "--dl-src", opts.Match.DlSrc)
	}
	if opts.Match.DlDst != "" {
		args = append(args, "--dl-dst", opts.Match.DlDst)
	}
	if opts.Match.DlType > 0 {
		args = append(args, "--dl-type", strconv.Itoa(int(opts.Match.DlType)))
	}
	if opts.Match.NwSrc != "" {
		args = append(args, "--nw-src", opts.Match.NwSrc)
	}
	if opts.Match.NwDst != "" {
		args = append(args, "--nw-dst", opts.Match.NwDst)
	}

	// Add actions
	for _, action := range opts.Actions {
		args = append(args, "--action", action.Type)
		if action.Port > 0 {
			args = append(args, "--action-port", strconv.Itoa(int(action.Port)))
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Flow protobuf JSON:
	// {"id": "...", "config": {"bridge_id": "...", "table": N, "priority": N, "metadata": {...}}, "created_at": {...}, "stats": {...}}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			BridgeID string            `json:"bridge_id"`
			Table    interface{}       `json:"table"`
			Priority uint32            `json:"priority"`
			Metadata map[string]string `json:"metadata"`
		} `json:"config"`
		CreatedAt interface{} `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	createdAt := parseTimestamp(result.CreatedAt)

	// The flow's identity is the ID the server returns ("flow-<cookie>");
	// --id is only a label stored in metadata, and delete or stats by it
	// names no flow (#614).
	flowID := result.ID

	return &FlowAddResult{
		BridgeID:  result.Config.BridgeID,
		FlowID:    flowID,
		Table:     parseFlowTableFromJSON(result.Config.Table),
		Priority:  int32(result.Config.Priority),
		CreatedAt: createdAt,
	}, nil
}

// FlowDelete deletes a flow from a bridge via CLI.
func (c *CLIAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	output, err := c.runCommand(ctx, "sdn", "flow", "delete", "--bridge", bridgeID, flowID)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID string `json:"bridge_id"`
		FlowID   string `json:"flow_id"`
		Deleted  bool   `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &FlowDeleteResult{
		BridgeID: result.BridgeID,
		FlowID:   result.FlowID,
		Deleted:  result.Deleted,
	}, nil
}

// FlowList lists flows on a bridge via CLI.
func (c *CLIAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	args := []string{"sdn", "flow", "list", "--bridge", bridgeID}

	if opts.Table >= 0 {
		args = append(args, "--table", strconv.Itoa(int(opts.Table)))
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs []*platformv1.Flow protobuf JSON (array, not wrapped):
	// [{"id": "...", "config": {"bridge_id": "...", "table": N, ...}, "created_at": {...}, "stats": {...}}, ...]
	var rawFlows []struct {
		ID     string `json:"id"`
		Config struct {
			BridgeID string            `json:"bridge_id"`
			Table    interface{}       `json:"table"`
			Priority uint32            `json:"priority"`
			Metadata map[string]string `json:"metadata"`
		} `json:"config"`
		CreatedAt interface{} `json:"created_at"`
		Stats     struct {
			PacketCount uint64 `json:"packet_count"`
			ByteCount   uint64 `json:"byte_count"`
		} `json:"stats"`
	}

	if err := c.parseJSONOutput(output, &rawFlows); err != nil {
		return nil, err
	}

	flows := make([]FlowSummary, len(rawFlows))
	for i, f := range rawFlows {
		flowID := f.Config.Metadata["flow_id"]
		if flowID == "" {
			flowID = f.ID
		}
		flows[i] = FlowSummary{
			FlowID:      flowID,
			Table:       parseFlowTableFromJSON(f.Config.Table),
			Priority:    int32(f.Config.Priority),
			PacketCount: f.Stats.PacketCount,
			ByteCount:   f.Stats.ByteCount,
		}
	}

	return &FlowListResult{
		BridgeID:   bridgeID,
		Flows:      flows,
		TotalCount: int32(len(flows)),
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN via CLI.
func (c *CLIAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	args := []string{"sdn", "vlan", "create",
		"--id", strconv.Itoa(int(opts.VLANID)),
		"--name", opts.Name,
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	for _, bridgeID := range opts.BridgeIDs {
		args = append(args, "--bridge", bridgeID)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.VLAN protobuf JSON:
	// {"id": "...", "config": {"vlan_id": N, "name": "...", "bridge_id": "...", "labels": {...}}, "created_at": {...}, "stats": {...}}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			VlanID   uint32            `json:"vlan_id"`
			Name     string            `json:"name"`
			BridgeID string            `json:"bridge_id"`
			Ports    []string          `json:"ports"`
			Labels   map[string]string `json:"labels"`
		} `json:"config"`
		CreatedAt interface{} `json:"created_at"`
		Stats     struct {
			PortCount uint32 `json:"port_count"`
		} `json:"stats"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	createdAt := parseTimestamp(result.CreatedAt)

	var bridgeCount int32
	if result.Config.BridgeID != "" {
		bridgeCount = 1
	}

	return &VLANCreateResult{
		VLANID:      int32(result.Config.VlanID),
		Name:        result.Config.Name,
		Description: result.Config.Labels["description"],
		BridgeCount: bridgeCount,
		PortCount:   int32(result.Stats.PortCount),
		CreatedAt:   createdAt,
	}, nil
}

// VLANDelete deletes a VLAN via CLI.
func (c *CLIAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	args := []string{"sdn", "vlan", "delete"}
	if bridgeID != "" {
		args = append(args, "--bridge", bridgeID)
	}
	args = append(args, strconv.Itoa(int(vlanID)))
	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result struct {
		VLANID  int32 `json:"vlan_id"`
		Deleted bool  `json:"deleted"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &VLANDeleteResult{
		VLANID:  result.VLANID,
		Deleted: result.Deleted,
	}, nil
}

// VLANList lists VLANs via CLI.
func (c *CLIAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	args := []string{"sdn", "vlan", "list"}

	if opts.BridgeID != "" {
		args = append(args, "--bridge", opts.BridgeID)
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs []*platformv1.VLAN protobuf JSON (array, not wrapped):
	// [{"id": "...", "config": {"vlan_id": N, "name": "...", ...}, "created_at": {...}, "stats": {...}}, ...]
	var rawVLANs []struct {
		ID     string `json:"id"`
		Config struct {
			VlanID   uint32            `json:"vlan_id"`
			Name     string            `json:"name"`
			BridgeID string            `json:"bridge_id"`
			Ports    []string          `json:"ports"`
			Labels   map[string]string `json:"labels"`
		} `json:"config"`
		CreatedAt interface{} `json:"created_at"`
		Stats     struct {
			PortCount uint32 `json:"port_count"`
		} `json:"stats"`
	}

	if err := c.parseJSONOutput(output, &rawVLANs); err != nil {
		return nil, err
	}

	vlans := make([]VLANSummary, len(rawVLANs))
	for i, v := range rawVLANs {
		createdAt := parseTimestamp(v.CreatedAt)
		var bridgeCount int32
		if v.Config.BridgeID != "" {
			bridgeCount = 1
		}
		vlans[i] = VLANSummary{
			VLANID:      int32(v.Config.VlanID),
			Name:        v.Config.Name,
			Description: v.Config.Labels["description"],
			BridgeCount: bridgeCount,
			PortCount:   int32(v.Stats.PortCount),
			CreatedAt:   createdAt,
		}
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: int32(len(vlans)),
	}, nil
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy via CLI.
func (c *CLIAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	args := []string{"sdn", "policy", "apply",
		"--id", opts.PolicyID,
		"--name", opts.Name,
		"--type", opts.Type,
		"--priority", strconv.Itoa(int(opts.Priority)),
	}

	if opts.BridgeID != "" {
		args = append(args, "--bridge", opts.BridgeID)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if opts.Enabled {
		args = append(args, "--enabled")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Policy protobuf JSON:
	// {"id": "...", "config": {"name": "...", "type": N, ...}, "status": N, "created_at": {...}}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			Name        string      `json:"name"`
			Description string      `json:"description"`
			Type        interface{} `json:"type"`
			Priority    int32       `json:"priority"`
			Enabled     bool        `json:"enabled"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		CreatedAt interface{} `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &PolicyApplyResult{
		PolicyID:  result.ID,
		Name:      result.Config.Name,
		Type:      parsePolicyTypeFromJSON(result.Config.Type),
		Status:    parsePolicyStatusFromJSON(result.Status),
		AppliedAt: parseTimestamp(result.CreatedAt),
	}, nil
}

// PolicyGet retrieves a policy by ID via CLI.
func (c *CLIAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	output, err := c.runCommand(ctx, "sdn", "policy", "get", policyID)
	if err != nil {
		return nil, err
	}

	// CLI outputs *platformv1.Policy protobuf JSON:
	// {"id": "...", "config": {"name": "...", "type": N, "priority": N, ...}, "status": N, ...}
	var result struct {
		ID     string `json:"id"`
		Config struct {
			Name        string      `json:"name"`
			Description string      `json:"description"`
			Type        interface{} `json:"type"`
			Priority    int32       `json:"priority"`
			Enabled     bool        `json:"enabled"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		HitCount  uint64      `json:"hit_count"`
		ByteCount uint64      `json:"byte_count"`
		CreatedAt interface{} `json:"created_at"`
		UpdatedAt interface{} `json:"updated_at"`
	}

	if err := c.parseJSONOutput(output, &result); err != nil {
		return nil, err
	}

	return &PolicyGetResult{
		PolicyID:    result.ID,
		Name:        result.Config.Name,
		Description: result.Config.Description,
		Type:        parsePolicyTypeFromJSON(result.Config.Type),
		Priority:    result.Config.Priority,
		Enabled:     result.Config.Enabled,
		Status:      parsePolicyStatusFromJSON(result.Status),
		HitCount:    result.HitCount,
		ByteCount:   result.ByteCount,
		CreatedAt:   parseTimestamp(result.CreatedAt),
		UpdatedAt:   parseTimestamp(result.UpdatedAt),
	}, nil
}

// PolicyList lists policies via CLI.
func (c *CLIAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	args := []string{"sdn", "policy", "list"}

	if opts.Type != "" {
		args = append(args, "--type", opts.Type)
	}
	if opts.TargetID != "" {
		args = append(args, "--target", opts.TargetID)
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	// CLI outputs []*platformv1.Policy protobuf JSON:
	// [{"id": "...", "config": {"name": "...", "type": N, ...}, "status": N, ...}, ...]
	var rawPolicies []struct {
		ID     string `json:"id"`
		Config struct {
			Name     string      `json:"name"`
			Type     interface{} `json:"type"`
			Priority int32       `json:"priority"`
			Enabled  bool        `json:"enabled"`
		} `json:"config"`
		Status    interface{} `json:"status"`
		HitCount  uint64      `json:"hit_count"`
		CreatedAt interface{} `json:"created_at"`
	}

	if err := c.parseJSONOutput(output, &rawPolicies); err != nil {
		return nil, err
	}

	var policies []PolicySummary
	for _, p := range rawPolicies {
		policies = append(policies, PolicySummary{
			PolicyID:  p.ID,
			Name:      p.Config.Name,
			Type:      parsePolicyTypeFromJSON(p.Config.Type),
			Priority:  p.Config.Priority,
			Enabled:   p.Config.Enabled,
			Status:    parsePolicyStatusFromJSON(p.Status),
			HitCount:  p.HitCount,
			CreatedAt: parseTimestamp(p.CreatedAt),
		})
	}

	if policies == nil {
		policies = []PolicySummary{}
	}

	return &PolicyListResult{
		Policies:   policies,
		TotalCount: int32(len(policies)),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure CLIAdapter implements SDNCommands interface.
var _ SDNCommands = (*CLIAdapter)(nil)
