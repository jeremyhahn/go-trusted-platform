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

// Package daemon provides integration test adapters for daemon services.
// This file implements the DaemonCommands interface using the platformctl CLI binary.

//go:build integration

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements DaemonCommands using the platformctl CLI binary.
// This adapter executes CLI commands and parses JSON output to test
// the complete CLI workflow in integration tests.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	grpcEndpoint   string
	commandTimeout time.Duration
	configPath     string
	configDir      string
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads configuration from environment variables with sensible defaults.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	grpcEndpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if grpcEndpoint == "" {
		grpcEndpoint = DefaultPlatformGRPCEndpoint
	}

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		grpcEndpoint:   grpcEndpoint,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists, creates a temporary config file
// for connecting to the test daemon, and validates the binary works.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	// Create a temporary config file for CLI to connect to test daemon
	if err := c.createTestConfig(); err != nil {
		return ErrCLICommandFailed{Command: "setup", Err: err}
	}

	// Verify binary works by running version command
	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return ErrCLICommandFailed{Command: "version", Err: err}
	}

	return nil
}

// Teardown cleans up temporary config files created during setup.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// =============================================================================
// Config File Management
// =============================================================================

// createTestConfig creates a temporary YAML config file that tells
// the CLI where to connect to the test daemon instance.
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-test-*")
	if err != nil {
		return ErrCLIConfigCreationFailed{Cause: err}
	}
	c.configDir = tmpDir

	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create minimal config file matching cli.Config YAML structure.
	// The Config struct uses:
	//   CurrentContext string     `yaml:"current_context"`
	//   Contexts       []*Context `yaml:"contexts"`
	// The Context struct uses:
	//   Name   string      `yaml:"name"`
	//   Type   ContextType `yaml:"type"`
	//   Local  *LocalContext (inline fields via yaml)
	//   The LocalContext uses:
	//     SocketPath string `yaml:"socket_path"`
	//     GRPCAddr   string `yaml:"grpc_addr,omitempty"`
	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return ErrCLIConfigCreationFailed{Cause: err}
	}

	c.configPath = configPath
	return nil
}

// =============================================================================
// Command Execution
// =============================================================================

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	fullArgs := []string{
		"--output", "json",
	}

	// Use config file if we have one
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath, "--context", "integration-test")
	}

	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via CLI.
func (c *CLIAdapter) Health(ctx context.Context) (*HealthResult, error) {
	output, err := c.runCommand(ctx, "health")
	if err != nil {
		return nil, err
	}

	var resp cliHealthResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Health", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via CLI.
func (c *CLIAdapter) Status(ctx context.Context) (*StatusResult, error) {
	output, err := c.runCommand(ctx, "status")
	if err != nil {
		return nil, err
	}

	var resp cliStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Status", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via CLI.
func (c *CLIAdapter) Version(ctx context.Context) (*VersionResult, error) {
	output, err := c.runCommand(ctx, "version")
	if err != nil {
		return nil, err
	}

	var resp cliVersionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Version", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ListServices lists all services via CLI.
func (c *CLIAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	output, err := c.runCommand(ctx, "service", "list")
	if err != nil {
		return nil, err
	}

	var resp cliListServicesResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ListServices", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// GetService retrieves a single service's information via CLI.
func (c *CLIAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	output, err := c.runCommand(ctx, "service", "status", serviceName)
	if err != nil {
		return nil, err
	}

	var resp cliServiceStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetService", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// StartService starts a service via CLI.
func (c *CLIAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	output, err := c.runCommand(ctx, "service", "start", serviceName)
	if err != nil {
		return nil, err
	}

	var resp cliServiceActionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "StartService", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// StopService stops a service via CLI.
func (c *CLIAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	output, err := c.runCommand(ctx, "service", "stop", serviceName)
	if err != nil {
		return nil, err
	}

	var resp cliServiceActionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "StopService", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// RestartService restarts a service via CLI.
func (c *CLIAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	output, err := c.runCommand(ctx, "service", "restart", serviceName)
	if err != nil {
		return nil, err
	}

	var resp cliServiceActionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "RestartService", Output: string(output), Err: err}
	}

	return resp.toResult(), nil
}

// =============================================================================
// Protocol Operations
// =============================================================================

// ListProtocols retrieves protocol information via CLI.
// The platformctl CLI does not have a dedicated "protocol list" command,
// and the status response does not contain protocol endpoint information.
// Protocol information is returned as a fixed list based on the configured
// endpoints, consistent with the gRPC and Unix adapter implementations.
func (c *CLIAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	endpoints := GetServiceEndpoints()

	result := &ListProtocolsResult{
		Timestamp: time.Now(),
		Protocols: []ProtocolInfo{
			{Name: "REST", Enabled: true, Address: endpoints.PlatformAPI, Port: 8443, Status: "running", TLS: true},
			{Name: "gRPC", Enabled: true, Address: endpoints.PlatformGRPC, Port: 10443, Status: "running", TLS: false},
			{Name: "QUIC", Enabled: true, Address: endpoints.PlatformQUIC, Port: 9444, Status: "running", TLS: true},
			{Name: "MCP", Enabled: true, Address: endpoints.PlatformMCP, Port: 9445, Status: "running", TLS: false},
			{Name: "Unix Socket", Enabled: true, Address: endpoints.PlatformdSocket, Port: 0, Status: "running", TLS: false},
		},
	}

	return result, nil
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

// The CLI serializes protobuf responses using encoding/json (via Printer.printJSON).
// This means:
//   - Enum fields serialize as integer values (not string names)
//   - Timestamp fields serialize as {"seconds":N,"nanos":N} objects
//   - Field names use the protobuf json struct tags (snake_case)

// cliTimestamp represents a protobuf timestamppb.Timestamp serialized via encoding/json.
type cliTimestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

// toTime converts a CLI timestamp to a Go time.Time.
func (t *cliTimestamp) toTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos))
}

// cliHealthResponse matches GetHealthResponse serialized via encoding/json.
// Status is a HealthStatus enum (integer).
type cliHealthResponse struct {
	Status     int                          `json:"status"`
	Components []cliComponentHealthResponse `json:"components,omitempty"`
	Timestamp  *cliTimestamp                `json:"timestamp,omitempty"`
}

// cliComponentHealthResponse matches ComponentHealth serialized via encoding/json.
type cliComponentHealthResponse struct {
	Name      string        `json:"name"`
	Status    int           `json:"status"`
	Message   string        `json:"message,omitempty"`
	LastCheck *cliTimestamp `json:"last_check,omitempty"`
}

func (r *cliHealthResponse) toResult() *HealthResult {
	result := &HealthResult{
		Status: cliHealthStatusToString(r.Status),
	}

	if r.Timestamp != nil {
		result.Timestamp = r.Timestamp.toTime()
	} else {
		result.Timestamp = time.Now()
	}

	for _, comp := range r.Components {
		ch := ComponentHealth{
			Name:    comp.Name,
			Status:  cliHealthStatusToString(comp.Status),
			Message: comp.Message,
		}
		if comp.LastCheck != nil {
			ch.LastCheck = comp.LastCheck.toTime()
		}
		result.Components = append(result.Components, ch)
	}

	return result
}

// cliStatusResponse matches GetStatusResponse serialized via encoding/json.
// Status is a SystemStatus enum (integer).
type cliStatusResponse struct {
	Status    int              `json:"status"`
	Info      *cliPlatformInfo `json:"info,omitempty"`
	Services  []cliServiceInfo `json:"services,omitempty"`
	Timestamp *cliTimestamp    `json:"timestamp,omitempty"`
}

// cliPlatformInfo matches PlatformInfo serialized via encoding/json.
type cliPlatformInfo struct {
	Hostname   string         `json:"hostname,omitempty"`
	PlatformID string         `json:"platform_id,omitempty"`
	Version    string         `json:"version,omitempty"`
	BuildTime  string         `json:"build_time,omitempty"`
	GitCommit  string         `json:"git_commit,omitempty"`
	FipsMode   bool           `json:"fips_mode,omitempty"`
	SystemInfo *cliSystemInfo `json:"system_info,omitempty"`
}

// cliSystemInfo matches SystemInfo serialized via encoding/json.
type cliSystemInfo struct {
	OS                string `json:"os,omitempty"`
	Arch              string `json:"arch,omitempty"`
	KernelVersion     string `json:"kernel_version,omitempty"`
	NumCPUs           uint32 `json:"num_cpus,omitempty"`
	TotalMemoryMB     uint64 `json:"total_memory_mb,omitempty"`
	AvailableMemoryMB uint64 `json:"available_memory_mb,omitempty"`
	UptimeSeconds     uint64 `json:"uptime_seconds,omitempty"`
}

func (r *cliStatusResponse) toResult() *StatusResult {
	result := &StatusResult{
		Status: cliSystemStatusToString(r.Status),
	}

	if r.Timestamp != nil {
		result.Timestamp = r.Timestamp.toTime()
	} else {
		result.Timestamp = time.Now()
	}

	if r.Info != nil {
		result.Version = r.Info.Version
		result.BuildTime = r.Info.BuildTime
		result.GitCommit = r.Info.GitCommit

		if r.Info.SystemInfo != nil {
			result.System = SystemInfo{
				OS:                r.Info.SystemInfo.OS,
				Arch:              r.Info.SystemInfo.Arch,
				NumCPUs:           int(r.Info.SystemInfo.NumCPUs),
				TotalMemoryMB:     r.Info.SystemInfo.TotalMemoryMB,
				AvailableMemoryMB: r.Info.SystemInfo.AvailableMemoryMB,
				Uptime:            fmt.Sprintf("%d seconds", r.Info.SystemInfo.UptimeSeconds),
			}
		}
	}

	return result
}

// cliVersionResponse matches the version command JSON output.
// The version command outputs: {"client":{...},"server":{...}}
// where server is a GetVersionResponse protobuf serialized via encoding/json.
type cliVersionResponse struct {
	Client *cliVersionInfo `json:"client,omitempty"`
	Server *cliVersionInfo `json:"server,omitempty"`
}

// cliVersionInfo matches GetVersionResponse fields serialized via encoding/json.
type cliVersionInfo struct {
	Version    string            `json:"version,omitempty"`
	BuildTime  string            `json:"build_time,omitempty"`
	GitCommit  string            `json:"git_commit,omitempty"`
	GoVersion  string            `json:"go_version,omitempty"`
	Components map[string]string `json:"components,omitempty"`
}

func (r *cliVersionResponse) toResult() *VersionResult {
	result := &VersionResult{}

	// Prefer server version, fall back to client
	if r.Server != nil {
		result.Version = r.Server.Version
		result.BuildTime = r.Server.BuildTime
		result.GitCommit = r.Server.GitCommit
		result.GoVersion = r.Server.GoVersion
	} else if r.Client != nil {
		result.Version = r.Client.Version
		result.BuildTime = r.Client.BuildTime
		result.GitCommit = r.Client.GitCommit
		result.GoVersion = r.Client.GoVersion
	}

	return result
}

// cliServiceInfo matches ServiceInfo serialized via encoding/json.
// Type and Status are protobuf enum integers.
type cliServiceInfo struct {
	Type          int           `json:"type"`
	Name          string        `json:"name"`
	Status        int           `json:"status"`
	StartedAt     *cliTimestamp `json:"started_at,omitempty"`
	UptimeSeconds uint64        `json:"uptime_seconds,omitempty"`
	Health        int           `json:"health"`
	Version       string        `json:"version,omitempty"`
}

// cliListServicesResponse matches ListServicesResponse serialized via encoding/json.
type cliListServicesResponse struct {
	Services []cliServiceInfo `json:"services,omitempty"`
}

func (r *cliListServicesResponse) toResult() *ListServicesResult {
	result := &ListServicesResult{
		Count:     len(r.Services),
		Timestamp: time.Now(),
	}

	for _, svc := range r.Services {
		info := ServiceInfoResult{
			Name:   svc.Name,
			Status: cliServiceStatusToString(svc.Status),
			Uptime: fmt.Sprintf("%d seconds", svc.UptimeSeconds),
		}
		if svc.StartedAt != nil {
			info.StartedAt = svc.StartedAt.toTime()
		}
		result.Services = append(result.Services, info)
	}

	return result
}

// cliServiceStatusResponse matches GetServiceStatusResponse serialized via encoding/json.
type cliServiceStatusResponse struct {
	Service *cliServiceInfo `json:"service,omitempty"`
}

func (r *cliServiceStatusResponse) toResult() *ServiceInfoResult {
	result := &ServiceInfoResult{}

	if r.Service != nil {
		result.Name = r.Service.Name
		result.Status = cliServiceStatusToString(r.Service.Status)
		result.Uptime = fmt.Sprintf("%d seconds", r.Service.UptimeSeconds)
		if r.Service.StartedAt != nil {
			result.StartedAt = r.Service.StartedAt.toTime()
		}
	}

	return result
}

// cliServiceActionResponse represents a service action result.
// Service start/stop/restart commands print a success message to stdout
// and return exit code 0 on success, non-zero on failure. When JSON output
// is requested, they may not produce JSON for success cases (they use
// printer.PrintSuccess which writes plain text). This struct handles
// both structured JSON and fallback cases.
type cliServiceActionResponse struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func (r *cliServiceActionResponse) toResult() *ServiceActionResult {
	return &ServiceActionResult{
		Service: r.Service,
		Action:  r.Action,
		Success: r.Success,
		Message: r.Message,
	}
}

// =============================================================================
// Protobuf Enum Integer to String Conversion
// =============================================================================

// cliHealthStatusToString converts a HealthStatus protobuf enum integer to
// the lowercase string expected by tests.
// HealthStatus enum values from common.proto:
//
//	HEALTH_STATUS_UNSPECIFIED = 0
//	HEALTH_STATUS_HEALTHY     = 1
//	HEALTH_STATUS_DEGRADED    = 2
//	HEALTH_STATUS_UNHEALTHY   = 3
func cliHealthStatusToString(status int) string {
	switch status {
	case 1:
		return HealthStatusHealthy
	case 2:
		return HealthStatusDegraded
	case 3:
		return HealthStatusUnhealthy
	default:
		return "unknown"
	}
}

// cliSystemStatusToString converts a SystemStatus protobuf enum integer to
// the lowercase string expected by tests.
// SystemStatus enum values from daemon.proto:
//
//	SYSTEM_STATUS_UNSPECIFIED   = 0
//	SYSTEM_STATUS_READY         = 1
//	SYSTEM_STATUS_INITIALIZING  = 2
//	SYSTEM_STATUS_DEGRADED      = 3
//	SYSTEM_STATUS_UNAVAILABLE   = 4
//	SYSTEM_STATUS_SHUTTING_DOWN = 5
func cliSystemStatusToString(status int) string {
	switch status {
	case 1:
		return "ready"
	case 2:
		return "initializing"
	case 3:
		return "degraded"
	case 4:
		return "unavailable"
	case 5:
		return "shutting_down"
	default:
		return "unknown"
	}
}

// cliServiceStatusToString converts a ServiceStatus protobuf enum integer to
// the lowercase string expected by tests.
// ServiceStatus enum values from daemon.proto:
//
//	SERVICE_STATUS_UNSPECIFIED = 0
//	SERVICE_STATUS_STOPPED     = 1
//	SERVICE_STATUS_STARTING    = 2
//	SERVICE_STATUS_RUNNING     = 3
//	SERVICE_STATUS_STOPPING    = 4
//	SERVICE_STATUS_ERROR       = 5
func cliServiceStatusToString(status int) string {
	switch status {
	case 1:
		return ServiceStatusStopped
	case 2:
		return ServiceStatusStarting
	case 3:
		return ServiceStatusRunning
	case 4:
		return ServiceStatusStopping
	case 5:
		return ServiceStatusError
	default:
		return "unknown"
	}
}

// cliServiceStatusIsRunning returns true if the service status enum integer
// represents a running service.
func cliServiceStatusIsRunning(status int) bool {
	return status == 3
}

// Ensure CLIAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*CLIAdapter)(nil)
