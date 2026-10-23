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

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements CLICommands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath string
	// configDir holds the platformctl config whose local context points at
	// PLATFORM_UNIX_SOCKET; every command reads it through PLATFORMCTL_CONFIG.
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI protocol adapter instance.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup initializes the CLI adapter by locating the platformctl binary.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	// Check if the binary exists and is executable
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	c.binaryPath = binaryPath

	if err := c.writeConfig(); err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: GetServiceEndpoints().PlatformUnix, Err: err}
	}

	// Verify connectivity by running a simple command
	_, err = c.runCommand(ctx, "version", "--client", "-o", "json")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	return nil
}

// Teardown performs any cleanup needed by the CLI adapter.
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	err := os.RemoveAll(c.configDir)
	c.configDir = ""
	c.configPath = ""
	return err
}

// writeConfig writes a platformctl config whose current context is a local
// context on the daemon socket the runner exports as PLATFORM_UNIX_SOCKET.
// Without it platformctl falls back to /run/platformd.sock.
func (c *CLIAdapter) writeConfig() error {
	dir, err := os.MkdirTemp("", "platformctl-cli-*")
	if err != nil {
		return err
	}
	configPath := filepath.Join(dir, "config.yaml")
	content := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
`, GetServiceEndpoints().PlatformUnix)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	c.configDir = dir
	c.configPath = configPath
	return nil
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	if c.configPath != "" {
		cmd.Env = append(os.Environ(), "PLATFORMCTL_CONFIG="+c.configPath)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("command failed: %s: %w", string(output), err)
	}
	return output, nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via CLI.
func (c *CLIAdapter) Version(ctx context.Context, opts VersionOptions) (*VersionResult, error) {
	args := []string{"version", "-o", "json"}
	if opts.ClientOnly {
		args = append(args, "--client")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "version", Err: err}
	}

	if opts.ClientOnly {
		var resp struct {
			ClientVersion string `json:"client_version"`
		}
		if err := json.Unmarshal(output, &resp); err != nil {
			return nil, ErrCallFailed{Protocol: "CLI", Method: "version", Err: err}
		}
		return &VersionResult{
			ClientVersion: resp.ClientVersion,
		}, nil
	}

	var resp struct {
		Client struct {
			Version string `json:"version"`
		} `json:"client"`
		Server struct {
			Version    string            `json:"version"`
			BuildTime  string            `json:"build_time"`
			GitCommit  string            `json:"git_commit"`
			GoVersion  string            `json:"go_version"`
			Components map[string]string `json:"components"`
		} `json:"server"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "version", Err: err}
	}

	result := &VersionResult{
		ClientVersion: resp.Client.Version,
	}

	if resp.Server.Version != "" {
		result.ServerVersion = &ServerVersionInfo{
			Version:    resp.Server.Version,
			BuildTime:  resp.Server.BuildTime,
			GitCommit:  resp.Server.GitCommit,
			GoVersion:  resp.Server.GoVersion,
			Components: resp.Server.Components,
		}
	}

	return result, nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves platform status via CLI.
func (c *CLIAdapter) Status(ctx context.Context) (*StatusResult, error) {
	output, err := c.runCommand(ctx, "status", "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "status", Err: err}
	}

	var resp struct {
		Status string `json:"status"`
		Info   *struct {
			Hostname   string `json:"hostname"`
			PlatformID string `json:"platform_id"`
			Version    string `json:"version"`
			BuildTime  string `json:"build_time"`
			GitCommit  string `json:"git_commit"`
			FIPSMode   bool   `json:"fips_mode"`
			SystemInfo *struct {
				OS                string `json:"os"`
				Arch              string `json:"arch"`
				KernelVersion     string `json:"kernel_version"`
				NumCPUs           int32  `json:"num_cpus"`
				TotalMemoryMB     int64  `json:"total_memory_mb"`
				AvailableMemoryMB int64  `json:"available_memory_mb"`
				UptimeSeconds     int64  `json:"uptime_seconds"`
			} `json:"system_info"`
			TPMInfo *struct {
				Version         string `json:"version"`
				Manufacturer    string `json:"manufacturer"`
				FirmwareVersion string `json:"firmware_version"`
				IsSimulator     bool   `json:"is_simulator"`
				FIPSMode        bool   `json:"fips_mode"`
			} `json:"tpm_info"`
		} `json:"info"`
		Services []struct {
			Name          string `json:"name"`
			Type          string `json:"type"`
			Status        string `json:"status"`
			Health        string `json:"health"`
			UptimeSeconds int64  `json:"uptime_seconds"`
			Version       string `json:"version"`
		} `json:"services"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "status", Err: err}
	}

	result := &StatusResult{
		SystemStatus: resp.Status,
	}

	if resp.Info != nil {
		result.Info = &PlatformInfo{
			Hostname:   resp.Info.Hostname,
			PlatformID: resp.Info.PlatformID,
			Version:    resp.Info.Version,
			BuildTime:  resp.Info.BuildTime,
			GitCommit:  resp.Info.GitCommit,
			FIPSMode:   resp.Info.FIPSMode,
		}

		if resp.Info.SystemInfo != nil {
			result.Info.SystemInfo = &SystemInfo{
				OS:                resp.Info.SystemInfo.OS,
				Arch:              resp.Info.SystemInfo.Arch,
				KernelVersion:     resp.Info.SystemInfo.KernelVersion,
				NumCPUs:           resp.Info.SystemInfo.NumCPUs,
				TotalMemoryMB:     resp.Info.SystemInfo.TotalMemoryMB,
				AvailableMemoryMB: resp.Info.SystemInfo.AvailableMemoryMB,
				UptimeSeconds:     resp.Info.SystemInfo.UptimeSeconds,
			}
		}

		if resp.Info.TPMInfo != nil {
			result.Info.TPMInfo = &TPMInfo{
				Version:         resp.Info.TPMInfo.Version,
				Manufacturer:    resp.Info.TPMInfo.Manufacturer,
				FirmwareVersion: resp.Info.TPMInfo.FirmwareVersion,
				IsSimulator:     resp.Info.TPMInfo.IsSimulator,
				FIPSMode:        resp.Info.TPMInfo.FIPSMode,
			}
		}
	}

	for _, svc := range resp.Services {
		result.Services = append(result.Services, ServiceInfo{
			Name:          svc.Name,
			Type:          svc.Type,
			Status:        svc.Status,
			Health:        svc.Health,
			UptimeSeconds: svc.UptimeSeconds,
			Version:       svc.Version,
		})
	}

	return result, nil
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via CLI.
func (c *CLIAdapter) Health(ctx context.Context, opts HealthOptions) (*HealthResult, error) {
	args := []string{"health", "-o", "json"}
	if opts.Detailed {
		args = append(args, "--detailed")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "health", Err: err}
	}

	var resp struct {
		Status     string `json:"status"`
		Components []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"components"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "health", Err: err}
	}

	result := &HealthResult{
		Status: resp.Status,
	}

	for _, comp := range resp.Components {
		result.Components = append(result.Components, ComponentHealth{
			Name:    comp.Name,
			Status:  comp.Status,
			Message: comp.Message,
		})
	}

	return result, nil
}

// =============================================================================
// Config Operations
// =============================================================================

// ConfigGet retrieves configuration via CLI.
func (c *CLIAdapter) ConfigGet(ctx context.Context, section string) (*ConfigGetResult, error) {
	args := []string{"config", "get", "-o", "json"}
	if section != "" {
		args = append(args, section)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "config get", Err: err}
	}

	// config get -o json prints a bare array of sections (docs/daemon/cli.md §4.5).
	var sections []struct {
		Section string            `json:"section"`
		Values  map[string]string `json:"values"`
	}

	if err := json.Unmarshal(output, &sections); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "config get", Err: err}
	}

	result := &ConfigGetResult{}
	for _, sec := range sections {
		result.Sections = append(result.Sections, ConfigSection{
			Section: sec.Section,
			Values:  sec.Values,
		})
	}

	return result, nil
}

// ConfigSet sets configuration values via CLI.
func (c *CLIAdapter) ConfigSet(ctx context.Context, section string, values map[string]string, persist bool) (*ConfigSetResult, error) {
	args := []string{"config", "set", section}

	for k, v := range values {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}

	if persist {
		args = append(args, "--persist")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "config set", Err: err}
	}

	// Config set returns success message in table format, check for success indicators
	outputStr := string(output)
	success := strings.Contains(outputStr, "successfully") || strings.Contains(outputStr, "Success")

	return &ConfigSetResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// ConfigReload reloads configuration via CLI.
func (c *CLIAdapter) ConfigReload(ctx context.Context) (*ConfigReloadResult, error) {
	output, err := c.runCommand(ctx, "config", "reload")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "config reload", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "successfully") || strings.Contains(outputStr, "Success")

	return &ConfigReloadResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// =============================================================================
// Context Operations
// =============================================================================

// ContextList lists all contexts via CLI.
func (c *CLIAdapter) ContextList(ctx context.Context) (*ContextListResult, error) {
	output, err := c.runCommand(ctx, "context", "list")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "context list", Err: err}
	}

	// context list prints a table, columns CURRENT NAME TYPE PROTOCOL TARGET
	// (docs/daemon/cli.md §4.6).
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	result := &ContextListResult{}

	// Skip header line
	for i, line := range lines {
		if i == 0 {
			continue // Skip header
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			info := ContextInfo{}
			offset := 0

			// Check if first field is the current marker
			if fields[0] == "*" {
				result.CurrentContext = fields[1]
				offset = 1
			}

			if len(fields) > offset {
				info.Name = fields[offset]
			}
			if len(fields) > offset+1 {
				info.Type = fields[offset+1]
			}
			if len(fields) > offset+3 {
				info.Target = fields[offset+3]
			}

			result.Contexts = append(result.Contexts, info)
		}
	}

	return result, nil
}

// ContextCurrent retrieves the current context via CLI.
func (c *CLIAdapter) ContextCurrent(ctx context.Context) (*ContextCurrentResult, error) {
	output, err := c.runCommand(ctx, "context", "current")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "context current", Err: err}
	}

	// Parse key-value output
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	result := &ContextCurrentResult{}

	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "Name":
				result.Name = value
			case "Type":
				result.Type = value
			case "Socket Path":
				result.SocketPath = value
			case "Server":
				result.Server = value
			case "CA Certificate":
				result.CACert = value
			case "Client Certificate":
				result.ClientCert = value
			}
		}
	}

	return result, nil
}

// ContextUse switches to a context via CLI.
func (c *CLIAdapter) ContextUse(ctx context.Context, name string) (*ContextUseResult, error) {
	output, err := c.runCommand(ctx, "context", "use", name)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "context use", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "Switched") || strings.Contains(outputStr, "Success")

	return &ContextUseResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// ContextAdd adds a new context via CLI.
func (c *CLIAdapter) ContextAdd(ctx context.Context, opts ContextAddOptions) (*ContextAddResult, error) {
	args := []string{"context", "add", opts.Name, "--type", opts.Type}

	if opts.Type == "local" && opts.SocketPath != "" {
		args = append(args, "--socket-path", opts.SocketPath)
	}

	if opts.Type == "remote" {
		if opts.Server != "" {
			args = append(args, "--server", opts.Server)
		}
		if opts.CACert != "" {
			args = append(args, "--ca-cert", opts.CACert)
		}
		if opts.ClientCert != "" {
			args = append(args, "--client-cert", opts.ClientCert)
		}
		if opts.ClientKey != "" {
			args = append(args, "--client-key", opts.ClientKey)
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "context add", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "added") || strings.Contains(outputStr, "Success")

	return &ContextAddResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// ContextDelete deletes a context via CLI.
func (c *CLIAdapter) ContextDelete(ctx context.Context, name string) (*ContextDeleteResult, error) {
	output, err := c.runCommand(ctx, "context", "delete", name)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "context delete", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "deleted") || strings.Contains(outputStr, "Success")

	return &ContextDeleteResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ServiceList lists all services via CLI.
func (c *CLIAdapter) ServiceList(ctx context.Context) (*ServiceListResult, error) {
	output, err := c.runCommand(ctx, "service", "list", "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service list", Err: err}
	}

	// service list -o json prints a bare array of services (docs/daemon/cli.md §4.4).
	var services []struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		Status        string `json:"status"`
		Health        string `json:"health"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Version       string `json:"version"`
	}

	if err := json.Unmarshal(output, &services); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service list", Err: err}
	}

	result := &ServiceListResult{}
	for _, svc := range services {
		result.Services = append(result.Services, ServiceInfo{
			Name:          svc.Name,
			Type:          svc.Type,
			Status:        svc.Status,
			Health:        svc.Health,
			UptimeSeconds: svc.UptimeSeconds,
			Version:       svc.Version,
		})
	}

	return result, nil
}

// ServiceStatus retrieves service status via CLI.
func (c *CLIAdapter) ServiceStatus(ctx context.Context, serviceType string) (*ServiceStatusResult, error) {
	output, err := c.runCommand(ctx, "service", "status", serviceType, "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service status", Err: err}
	}
	return parseServiceStatusJSON(output)
}

// parseServiceStatusJSON decodes `service status -o json`, which prints the
// service as a bare object with no wrapping key (docs/daemon/cli.md §4.4).
func parseServiceStatusJSON(output []byte) (*ServiceStatusResult, error) {
	var svc *struct {
		Name          string `json:"name"`
		Type          string `json:"type"`
		Status        string `json:"status"`
		Health        string `json:"health"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		Version       string `json:"version"`
	}

	if err := json.Unmarshal(output, &svc); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service status", Err: err}
	}

	result := &ServiceStatusResult{}
	if svc != nil {
		result.Service = &ServiceInfo{
			Name:          svc.Name,
			Type:          svc.Type,
			Status:        svc.Status,
			Health:        svc.Health,
			UptimeSeconds: svc.UptimeSeconds,
			Version:       svc.Version,
		}
	}

	return result, nil
}

// ServiceStart starts a service via CLI.
func (c *CLIAdapter) ServiceStart(ctx context.Context, serviceType string) (*ServiceStartResult, error) {
	output, err := c.runCommand(ctx, "service", "start", serviceType)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service start", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "started") || strings.Contains(outputStr, "Success")

	return &ServiceStartResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// ServiceStop stops a service via CLI.
func (c *CLIAdapter) ServiceStop(ctx context.Context, serviceType string, opts ServiceStopOptions) (*ServiceStopResult, error) {
	args := []string{"service", "stop", serviceType}

	if opts.Force {
		args = append(args, "--force")
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", opts.Timeout))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service stop", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "stopped") || strings.Contains(outputStr, "Success")

	return &ServiceStopResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// ServiceRestart restarts a service via CLI.
func (c *CLIAdapter) ServiceRestart(ctx context.Context, serviceType string, timeout uint32) (*ServiceRestartResult, error) {
	args := []string{"service", "restart", serviceType}

	if timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", timeout))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "service restart", Err: err}
	}

	outputStr := string(output)
	success := strings.Contains(outputStr, "restarted") || strings.Contains(outputStr, "Success")

	return &ServiceRestartResult{
		Success: success,
		Message: outputStr,
	}, nil
}

// =============================================================================
// Completion Operations
// =============================================================================

// Completion generates shell completion scripts via CLI.
func (c *CLIAdapter) Completion(ctx context.Context, shell string) (*CompletionResult, error) {
	output, err := c.runCommand(ctx, "completion", shell)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "completion", Err: err}
	}

	return &CompletionResult{
		Script: string(output),
	}, nil
}

// Ensure CLIAdapter implements CLICommands interface.
var _ CLICommands = (*CLIAdapter)(nil)
