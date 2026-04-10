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

package daemon

import (
	"fmt"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// mcpHealthStatusString converts a protobuf HealthStatus enum to the lowercase
// string expected by MCP tool consumers (e.g., "healthy", "degraded", "unhealthy").
func mcpHealthStatusString(s platformv1.HealthStatus) string {
	raw := s.String()
	return strings.ToLower(strings.TrimPrefix(raw, "HEALTH_STATUS_"))
}

// mcpSystemStatusString converts a protobuf SystemStatus enum to the lowercase
// string expected by MCP tool consumers (e.g., "ready", "initializing").
func mcpSystemStatusString(s platformv1.SystemStatus) string {
	raw := s.String()
	return strings.ToLower(strings.TrimPrefix(raw, "SYSTEM_STATUS_"))
}

// mcpServiceStatusString converts a protobuf ServiceStatus enum to the lowercase
// string expected by MCP tool consumers (e.g., "running", "stopped", "error").
func mcpServiceStatusString(s platformv1.ServiceStatus) string {
	raw := s.String()
	return strings.ToLower(strings.TrimPrefix(raw, "SERVICE_STATUS_"))
}

// mcpTimestampMillis converts a time.Time to Unix milliseconds for MCP JSON responses.
func mcpTimestampMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// mcpHealthResponseMap converts a GetHealthResponse proto to an MCP-compatible map
// with lowercase string status values and Unix millisecond timestamps.
func mcpHealthResponseMap(resp *platformv1.GetHealthResponse) map[string]interface{} {
	components := make([]map[string]interface{}, 0, len(resp.GetComponents()))
	for _, c := range resp.GetComponents() {
		comp := map[string]interface{}{
			"name":      c.GetName(),
			"status":    mcpHealthStatusString(c.GetStatus()),
			"message":   c.GetMessage(),
			"lastCheck": mcpTimestampMillis(c.GetLastCheck().AsTime()),
		}
		components = append(components, comp)
	}

	return map[string]interface{}{
		"status":     mcpHealthStatusString(resp.GetStatus()),
		"components": components,
		"timestamp":  mcpTimestampMillis(resp.GetTimestamp().AsTime()),
	}
}

// mcpStatusResponseMap converts a GetStatusResponse proto to an MCP-compatible map.
func mcpStatusResponseMap(resp *platformv1.GetStatusResponse) map[string]interface{} {
	info := resp.GetInfo()
	sysInfo := info.GetSystemInfo()

	uptimeStr := formatUptimeDuration(time.Duration(sysInfo.GetUptimeSeconds()) * time.Second)

	system := map[string]interface{}{
		"os":                sysInfo.GetOs(),
		"arch":              sysInfo.GetArch(),
		"numCpus":           int(sysInfo.GetNumCpus()),
		"totalMemoryMb":     sysInfo.GetTotalMemoryMb(),
		"availableMemoryMb": sysInfo.GetAvailableMemoryMb(),
		"uptime":            uptimeStr,
	}

	return map[string]interface{}{
		"status":    mcpSystemStatusString(resp.GetStatus()),
		"version":   info.GetVersion(),
		"buildTime": info.GetBuildTime(),
		"gitCommit": info.GetGitCommit(),
		"goVersion": "", // populated by caller if available
		"system":    system,
		"timestamp": mcpTimestampMillis(resp.GetTimestamp().AsTime()),
	}
}

// mcpVersionResponseMap converts a GetVersionResponse proto to an MCP-compatible map.
func mcpVersionResponseMap(resp *platformv1.GetVersionResponse) map[string]interface{} {
	return map[string]interface{}{
		"version":   resp.GetVersion(),
		"buildTime": resp.GetBuildTime(),
		"gitCommit": resp.GetGitCommit(),
		"goVersion": resp.GetGoVersion(),
	}
}

// mcpServiceInfoMap converts a ServiceInfo proto to an MCP-compatible map.
func mcpServiceInfoMap(info *platformv1.ServiceInfo) map[string]interface{} {
	result := map[string]interface{}{
		"name":       info.GetName(),
		"status":     mcpServiceStatusString(info.GetStatus()),
		"startCount": parseUint64FromMetadata(info.GetMetadata(), "start_count"),
		"stopCount":  parseUint64FromMetadata(info.GetMetadata(), "stop_count"),
	}

	if info.GetStartedAt() != nil {
		result["startedAt"] = mcpTimestampMillis(info.GetStartedAt().AsTime())
	}

	if info.GetUptimeSeconds() > 0 {
		result["uptime"] = formatUptimeDuration(time.Duration(info.GetUptimeSeconds()) * time.Second)
	}

	if lastErr, ok := info.GetMetadata()["last_error"]; ok && lastErr != "" {
		result["lastError"] = lastErr
	}

	return result
}

// mcpListServicesResponseMap converts a ListServicesResponse proto to an MCP-compatible map.
func mcpListServicesResponseMap(resp *platformv1.ListServicesResponse) map[string]interface{} {
	services := make([]map[string]interface{}, 0, len(resp.GetServices()))
	for _, s := range resp.GetServices() {
		services = append(services, mcpServiceInfoMap(s))
	}

	return map[string]interface{}{
		"services":  services,
		"count":     len(resp.GetServices()),
		"timestamp": mcpTimestampMillis(time.Now()),
	}
}

// mcpServiceActionMap creates an MCP-compatible service action response map.
func mcpServiceActionMap(serviceName string, action string, success bool, message string) map[string]interface{} {
	return map[string]interface{}{
		"service": serviceName,
		"action":  action,
		"success": success,
		"message": message,
	}
}

// mcpListProtocolsMap creates an MCP-compatible protocol list response map
// from the daemon service configuration.
func mcpListProtocolsMap(config *Config) map[string]interface{} {
	protocols := make([]map[string]interface{}, 0, 5)

	if config.EnableREST {
		protocols = append(protocols, map[string]interface{}{
			"name":    "REST",
			"enabled": true,
			"address": config.RESTListenAddr,
			"port":    extractPort(config.RESTListenAddr),
			"status":  "active",
			"tls":     config.RESTTLSCertFile != "",
		})
	}

	if config.EnableGRPCTCP {
		protocols = append(protocols, map[string]interface{}{
			"name":    "gRPC",
			"enabled": true,
			"address": config.GRPCListenAddr,
			"port":    extractPort(config.GRPCListenAddr),
			"status":  "active",
			"tls":     config.GRPCTLSCertFile != "",
		})
	}

	if config.EnableQUIC {
		protocols = append(protocols, map[string]interface{}{
			"name":    "QUIC",
			"enabled": true,
			"address": config.QUICListenAddr,
			"port":    extractPort(config.QUICListenAddr),
			"status":  "active",
			"tls":     true,
		})
	}

	if config.EnableMCP {
		mcpAddr := ""
		mcpPort := 0
		if config.MCPConfig != nil {
			mcpAddr = config.MCPConfig.HTTPAddr
			mcpPort = extractPort(config.MCPConfig.HTTPAddr)
		}
		protocols = append(protocols, map[string]interface{}{
			"name":    "MCP",
			"enabled": true,
			"address": mcpAddr,
			"port":    mcpPort,
			"status":  "active",
			"tls":     false,
		})
	}

	if config.EnableGRPCUDS {
		protocols = append(protocols, map[string]interface{}{
			"name":    "Unix Socket",
			"enabled": true,
			"address": config.GRPCSocketPath,
			"port":    0,
			"status":  "active",
			"tls":     false,
		})
	}

	return map[string]interface{}{
		"protocols": protocols,
		"timestamp": mcpTimestampMillis(time.Now()),
	}
}

// formatUptimeDuration converts a time.Duration to a human-readable uptime string.
func formatUptimeDuration(d time.Duration) string {
	totalSeconds := int(d.Seconds())
	hours := totalSeconds / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// parseUint64FromMetadata parses a uint64 value from service metadata.
func parseUint64FromMetadata(metadata map[string]string, key string) uint64 {
	val, ok := metadata[key]
	if !ok {
		return 0
	}
	var result uint64
	for _, c := range val {
		if c < '0' || c > '9' {
			return 0
		}
		result = result*10 + uint64(c-'0')
	}
	return result
}
