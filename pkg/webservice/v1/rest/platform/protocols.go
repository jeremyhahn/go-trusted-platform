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

package platform

import (
	"net/http"
	"strings"
	"time"
)

// GetProtocols handles GET /api/v1/platform/protocols
func (h *PlatformHandlers) GetProtocols(w http.ResponseWriter, r *http.Request) {
	if h.protocolConfig == nil {
		h.respWriter.Error500(w, r, ErrDaemonConfigNotConfigured{})
		return
	}

	// Determine REST server status
	var restStatus string
	if h.restServerRunFn != nil {
		if h.restServerRunFn() {
			restStatus = "running"
		} else {
			restStatus = "stopped"
		}
	} else {
		// If no function provided, assume running since we're handling this request
		restStatus = "running"
	}

	protocols := []ProtocolStatusResponse{
		{
			Name:    "REST",
			Enabled: h.protocolConfig.EnableREST,
			Address: h.protocolConfig.RESTListenAddr,
			Port:    extractPort(h.protocolConfig.RESTListenAddr),
			Status:  restStatus,
			TLS:     h.protocolConfig.RESTTLSEnabled,
		},
		{
			Name:    "gRPC",
			Enabled: h.protocolConfig.EnableGRPCTCP,
			Address: h.protocolConfig.GRPCListenAddr,
			Port:    extractPort(h.protocolConfig.GRPCListenAddr),
			Status:  boolToStatus(h.protocolConfig.EnableGRPCTCP),
			TLS:     h.protocolConfig.GRPCTLSEnabled,
		},
		{
			Name:    "Unix Socket",
			Enabled: true,
			Address: h.protocolConfig.SocketPath,
			Port:    0,
			Status:  "running",
			TLS:     false,
		},
		{
			Name:    "QUIC",
			Enabled: h.protocolConfig.EnableQUIC,
			Address: h.protocolConfig.QUICListenAddr,
			Port:    extractPort(h.protocolConfig.QUICListenAddr),
			Status:  boolToStatus(h.protocolConfig.EnableQUIC),
			TLS:     true, // QUIC always uses TLS
		},
		{
			Name:    "MCP",
			Enabled: h.protocolConfig.EnableMCP,
			Address: h.protocolConfig.MCPHTTPAddr,
			Port:    extractPort(h.protocolConfig.MCPHTTPAddr),
			Status:  boolToStatus(h.protocolConfig.EnableMCP),
			TLS:     false,
		},
	}

	h.respWriter.Success200(w, r, ProtocolsResponse{
		Protocols: protocols,
		Timestamp: time.Now().Unix(),
	})
}

// extractPort extracts the port number from an address string
func extractPort(addr string) int {
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return 0
	}
	port := 0
	for _, c := range parts[len(parts)-1] {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		} else {
			return 0
		}
	}
	return port
}

// boolToStatus converts a boolean enabled flag to status string
func boolToStatus(enabled bool) string {
	if enabled {
		return "running"
	}
	return "stopped"
}
