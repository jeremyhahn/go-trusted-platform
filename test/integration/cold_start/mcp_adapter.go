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

package cold_start

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// MCPAdapter drives cold-start auth operations via the MCP JSON-RPC
// surface. The /healthz endpoint reuses the same plain-HTTP MCP listener
// the daemon binds in init-only mode, so this adapter can observe state
// transitions even when the JSON-RPC tool surface is not yet wired.
type MCPAdapter struct {
	endpoint string
	client   *http.Client
}

// NewMCPAdapter returns a fresh MCP adapter.
func NewMCPAdapter() *MCPAdapter { return &MCPAdapter{} }

// Name returns "MCP".
func (m *MCPAdapter) Name() string { return "MCP" }

// Setup constructs a plain HTTP client targeting the harness MCP port.
func (m *MCPAdapter) Setup(ctx context.Context, h *Harness) error {
	m.endpoint = GetServiceEndpoints(h.Config()).MCP
	m.client = helpers.NewPlainHTTPClient(15 * time.Second)
	return nil
}

// Teardown closes idle connections.
func (m *MCPAdapter) Teardown() error {
	if m.client != nil {
		m.client.CloseIdleConnections()
	}
	return nil
}

// Health invokes GET /healthz on the MCP listener.
func (m *MCPAdapter) Health(ctx context.Context) (*HealthSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.endpoint+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		State string `json:"state"`
		Ready bool   `json:"ready"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return &HealthSnapshot{State: body.State, Ready: body.Ready}, nil
}

// AddMTLSFactor calls the platform_auth_factor_add MCP tool. Stubbed.
func (m *MCPAdapter) AddMTLSFactor(ctx context.Context, username, bundlePath, label string) error {
	return notWired("MCP", "auth factor add")
}

// ListFactors lists factors. Stubbed.
func (m *MCPAdapter) ListFactors(ctx context.Context, username string) ([]FactorRecord, error) {
	return nil, notWired("MCP", "auth factor list")
}

// LoginMTLS performs an mTLS login. Stubbed.
func (m *MCPAdapter) LoginMTLS(ctx context.Context, username, bundlePath string) (*LoginSnapshot, error) {
	return nil, notWired("MCP", "auth login")
}

// RotateMTLSFactor rotates a factor. Stubbed.
func (m *MCPAdapter) RotateMTLSFactor(ctx context.Context, username, factorID, newBundlePath string) (string, error) {
	return "", notWired("MCP", "auth factor rotate")
}

// RemoveFactor removes a factor. Stubbed.
func (m *MCPAdapter) RemoveFactor(ctx context.Context, username, factorID string) error {
	return notWired("MCP", "auth factor remove")
}

var _ ColdStartCommands = (*MCPAdapter)(nil)
