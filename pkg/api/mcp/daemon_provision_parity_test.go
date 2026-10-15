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

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// scopeParityRow is one daemon or provisioning operation and its name on
// each transport. scope is the permission every transport must require;
// "" means the operation is open (pre-auth) everywhere it is served. An
// empty grpcMethod or quicOpcode means that transport does not serve the
// operation. mcpRefused marks a tool MCP deliberately leaves unclassified
// so the authorizer refuses it (#304).
type scopeParityRow struct {
	name       string
	scope      string
	grpcMethod string
	quicOpcode byte
	quicSub    []byte
	mcpTool    string
	mcpRefused bool
}

var daemonProvisionParityRows = []scopeParityRow{
	{name: "daemon status", scope: "platform:read",
		grpcMethod: "/platform.v1.PlatformDaemon/GetStatus",
		quicOpcode: quicwire.OpDaemonStatus, mcpTool: "platform_daemon_status"},
	{name: "daemon version", scope: "platform:read",
		grpcMethod: "/platform.v1.PlatformDaemon/GetVersion",
		quicOpcode: quicwire.OpDaemonVersion, mcpTool: "platform_daemon_version"},
	{name: "daemon list services", scope: "platform:read",
		grpcMethod: "/platform.v1.PlatformDaemon/ListServices",
		quicOpcode: quicwire.OpDaemonListServices, mcpTool: "platform_daemon_list_services"},
	{name: "daemon get service", scope: "platform:read",
		grpcMethod: "/platform.v1.PlatformDaemon/GetServiceStatus",
		quicOpcode: quicwire.OpDaemonGetService, mcpTool: "platform_daemon_get_service"},
	{name: "daemon start service", scope: "platform:write",
		grpcMethod: "/platform.v1.PlatformDaemon/StartService",
		quicOpcode: quicwire.OpDaemonStartService, mcpTool: "platform_daemon_start_service"},
	{name: "daemon stop service", scope: "platform:write",
		grpcMethod: "/platform.v1.PlatformDaemon/StopService",
		quicOpcode: quicwire.OpDaemonStopService, mcpTool: "platform_daemon_stop_service"},
	{name: "daemon restart service", scope: "platform:write",
		grpcMethod: "/platform.v1.PlatformDaemon/RestartService",
		quicOpcode: quicwire.OpDaemonRestartService, mcpTool: "platform_daemon_restart_service"},
	{name: "daemon list protocols", scope: "platform:read",
		quicOpcode: quicwire.OpDaemonListProtocols, mcpTool: "platform_daemon_list_protocols", mcpRefused: true},
	{name: "provisioning get nonce",
		grpcMethod: "/platform.v1.ConfigDeliveryService/GetNonce",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubGetNonce},
		mcpTool: "provision_get_nonce"},
	{name: "provisioning fetch config",
		grpcMethod: "/platform.v1.ConfigDeliveryService/FetchConfig",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubFetchConfig},
		mcpTool: "provision_fetch_config"},
	{name: "provisioning sign digest",
		grpcMethod: "/platform.v1.ConfigDeliveryService/SignDigest",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubSignDigest},
		mcpTool: "provision_sign_digest"},
	{name: "provisioning poll session",
		grpcMethod: "/platform.v1.ConfigDeliveryService/PollSession",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubPollSession},
		mcpTool: "provision_poll_session"},
	{name: "provisioning fulfill session", scope: "provisioning:write",
		grpcMethod: "/platform.v1.ConfigDeliveryService/FulfillSession",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubFulfillSession},
		mcpTool: "provision_fulfill_session"},
	{name: "provisioning list sessions", scope: "provisioning:read",
		grpcMethod: "/platform.v1.ConfigDeliveryService/ListSessions",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubListSessions},
		mcpTool: "provision_list_sessions"},
	{name: "provisioning get session", scope: "provisioning:read",
		grpcMethod: "/platform.v1.ConfigDeliveryService/GetSession",
		quicOpcode: quicwire.OpProvisioningCategory, quicSub: []byte{quicwire.ProvisioningSubGetSession},
		mcpTool: "provision_get_session"},
}

// TestDaemonProvisionScopeParity asserts that every daemon and
// provisioning operation needs one permission — or is open — on gRPC, QUIC
// and MCP alike, so the three catalogs cannot drift apart again (#304,
// #317). A registered gRPC method without a scope is pre-auth: the gRPC
// catalog test refuses any registered method that is neither.
func TestDaemonProvisionScopeParity(t *testing.T) {
	assertScopeParity(t, daemonProvisionParityRows)
}

// assertScopeParity checks every row's scope against the gRPC, QUIC and MCP
// catalogs.
func assertScopeParity(t *testing.T, rows []scopeParityRow) {
	t.Helper()
	catalog := toolPermissionCatalog()
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if row.grpcMethod != "" {
				assert.Equal(t, row.scope, grpcapi.ScopeForMethod(row.grpcMethod), "gRPC %s", row.grpcMethod)
			}

			perm, preAuth, err := quicapi.LookupOperationPermission(row.quicOpcode, row.quicSub)
			require.NoError(t, err, "QUIC opcode 0x%02X is not classified", row.quicOpcode)
			if row.scope == "" {
				assert.True(t, preAuth, "QUIC opcode 0x%02X %v must be open", row.quicOpcode, row.quicSub)
			} else {
				assert.False(t, preAuth, "QUIC opcode 0x%02X %v must not be open", row.quicOpcode, row.quicSub)
				assert.Equal(t, row.scope, perm.Scope(), "QUIC opcode 0x%02X %v", row.quicOpcode, row.quicSub)
			}

			mcpScope, classified := catalog[row.mcpTool]
			if row.mcpRefused {
				assert.False(t, classified, "MCP %s must stay unclassified (refused)", row.mcpTool)
				return
			}
			require.True(t, classified, "MCP %s is not classified", row.mcpTool)
			assert.Equal(t, row.scope, mcpScope, "MCP %s", row.mcpTool)
		})
	}
}
