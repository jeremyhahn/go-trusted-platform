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
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

const tenantServiceName = "platform.v1.TenantService"

// TestRegisterTenantGRPCServer_OneInstanceAcrossServers is the #730
// regression: registering on the TCP and the Unix-socket servers must leave
// one TenantGRPCServer behind, so the SetManager the daemon calls afterwards
// reaches the handler both listeners dispatch to.
func TestRegisterTenantGRPCServer_OneInstanceAcrossServers(t *testing.T) {
	svc := &TenantService{logger: slog.Default()}
	tcp, uds := grpc.NewServer(), grpc.NewServer()

	svc.registerTenantGRPCServer(tcp)
	first := svc.grpcServer
	require.NotNil(t, first)

	svc.registerTenantGRPCServer(uds)
	assert.Same(t, first, svc.grpcServer, "the second registration must not replace the first server's handler")

	assert.Contains(t, tcp.GetServiceInfo(), tenantServiceName)
	assert.Contains(t, uds.GetServiceInfo(), tenantServiceName)
}

// TestRegisterTenantGRPCServer_KeepsAnInjectedServer covers the error-prone
// direction: an existing handler (one SetManager may already have reached) is
// registered as is, never rebuilt.
func TestRegisterTenantGRPCServer_KeepsAnInjectedServer(t *testing.T) {
	existing := NewTenantGRPCServer(WithTenantLogger(slog.Default()))
	svc := &TenantService{logger: slog.Default(), grpcServer: existing}

	svc.registerTenantGRPCServer(grpc.NewServer())
	assert.Same(t, existing, svc.grpcServer)
}
