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
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vpnMCPProvider is the VPN surface both MCP service providers expose, so
// one table drives both implementations.
type vpnMCPProvider interface {
	VPNEnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (interface{}, error)
	VPNListPeers(ctx context.Context, tenantID string) (interface{}, error)
	VPNRevokePeer(ctx context.Context, tenantID, deviceID string) (interface{}, error)
	VPNStatus(ctx context.Context, gatewayID string) (interface{}, error)
	VPNPosturePolicyGet(ctx context.Context, tenantID, name string) (interface{}, error)
	VPNPosturePolicySet(ctx context.Context, tenantID, name, module string) (interface{}, error)
	VPNPosturePolicyDelete(ctx context.Context, tenantID, name string) (interface{}, error)
	VPNPosturePolicyList(ctx context.Context, tenantID string) (interface{}, error)
}

// vpnProviders builds the MCP provider over the server; a nil server
// leaves it unwired.
func vpnProviders(server platformv1.VPNServiceServer) map[string]vpnMCPProvider {
	mcpProvider := &MCPServiceProvider{}
	if server != nil {
		mcpProvider.SetVPNService(server)
	}
	return map[string]vpnMCPProvider{
		"MCPServiceProvider": mcpProvider,
	}
}

func TestMCPProvidersWithoutVPNServiceAreUnavailable(t *testing.T) {
	for name, provider := range vpnProviders(nil) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			calls := map[string]func() error{
				"VPNEnrolPeer": func() error {
					_, err := provider.VPNEnrolPeer(ctx, "acme", "laptop-1", nil)
					return err
				},
				"VPNListPeers": func() error {
					_, err := provider.VPNListPeers(ctx, "")
					return err
				},
				"VPNRevokePeer": func() error {
					_, err := provider.VPNRevokePeer(ctx, "acme", "laptop-1")
					return err
				},
				"VPNStatus": func() error {
					_, err := provider.VPNStatus(ctx, "")
					return err
				},
				"VPNPosturePolicyGet": func() error {
					_, err := provider.VPNPosturePolicyGet(ctx, "acme", "corp")
					return err
				},
				"VPNPosturePolicySet": func() error {
					_, err := provider.VPNPosturePolicySet(ctx, "acme", "corp", vpnTestPolicy)
					return err
				},
				"VPNPosturePolicyDelete": func() error {
					_, err := provider.VPNPosturePolicyDelete(ctx, "acme", "corp")
					return err
				},
				"VPNPosturePolicyList": func() error {
					_, err := provider.VPNPosturePolicyList(ctx, "")
					return err
				},
			}
			for call, run := range calls {
				var unavailable ErrServiceNotAvailable
				err := run()
				require.True(t, errors.As(err, &unavailable), "%s error = %v", call, err)
				assert.Equal(t, vpnServiceName, unavailable.Service, call)
			}
		})
	}
}
