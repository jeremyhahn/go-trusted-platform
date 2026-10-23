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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// SDN Operations - Nil Service Tests
// =============================================================================

// mcpPortStateSetters are the two MCP service providers' SDNSetPortState,
// each wired to svc, so one test proves both reach the shared SDNService.
func mcpPortStateSetters(svc *SDNService) map[string]func(ctx context.Context, bridge, port, state string, rates mcp.PortRates) (interface{}, error) {
	mcpProvider := NewMCPServiceProvider(&MCPServiceProviderConfig{SDNService: svc})
	return map[string]func(ctx context.Context, bridge, port, state string, rates mcp.PortRates) (interface{}, error){
		"MCPServiceProvider": mcpProvider.SDNSetPortState,
	}
}

func TestMCPSDNSetPortState_AppliesStateAndIngressPolicing(t *testing.T) {
	ctx := context.Background()
	for name := range mcpPortStateSetters(nil) {
		t.Run(name, func(t *testing.T) {
			mockClient := NewConfigurableMockOVSClient()
			setPortState := mcpPortStateSetters(newSetPortStateTestService(mockClient))[name]

			_, err := setPortState(ctx, "br0", "port0", "down", mcp.PortRates{
				IngressRate: 10_000_000, IngressBurst: 1_000_000,
				EgressRate: 20_000_000, EgressBurst: 2_000_000,
			})
			require.NoError(t, err)

			stateCalls := mockClient.GetCalls("SetPortState")
			require.Len(t, stateCalls, 1)
			assert.Equal(t, []interface{}{"port0", ovs.PortStateDown}, stateCalls[0].Args)
			policingCalls := mockClient.GetCalls("SetIngressPolicing")
			require.Len(t, policingCalls, 1)
			assert.Equal(t, []interface{}{"port0", uint64(10_000_000), uint64(1_000_000)}, policingCalls[0].Args)
			shapingCalls := mockClient.GetCalls("SetEgressShaping")
			require.Len(t, shapingCalls, 1)
			assert.Equal(t, []interface{}{"port0", uint64(20_000_000), uint64(2_000_000)}, shapingCalls[0].Args)
		})
	}
}

func TestMCPSDNSetPortState_Errors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		bridge string
		port   string
		state  string
		rates  mcp.PortRates
		want   codes.Code
	}{
		{name: "missing bridge", port: "port0", state: "up", want: codes.InvalidArgument},
		{name: "802.1X state", bridge: "br0", port: "port0", state: "authorized", want: codes.InvalidArgument},
		{name: "rate not a whole kbps", bridge: "br0", port: "port0", state: "up", rates: mcp.PortRates{IngressRate: 1500}, want: codes.InvalidArgument},
		{name: "egress burst without a rate", bridge: "br0", port: "port0", state: "up", rates: mcp.PortRates{EgressBurst: 1000}, want: codes.InvalidArgument},
		{name: "unknown port", bridge: "br0", port: "missing", state: "up", want: codes.NotFound},
	}
	for name := range mcpPortStateSetters(nil) {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				mockClient := NewConfigurableMockOVSClient()
				setPortState := mcpPortStateSetters(newSetPortStateTestService(mockClient))[name]

				_, err := setPortState(ctx, tc.bridge, tc.port, tc.state, tc.rates)

				assert.Equal(t, tc.want, status.Code(err), err)
				assert.Empty(t, mockClient.GetCalls("SetPortState"), "nothing is applied")
			})
		}
	}

	t.Run("without the SDN service", func(t *testing.T) {
		for name, setPortState := range mcpPortStateSetters(nil) {
			var unavailable ErrServiceNotAvailable
			_, err := setPortState(ctx, "br0", "port0", "up", mcp.PortRates{})
			assert.ErrorAs(t, err, &unavailable, name)
		}
	})
}

func TestMCPServiceProvider_SDNCreateBridge_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNCreateBridge(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNDeleteBridge_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNDeleteBridge(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNAddPort_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNAddPort(ctx, "br0", "eth0", "access")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNDeletePort_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNDeletePort(ctx, "br0", "eth0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNAddFlow_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNDeleteFlow_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNDeleteFlow(ctx, "br0", "flow-1")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNListFlows_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNListFlows(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNFlushFlows_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNFlushFlows(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNCreateVLAN_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNCreateVLAN(ctx, "br0", 100, "guest")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNDeleteVLAN_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNDeleteVLAN(ctx, "br0", 100)
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNListVLANs_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNListVLANs(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNGetPortStats_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNGetFlowStats_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		_, err := provider.SDNGetFlowStats(ctx, "br0", "0x1")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}
