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
)

// =============================================================================
// SDN Operations - Nil Service Tests
// =============================================================================

func TestMCPServiceProvider_SDNSetPortState_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNSetPortState(ctx, "br0", "eth0", "authorized")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		err := provider.SDNSetPortState(ctx, "", "eth0", "authorized")
		if err == nil {
			t.Fatal("expected error for missing bridge name")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
		}
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		err := provider.SDNSetPortState(ctx, "br0", "", "authorized")
		if err == nil {
			t.Fatal("expected error for missing port name")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
		}
	})

	t.Run("returns error for missing state", func(t *testing.T) {
		err := provider.SDNSetPortState(ctx, "br0", "eth0", "")
		if err == nil {
			t.Fatal("expected error for missing state")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
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

func TestMCPServiceProvider_SDNApplyPolicy_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error for missing policyID", func(t *testing.T) {
		err := provider.SDNApplyPolicy(ctx, "", "br0")
		if err == nil {
			t.Fatal("expected error for missing policyID")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
		}
	})

	t.Run("returns error for missing bridgeName", func(t *testing.T) {
		err := provider.SDNApplyPolicy(ctx, "policy1", "")
		if err == nil {
			t.Fatal("expected error for missing bridgeName")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
		}
	})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNApplyPolicy(ctx, "policy1", "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNGetPolicy_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error for missing policyID", func(t *testing.T) {
		_, err := provider.SDNGetPolicy(ctx, "")
		if err == nil {
			t.Fatal("expected error for missing policyID")
		}
		if _, ok := err.(ErrSDNMissingParameter); !ok {
			t.Errorf("expected ErrSDNMissingParameter, got %T: %v", err, err)
		}
	})

	t.Run("returns error when policy engine is nil", func(t *testing.T) {
		_, err := provider.SDNGetPolicy(ctx, "policy1")
		if err == nil {
			t.Fatal("expected error for nil policy engine")
		}
		if _, ok := err.(ErrSDNPolicyEngineNotConfigured); !ok {
			t.Errorf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNListPolicies_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when policy engine is nil", func(t *testing.T) {
		_, err := provider.SDNListPolicies(ctx)
		if err == nil {
			t.Fatal("expected error for nil policy engine")
		}
		if _, ok := err.(ErrSDNPolicyEngineNotConfigured); !ok {
			t.Errorf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNAddFlow_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{"priority": 100})
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
		err := provider.SDNFlushFlows(ctx, "br0")
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
		err := provider.SDNCreateVLAN(ctx, "br0", 100, "guest")
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

func TestMCPServiceProvider_SDNAuthenticatePort_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", map[string]string{"certificate": "cert"})
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}

func TestMCPServiceProvider_SDNRevokePortAuth_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	t.Run("returns error when SDN service is nil", func(t *testing.T) {
		err := provider.SDNRevokePortAuth(ctx, "br0", "eth0")
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
		_, err := provider.SDNGetFlowStats(ctx, "br0")
		if err == nil {
			t.Fatal("expected error for nil SDN service")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
		}
	})
}
