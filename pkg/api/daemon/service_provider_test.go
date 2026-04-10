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
)

func TestNewPlatformServiceProvider(t *testing.T) {
	t.Run("creates provider with nil services", func(t *testing.T) {
		config := &PlatformServiceProviderConfig{}
		provider := NewPlatformServiceProvider(config)

		if provider == nil {
			t.Fatal("NewPlatformServiceProvider() returned nil")
		}
	})

	t.Run("creates provider with default logger", func(t *testing.T) {
		config := &PlatformServiceProviderConfig{
			Logger: nil,
		}
		provider := NewPlatformServiceProvider(config)

		if provider.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestPlatformServiceProvider_VTPMOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("VTPMCreate returns error", func(t *testing.T) {
		_, err := provider.VTPMCreate(ctx, "test", "RSA")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMDelete returns error", func(t *testing.T) {
		err := provider.VTPMDelete(ctx, "test")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMList returns error", func(t *testing.T) {
		_, err := provider.VTPMList(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMStart returns error", func(t *testing.T) {
		err := provider.VTPMStart(ctx, "test")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMStop returns error", func(t *testing.T) {
		err := provider.VTPMStop(ctx, "test")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMQuote returns error", func(t *testing.T) {
		_, err := provider.VTPMQuote(ctx, "test", []byte("nonce"), []int{0, 1, 2})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMSeal returns error", func(t *testing.T) {
		_, err := provider.VTPMSeal(ctx, "test", []byte("data"), []int{0, 1})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMUnseal returns error", func(t *testing.T) {
		_, err := provider.VTPMUnseal(ctx, "test", []byte("sealed"))
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMExtendPCR returns error", func(t *testing.T) {
		err := provider.VTPMExtendPCR(ctx, "test", 0, []byte("data"))
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("VTPMReadPCR returns error", func(t *testing.T) {
		_, err := provider.VTPMReadPCR(ctx, "test", 0)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

func TestPlatformServiceProvider_DNSOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("DNSAddRecord returns error", func(t *testing.T) {
		err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSDeleteRecord returns error", func(t *testing.T) {
		err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSGetRecord returns error", func(t *testing.T) {
		_, err := provider.DNSGetRecord(ctx, "test.example.com", "A")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSListRecords returns error", func(t *testing.T) {
		_, err := provider.DNSListRecords(ctx, "example.com")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSResolve returns error", func(t *testing.T) {
		_, err := provider.DNSResolve(ctx, "test.example.com", "A")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSCreateZone returns error", func(t *testing.T) {
		err := provider.DNSCreateZone(ctx, "example.com")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSDeleteZone returns error", func(t *testing.T) {
		err := provider.DNSDeleteZone(ctx, "example.com")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DNSListZones returns error", func(t *testing.T) {
		_, err := provider.DNSListZones(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

func TestPlatformServiceProvider_DeviceOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("DeviceRegister returns error", func(t *testing.T) {
		_, err := provider.DeviceRegister(ctx, "device1", "server", nil)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceGet returns error", func(t *testing.T) {
		_, err := provider.DeviceGet(ctx, "1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceList returns error", func(t *testing.T) {
		_, err := provider.DeviceList(ctx, nil)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceDelete returns error", func(t *testing.T) {
		err := provider.DeviceDelete(ctx, "1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceUpdate returns error", func(t *testing.T) {
		err := provider.DeviceUpdate(ctx, "1", map[string]interface{}{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceAttest returns error", func(t *testing.T) {
		_, err := provider.DeviceAttest(ctx, "1", nil)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("DeviceProvision returns error", func(t *testing.T) {
		err := provider.DeviceProvision(ctx, "1", "profile1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

func TestPlatformServiceProvider_SDNOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("SDNGetPortState returns error", func(t *testing.T) {
		_, err := provider.SDNGetPortState(ctx, "br0", "eth0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNSetPortState returns error", func(t *testing.T) {
		err := provider.SDNSetPortState(ctx, "br0", "eth0", "up")
		if err == nil {
			t.Error("expected error")
		}
		// This method returns a specific error even with nil service
	})

	t.Run("SDNListBridges returns error", func(t *testing.T) {
		_, err := provider.SDNListBridges(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNCreateBridge returns error", func(t *testing.T) {
		err := provider.SDNCreateBridge(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNDeleteBridge returns error", func(t *testing.T) {
		err := provider.SDNDeleteBridge(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNAddPort returns error", func(t *testing.T) {
		err := provider.SDNAddPort(ctx, "br0", "eth0", "PORT_TYPE_INTERNAL")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNDeletePort returns error", func(t *testing.T) {
		err := provider.SDNDeletePort(ctx, "br0", "eth0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNApplyPolicy returns error", func(t *testing.T) {
		err := provider.SDNApplyPolicy(ctx, "policy1", "br0")
		if err == nil {
			t.Error("expected error")
		}
		// This method is not implemented yet
	})

	t.Run("SDNGetPolicy returns error", func(t *testing.T) {
		_, err := provider.SDNGetPolicy(ctx, "policy1")
		if err == nil {
			t.Error("expected error")
		}
		// This method is not implemented yet
	})

	t.Run("SDNListPolicies returns error", func(t *testing.T) {
		_, err := provider.SDNListPolicies(ctx)
		if err == nil {
			t.Error("expected error")
		}
		// This method is not implemented yet
	})

	t.Run("SDNAddFlow returns error", func(t *testing.T) {
		err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNDeleteFlow returns error", func(t *testing.T) {
		err := provider.SDNDeleteFlow(ctx, "br0", "flow1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNListFlows returns error", func(t *testing.T) {
		_, err := provider.SDNListFlows(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNFlushFlows returns error", func(t *testing.T) {
		err := provider.SDNFlushFlows(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNCreateVLAN returns error", func(t *testing.T) {
		err := provider.SDNCreateVLAN(ctx, "br0", 100, "vlan100")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNDeleteVLAN returns error", func(t *testing.T) {
		err := provider.SDNDeleteVLAN(ctx, "br0", 100)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNListVLANs returns error", func(t *testing.T) {
		_, err := provider.SDNListVLANs(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNAuthenticatePort returns error", func(t *testing.T) {
		err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", map[string]string{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNRevokePortAuth returns error", func(t *testing.T) {
		err := provider.SDNRevokePortAuth(ctx, "br0", "eth0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNGetPortStats returns error", func(t *testing.T) {
		_, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("SDNGetFlowStats returns error", func(t *testing.T) {
		_, err := provider.SDNGetFlowStats(ctx, "br0")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

func TestPlatformServiceProvider_HealthOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("Health returns error", func(t *testing.T) {
		_, err := provider.Health(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("Liveness returns error", func(t *testing.T) {
		_, err := provider.Liveness(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("Readiness returns error", func(t *testing.T) {
		_, err := provider.Readiness(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

func TestParseDeviceID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    uint64
		wantErr bool
	}{
		{
			name:    "valid ID",
			input:   "123",
			want:    123,
			wantErr: false,
		},
		{
			name:    "zero",
			input:   "0",
			want:    0,
			wantErr: false,
		},
		{
			name:    "large number",
			input:   "9999999",
			want:    9999999,
			wantErr: false,
		},
		{
			name:    "invalid string",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			// Sscanf parses the leading digits and ignores trailing characters
			name:    "mixed alphanumeric parses leading digits",
			input:   "123abc",
			want:    123,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDeviceID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if got != tt.want {
					t.Errorf("parseDeviceID(%q) = %d, want %d", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestBuildFlowMatch(t *testing.T) {
	t.Run("builds empty match from empty map", func(t *testing.T) {
		match := buildFlowMatch(map[string]interface{}{})
		if match == nil {
			t.Fatal("match should not be nil")
		}
	})

	t.Run("builds match with all fields", func(t *testing.T) {
		matchMap := map[string]interface{}{
			"in_port":  "eth0",
			"vlan_id":  100,
			"eth_src":  "00:11:22:33:44:55",
			"eth_dst":  "66:77:88:99:aa:bb",
			"eth_type": 0x0800,
			"ip_src":   "192.168.1.1",
			"ip_dst":   "192.168.1.2",
			"ip_proto": 6,
			"tcp_src":  80,
			"tcp_dst":  443,
			"udp_src":  53,
			"udp_dst":  5353,
			"metadata": map[string]string{"key": "value"},
		}

		match := buildFlowMatch(matchMap)
		if match.InPort != "eth0" {
			t.Errorf("InPort = %q, want %q", match.InPort, "eth0")
		}
		if match.VlanId != 100 {
			t.Errorf("VlanId = %d, want %d", match.VlanId, 100)
		}
		if match.EthSrc != "00:11:22:33:44:55" {
			t.Errorf("EthSrc = %q, want %q", match.EthSrc, "00:11:22:33:44:55")
		}
	})
}

func TestBuildFlowActions(t *testing.T) {
	t.Run("builds empty actions from empty slice", func(t *testing.T) {
		actions := buildFlowActions([]interface{}{})
		if actions == nil {
			t.Fatal("actions should not be nil")
		}
		if len(actions) != 0 {
			t.Errorf("len(actions) = %d, want 0", len(actions))
		}
	})

	t.Run("skips invalid action types", func(t *testing.T) {
		actions := buildFlowActions([]interface{}{"not a map"})
		if len(actions) != 0 {
			t.Errorf("len(actions) = %d, want 0", len(actions))
		}
	})

	t.Run("builds actions with valid maps", func(t *testing.T) {
		actionsSlice := []interface{}{
			map[string]interface{}{
				"port":     "eth1",
				"vlan_id":  200,
				"field":    "dst_ip",
				"value":    "10.0.0.1",
				"table_id": 5,
			},
		}

		actions := buildFlowActions(actionsSlice)
		if len(actions) != 1 {
			t.Fatalf("len(actions) = %d, want 1", len(actions))
		}
		if actions[0].Port != "eth1" {
			t.Errorf("Port = %q, want %q", actions[0].Port, "eth1")
		}
		if actions[0].VlanId != 200 {
			t.Errorf("VlanId = %d, want %d", actions[0].VlanId, 200)
		}
	})
}

// CA Operations tests - all return service not available

func TestPlatformServiceProvider_CAOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("CAInfo returns error", func(t *testing.T) {
		_, err := provider.CAInfo(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CAIssue returns error", func(t *testing.T) {
		_, err := provider.CAIssue(ctx, &mcp.CAIssueRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CAGet returns error", func(t *testing.T) {
		_, err := provider.CAGet(ctx, "123456", true)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CAList returns error", func(t *testing.T) {
		_, err := provider.CAList(ctx, 10, "", "active")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CARevoke returns error", func(t *testing.T) {
		_, err := provider.CARevoke(ctx, "123456", 1, false)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CARenew returns error", func(t *testing.T) {
		_, err := provider.CARenew(ctx, "123456", 365, true)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CAVerify returns error", func(t *testing.T) {
		_, err := provider.CAVerify(ctx, "-----BEGIN CERTIFICATE-----", nil, true)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CACRL returns error", func(t *testing.T) {
		_, err := provider.CACRL(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("CABundle returns error", func(t *testing.T) {
		_, err := provider.CABundle(ctx, "file", "RSA")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

// IAM Operations tests - all return service not available

func TestPlatformServiceProvider_IAMOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("IAMCreateUser returns error", func(t *testing.T) {
		_, err := provider.IAMCreateUser(ctx, &mcp.IAMCreateUserRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMDeleteUser returns error", func(t *testing.T) {
		err := provider.IAMDeleteUser(ctx, "tenant1", "user1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMGetUser returns error", func(t *testing.T) {
		_, err := provider.IAMGetUser(ctx, "tenant1", "user1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMListUsers returns error", func(t *testing.T) {
		_, err := provider.IAMListUsers(ctx, "tenant1", 10, 0)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMCreateRole returns error", func(t *testing.T) {
		_, err := provider.IAMCreateRole(ctx, &mcp.IAMCreateRoleRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMDeleteRole returns error", func(t *testing.T) {
		err := provider.IAMDeleteRole(ctx, "tenant1", "role1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMGetRole returns error", func(t *testing.T) {
		_, err := provider.IAMGetRole(ctx, "tenant1", "role1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMListRoles returns error", func(t *testing.T) {
		_, err := provider.IAMListRoles(ctx, "tenant1", 10, 0)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMAssignRole returns error", func(t *testing.T) {
		err := provider.IAMAssignRole(ctx, "tenant1", "user1", "admin")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMRevokeRole returns error", func(t *testing.T) {
		err := provider.IAMRevokeRole(ctx, "tenant1", "user1", "admin")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMCheckPermission returns error", func(t *testing.T) {
		_, err := provider.IAMCheckPermission(ctx, "tenant1", "user1", "resource", "read")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("IAMAuthenticate returns error", func(t *testing.T) {
		_, err := provider.IAMAuthenticate(ctx, &mcp.IAMAuthenticateRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}

// KMS Operations tests - all return service not available

func TestPlatformServiceProvider_KMSOperations_NilService(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	t.Run("KMSCreateKey returns error", func(t *testing.T) {
		_, err := provider.KMSCreateKey(ctx, &mcp.KMSCreateKeyRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSDeleteKey returns error", func(t *testing.T) {
		err := provider.KMSDeleteKey(ctx, "key1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSGetKey returns error", func(t *testing.T) {
		_, err := provider.KMSGetKey(ctx, "key1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSListKeys returns error", func(t *testing.T) {
		_, err := provider.KMSListKeys(ctx, 10, 0)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSRotateKey returns error", func(t *testing.T) {
		_, err := provider.KMSRotateKey(ctx, "key1")
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSEncrypt returns error", func(t *testing.T) {
		_, err := provider.KMSEncrypt(ctx, &mcp.KMSEncryptRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSDecrypt returns error", func(t *testing.T) {
		_, err := provider.KMSDecrypt(ctx, &mcp.KMSDecryptRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSSign returns error", func(t *testing.T) {
		_, err := provider.KMSSign(ctx, &mcp.KMSSignRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSVerify returns error", func(t *testing.T) {
		_, err := provider.KMSVerify(ctx, &mcp.KMSVerifyRequest{})
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})

	t.Run("KMSGenerateRandom returns error", func(t *testing.T) {
		_, err := provider.KMSGenerateRandom(ctx, 32)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable, got %T", err)
		}
	})
}
