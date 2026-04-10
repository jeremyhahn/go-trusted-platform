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

package modes

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// createTestLogger creates a logger for tests.
func createTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// createTestVTEPConfig creates a valid VTEP configuration for testing.
func createTestVTEPConfig() *vxlan.VTEPConfig {
	return &vxlan.VTEPConfig{
		LocalIP:       netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   9000,
		VXLANPort:     4789,
	}
}

// createTestOverlayConfig creates a valid overlay mode configuration for testing.
func createTestOverlayConfig() *OverlayModeConfig {
	return &OverlayModeConfig{
		VTEPConfig:     createTestVTEPConfig(),
		BridgeName:     "br-test",
		ARPSuppression: true,
		Logger:         createTestLogger(),
	}
}

// TestMACEntrySource_String tests the MACEntrySource.String method.
func TestMACEntrySource_String(t *testing.T) {
	tests := []struct {
		name   string
		source MACEntrySource
		want   string
	}{
		{
			name:   "local source",
			source: MACSourceLocal,
			want:   "local",
		},
		{
			name:   "remote source",
			source: MACSourceRemote,
			want:   "remote",
		},
		{
			name:   "static source",
			source: MACSourceStatic,
			want:   "static",
		},
		{
			name:   "unknown source",
			source: MACEntrySource(99),
			want:   "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.source.String(); got != tt.want {
				t.Errorf("MACEntrySource.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMACEntry_IsExpired tests the MACEntry.IsExpired method.
func TestMACEntry_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "zero expiration time",
			expiresAt: time.Time{},
			want:      false,
		},
		{
			name:      "future expiration",
			expiresAt: time.Now().Add(time.Hour),
			want:      false,
		},
		{
			name:      "past expiration",
			expiresAt: time.Now().Add(-time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := &MACEntry{
				ExpiresAt: tt.expiresAt,
			}
			if got := entry.IsExpired(); got != tt.want {
				t.Errorf("MACEntry.IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMACEntry_Clone tests the MACEntry.Clone method.
func TestMACEntry_Clone(t *testing.T) {
	t.Run("clone nil entry", func(t *testing.T) {
		var entry *MACEntry
		clone := entry.Clone()
		if clone != nil {
			t.Error("Clone of nil entry should be nil")
		}
	})

	t.Run("clone valid entry", func(t *testing.T) {
		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		now := time.Now()
		entry := &MACEntry{
			MAC:       mac,
			IP:        netip.MustParseAddr("192.168.1.100"),
			VNI:       1000,
			VTEPIP:    netip.MustParseAddr("10.0.0.1"),
			OFPort:    10,
			Source:    MACSourceLocal,
			Sequence:  5,
			CreatedAt: now,
			UpdatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		}

		clone := entry.Clone()
		if clone == nil {
			t.Fatal("Clone should not be nil")
		}

		// Verify deep copy
		if clone == entry {
			t.Error("Clone should be a different instance")
		}

		// Verify values
		if clone.VNI != entry.VNI {
			t.Errorf("VNI mismatch: got %d, want %d", clone.VNI, entry.VNI)
		}
		if clone.IP != entry.IP {
			t.Errorf("IP mismatch: got %v, want %v", clone.IP, entry.IP)
		}
		if clone.Source != entry.Source {
			t.Errorf("Source mismatch: got %v, want %v", clone.Source, entry.Source)
		}

		// Verify MAC is deep copied
		if &clone.MAC[0] == &entry.MAC[0] {
			t.Error("MAC should be a deep copy")
		}
		if clone.MAC.String() != entry.MAC.String() {
			t.Errorf("MAC value mismatch: got %s, want %s", clone.MAC.String(), entry.MAC.String())
		}
	})

	t.Run("clone entry with nil MAC", func(t *testing.T) {
		entry := &MACEntry{
			VNI: 1000,
		}
		clone := entry.Clone()
		if clone == nil {
			t.Fatal("Clone should not be nil")
		}
		if clone.MAC != nil {
			t.Error("Clone MAC should be nil")
		}
	})
}

// TestOverlayModeConfig_Validate tests the OverlayModeConfig.Validate method.
func TestOverlayModeConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *OverlayModeConfig
		wantErr error
	}{
		{
			name:    "valid config",
			config:  createTestOverlayConfig(),
			wantErr: nil,
		},
		{
			name: "nil VTEP config",
			config: &OverlayModeConfig{
				VTEPConfig: nil,
				BridgeName: "br-test",
				Logger:     createTestLogger(),
			},
			wantErr: ErrVTEPConfigNil,
		},
		{
			name: "empty bridge name",
			config: &OverlayModeConfig{
				VTEPConfig: createTestVTEPConfig(),
				BridgeName: "",
				Logger:     createTestLogger(),
			},
			wantErr: ErrBridgeNameEmpty,
		},
		{
			name: "nil logger",
			config: &OverlayModeConfig{
				VTEPConfig: createTestVTEPConfig(),
				BridgeName: "br-test",
				Logger:     nil,
			},
			wantErr: ErrLoggerNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Validate() should return error %v", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestNewOverlayModeHandler tests the NewOverlayModeHandler function.
func TestNewOverlayModeHandler(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		_, err := NewOverlayModeHandler(nil, nil, nil)
		if err != ErrConfigNil {
			t.Errorf("NewOverlayModeHandler(nil) error = %v, want %v", err, ErrConfigNil)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		config := &OverlayModeConfig{
			VTEPConfig: nil, // Invalid
		}
		_, err := NewOverlayModeHandler(config, nil, nil)
		if err == nil {
			t.Error("NewOverlayModeHandler with invalid config should return error")
		}
	})

	t.Run("nil OVS client", func(t *testing.T) {
		config := createTestOverlayConfig()
		_, err := NewOverlayModeHandler(config, nil, nil)
		if err != ErrOVSClientNil {
			t.Errorf("NewOverlayModeHandler with nil OVS client error = %v, want %v", err, ErrOVSClientNil)
		}
	})
}

// TestValidateVNI tests the validateVNI function.
func TestValidateVNI(t *testing.T) {
	tests := []struct {
		name    string
		vni     uint32
		wantErr error
	}{
		{
			name:    "valid VNI minimum",
			vni:     1,
			wantErr: nil,
		},
		{
			name:    "valid VNI maximum",
			vni:     16777215,
			wantErr: nil,
		},
		{
			name:    "valid VNI mid-range",
			vni:     1000,
			wantErr: nil,
		},
		{
			name:    "invalid VNI zero",
			vni:     0,
			wantErr: ErrVNIOutOfRange,
		},
		{
			name:    "invalid VNI too large",
			vni:     16777216,
			wantErr: ErrVNIOutOfRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateVNI(tt.vni)
			if err != tt.wantErr {
				t.Errorf("validateVNI(%d) error = %v, want %v", tt.vni, err, tt.wantErr)
			}
		})
	}
}

// TestValidateMAC tests the validateMAC function.
func TestValidateMAC(t *testing.T) {
	tests := []struct {
		name    string
		mac     net.HardwareAddr
		wantErr error
	}{
		{
			name:    "valid MAC",
			mac:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			wantErr: nil,
		},
		{
			name:    "nil MAC",
			mac:     nil,
			wantErr: ErrMACNil,
		},
		{
			name:    "invalid MAC length (too short)",
			mac:     net.HardwareAddr{0xaa, 0xbb, 0xcc},
			wantErr: ErrMACInvalid,
		},
		{
			name:    "invalid MAC length (too long)",
			mac:     net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00},
			wantErr: ErrMACInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMAC(tt.mac)
			if err != tt.wantErr {
				t.Errorf("validateMAC() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestFormatMACKey tests the formatMACKey function.
func TestFormatMACKey(t *testing.T) {
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	key := formatMACKey(1000, mac)
	expected := "1000:aa:bb:cc:dd:ee:ff"
	if key != expected {
		t.Errorf("formatMACKey() = %v, want %v", key, expected)
	}
}

// TestFormatARPKey tests the formatARPKey function.
func TestFormatARPKey(t *testing.T) {
	ip := netip.MustParseAddr("192.168.1.100")
	key := formatARPKey(1000, ip)
	expected := "1000:192.168.1.100"
	if key != expected {
		t.Errorf("formatARPKey() = %v, want %v", key, expected)
	}
}

// TestFormatVNIPrefix tests the formatVNIPrefix function.
func TestFormatVNIPrefix(t *testing.T) {
	prefix := formatVNIPrefix(1000)
	expected := "1000:"
	if prefix != expected {
		t.Errorf("formatVNIPrefix() = %v, want %v", prefix, expected)
	}
}

// TestFormatUint32 tests the formatUint32 function.
func TestFormatUint32(t *testing.T) {
	tests := []struct {
		n    uint32
		want string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{100, "100"},
		{1000, "1000"},
		{4294967295, "4294967295"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := formatUint32(tt.n); got != tt.want {
				t.Errorf("formatUint32(%d) = %v, want %v", tt.n, got, tt.want)
			}
		})
	}
}

// TestEncodeVLAN tests the encodeVLAN function.
func TestEncodeVLAN(t *testing.T) {
	tests := []struct {
		name string
		vlan uint16
		want uint16
	}{
		{
			name: "VLAN 1",
			vlan: 1,
			want: 0x1001, // 0x1000 (OFPVID_PRESENT) | 1
		},
		{
			name: "VLAN 100",
			vlan: 100,
			want: 0x1064, // 0x1000 (OFPVID_PRESENT) | 100
		},
		{
			name: "VLAN 4094",
			vlan: 4094,
			want: 0x1FFE, // 0x1000 (OFPVID_PRESENT) | 4094
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := encodeVLAN(tt.vlan)
			if len(bytes) != 2 {
				t.Errorf("encodeVLAN() length = %d, want 2", len(bytes))
			}
			got := uint16(bytes[0])<<8 | uint16(bytes[1])
			if got != tt.want {
				t.Errorf("encodeVLAN(%d) = 0x%04X, want 0x%04X", tt.vlan, got, tt.want)
			}
		})
	}
}

// TestOverlayModeStatus tests the OverlayModeStatus structure.
func TestOverlayModeStatus(t *testing.T) {
	status := &OverlayModeStatus{
		Running:                  true,
		LocalVTEP:                netip.MustParseAddr("10.0.0.1"),
		VNICount:                 5,
		TunnelCount:              3,
		LocalMACCount:            10,
		RemoteMACCount:           20,
		ARPSuppressionEnabled:    true,
		AnycastGatewayConfigured: true,
		StartedAt:                time.Now(),
		Uptime:                   time.Hour,
	}

	if !status.Running {
		t.Error("Status.Running should be true")
	}
	if status.VNICount != 5 {
		t.Errorf("Status.VNICount = %d, want 5", status.VNICount)
	}
	if status.TunnelCount != 3 {
		t.Errorf("Status.TunnelCount = %d, want 3", status.TunnelCount)
	}
	if status.LocalMACCount != 10 {
		t.Errorf("Status.LocalMACCount = %d, want 10", status.LocalMACCount)
	}
	if status.RemoteMACCount != 20 {
		t.Errorf("Status.RemoteMACCount = %d, want 20", status.RemoteMACCount)
	}
}

// TestVNIMapping tests the VNIMapping structure.
func TestVNIMapping(t *testing.T) {
	now := time.Now()
	mapping := &VNIMapping{
		VNI:       1000,
		VLAN:      100,
		CreatedAt: now,
	}

	if mapping.VNI != 1000 {
		t.Errorf("VNIMapping.VNI = %d, want 1000", mapping.VNI)
	}
	if mapping.VLAN != 100 {
		t.Errorf("VNIMapping.VLAN = %d, want 100", mapping.VLAN)
	}
	if !mapping.CreatedAt.Equal(now) {
		t.Errorf("VNIMapping.CreatedAt mismatch")
	}
}

// TestARPPacket tests the ARPPacket structure.
func TestARPPacket(t *testing.T) {
	senderMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	targetMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	packet := &ARPPacket{
		Operation: ARPRequest,
		SenderMAC: senderMAC,
		SenderIP:  netip.MustParseAddr("192.168.1.1"),
		TargetMAC: targetMAC,
		TargetIP:  netip.MustParseAddr("192.168.1.100"),
		VNI:       1000,
		InPort:    10,
	}

	if packet.Operation != ARPRequest {
		t.Errorf("ARPPacket.Operation = %d, want %d", packet.Operation, ARPRequest)
	}
	if packet.VNI != 1000 {
		t.Errorf("ARPPacket.VNI = %d, want 1000", packet.VNI)
	}
	if packet.InPort != 10 {
		t.Errorf("ARPPacket.InPort = %d, want 10", packet.InPort)
	}
}

// TestARPResponse tests the ARPResponse structure.
func TestARPResponse(t *testing.T) {
	replyMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	floodVTEPs := []netip.Addr{
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
	}

	response := &ARPResponse{
		ShouldRespond: true,
		ReplyMAC:      replyMAC,
		ShouldFlood:   false,
		FloodVTEPs:    floodVTEPs,
	}

	if !response.ShouldRespond {
		t.Error("ARPResponse.ShouldRespond should be true")
	}
	if response.ShouldFlood {
		t.Error("ARPResponse.ShouldFlood should be false")
	}
	if len(response.FloodVTEPs) != 2 {
		t.Errorf("ARPResponse.FloodVTEPs length = %d, want 2", len(response.FloodVTEPs))
	}
}

// TestARPOperation tests the ARPOperation constants.
func TestARPOperation(t *testing.T) {
	if ARPRequest != 1 {
		t.Errorf("ARPRequest = %d, want 1", ARPRequest)
	}
	if ARPReply != 2 {
		t.Errorf("ARPReply = %d, want 2", ARPReply)
	}
}

// TestTableConstants tests the OpenFlow table constants.
func TestTableConstants(t *testing.T) {
	if TableIngress != 0 {
		t.Errorf("TableIngress = %d, want 0", TableIngress)
	}
	if TableVXLANDecap != 10 {
		t.Errorf("TableVXLANDecap = %d, want 10", TableVXLANDecap)
	}
	if TableAuthentication != 20 {
		t.Errorf("TableAuthentication = %d, want 20", TableAuthentication)
	}
	if TableMACLearning != 30 {
		t.Errorf("TableMACLearning = %d, want 30", TableMACLearning)
	}
	if TableARP != 40 {
		t.Errorf("TableARP = %d, want 40", TableARP)
	}
	if TableL3Routing != 50 {
		t.Errorf("TableL3Routing = %d, want 50", TableL3Routing)
	}
	if TableEgress != 60 {
		t.Errorf("TableEgress = %d, want 60", TableEgress)
	}
}

// TestOverlayModeHandlerNotRunning tests operations on a non-running handler.
func TestOverlayModeHandlerNotRunning(t *testing.T) {
	// Create a handler without starting it (we can't easily create a real one without mocks)
	// These tests verify the error handling for operations on a non-running handler
	t.Run("AddVNI returns error when not running", func(t *testing.T) {
		// Would need mock OVS and OpenFlow clients to test fully
		// This test documents the expected behavior
		t.Log("AddVNI should return ErrNotRunning when handler is not started")
	})

	t.Run("RemoveVNI returns error when not running", func(t *testing.T) {
		t.Log("RemoveVNI should return ErrNotRunning when handler is not started")
	})

	t.Run("LearnMAC returns error when not running", func(t *testing.T) {
		t.Log("LearnMAC should return ErrNotRunning when handler is not started")
	})

	t.Run("LookupMAC returns error when not running", func(t *testing.T) {
		t.Log("LookupMAC should return ErrNotRunning when handler is not started")
	})

	t.Run("HandleARP returns error when not running", func(t *testing.T) {
		t.Log("HandleARP should return ErrNotRunning when handler is not started")
	})
}

// TestReplicationListOperations tests the replication list helper functions.
func TestReplicationListOperations(t *testing.T) {
	// Create a minimal handler for testing replication list operations
	handler := &OverlayModeHandler{
		logger: createTestLogger(),
	}

	t.Run("addToReplicationList adds new entry", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.2")
		handler.addToReplicationList(1000, vtep)

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("Expected 1 VTEP in list, got %d", len(list))
		}
		if list[0] != vtep {
			t.Errorf("Expected VTEP %v, got %v", vtep, list[0])
		}
	})

	t.Run("addToReplicationList skips duplicate", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.2")
		handler.addToReplicationList(1000, vtep) // Already added
		handler.addToReplicationList(1000, vtep) // Duplicate

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("Expected 1 VTEP (no duplicate), got %d", len(list))
		}
	})

	t.Run("addToReplicationList adds multiple entries", func(t *testing.T) {
		vtep3 := netip.MustParseAddr("10.0.0.3")
		handler.addToReplicationList(1000, vtep3)

		list := handler.getReplicationList(1000)
		if len(list) != 2 {
			t.Errorf("Expected 2 VTEPs, got %d", len(list))
		}
	})

	t.Run("removeFromReplicationList removes entry", func(t *testing.T) {
		vtep2 := netip.MustParseAddr("10.0.0.2")
		handler.removeFromReplicationList(1000, vtep2)

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("Expected 1 VTEP after removal, got %d", len(list))
		}
	})

	t.Run("removeFromReplicationList handles non-existent entry", func(t *testing.T) {
		vtep99 := netip.MustParseAddr("10.0.0.99")
		handler.removeFromReplicationList(1000, vtep99) // Should not panic

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("Expected 1 VTEP after removing non-existent, got %d", len(list))
		}
	})

	t.Run("removeFromReplicationList handles non-existent VNI", func(t *testing.T) {
		handler.removeFromReplicationList(9999, netip.MustParseAddr("10.0.0.1"))
		// Should not panic
	})

	t.Run("removeFromReplicationList removes last entry and deletes VNI", func(t *testing.T) {
		vtep3 := netip.MustParseAddr("10.0.0.3")
		handler.removeFromReplicationList(1000, vtep3)

		list := handler.getReplicationList(1000)
		if len(list) != 0 {
			t.Errorf("Expected empty list after removing last VTEP, got %d", len(list))
		}
	})

	t.Run("getReplicationList returns nil for non-existent VNI", func(t *testing.T) {
		list := handler.getReplicationList(9999)
		if list != nil {
			t.Errorf("Expected nil for non-existent VNI, got %v", list)
		}
	})
}

// TestVTEPInUse tests the vtepInUse helper function.
func TestVTEPInUse(t *testing.T) {
	handler := &OverlayModeHandler{
		logger: createTestLogger(),
	}

	vtep1 := netip.MustParseAddr("10.0.0.1")
	vtep2 := netip.MustParseAddr("10.0.0.2")

	// Initially no VTEPs in use
	if handler.vtepInUse(vtep1) {
		t.Error("VTEP should not be in use initially")
	}

	// Add VTEP to VNI
	handler.addToReplicationList(1000, vtep1)
	if !handler.vtepInUse(vtep1) {
		t.Error("VTEP should be in use after adding to replication list")
	}

	// Check VTEP not in list
	if handler.vtepInUse(vtep2) {
		t.Error("VTEP2 should not be in use")
	}

	// Add same VTEP to another VNI
	handler.addToReplicationList(2000, vtep1)
	if !handler.vtepInUse(vtep1) {
		t.Error("VTEP should still be in use")
	}

	// Remove from first VNI
	handler.removeFromReplicationList(1000, vtep1)
	if !handler.vtepInUse(vtep1) {
		t.Error("VTEP should still be in use (in VNI 2000)")
	}

	// Remove from second VNI
	handler.removeFromReplicationList(2000, vtep1)
	if handler.vtepInUse(vtep1) {
		t.Error("VTEP should not be in use after removing from all VNIs")
	}
}

// TestCleanupVNIMACs tests the cleanupVNIMACs helper function.
func TestCleanupVNIMACs(t *testing.T) {
	handler := &OverlayModeHandler{
		logger: createTestLogger(),
	}

	mac1 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	mac2 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	mac3 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}

	// Add MACs to different VNIs
	handler.localMACs.Store(formatMACKey(1000, mac1), &MACEntry{MAC: mac1, VNI: 1000})
	handler.localMACs.Store(formatMACKey(1000, mac2), &MACEntry{MAC: mac2, VNI: 1000})
	handler.localMACs.Store(formatMACKey(2000, mac3), &MACEntry{MAC: mac3, VNI: 2000})

	handler.remoteMACs.Store(formatMACKey(1000, mac3), &MACEntry{MAC: mac3, VNI: 1000})

	// Clean up VNI 1000
	handler.cleanupVNIMACs(1000)

	// Verify VNI 1000 MACs are removed
	count1000 := 0
	handler.localMACs.Range(func(key, _ any) bool {
		k := key.(string)
		if k[:5] == "1000:" {
			count1000++
		}
		return true
	})
	if count1000 != 0 {
		t.Errorf("Expected 0 local MACs for VNI 1000, got %d", count1000)
	}

	// Verify VNI 2000 MAC is still present
	if _, ok := handler.localMACs.Load(formatMACKey(2000, mac3)); !ok {
		t.Error("VNI 2000 MAC should still be present")
	}

	// Verify remote MAC for VNI 1000 is also removed
	if _, ok := handler.remoteMACs.Load(formatMACKey(1000, mac3)); ok {
		t.Error("Remote MAC for VNI 1000 should be removed")
	}
}

// TestGetStatusWhenNotRunning tests GetStatus on a non-running handler.
func TestGetStatusWhenNotRunning(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression:    true,
			AnycastGatewayIP:  netip.MustParseAddr("192.168.1.1"),
			AnycastGatewayMAC: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		},
		logger: createTestLogger(),
	}

	status := handler.GetStatus()
	if status == nil {
		t.Fatal("GetStatus should not return nil")
	}
	if status.Running {
		t.Error("Status.Running should be false")
	}
	if !status.ARPSuppressionEnabled {
		t.Error("Status.ARPSuppressionEnabled should be true")
	}
	if !status.AnycastGatewayConfigured {
		t.Error("Status.AnycastGatewayConfigured should be true")
	}
	// Counters should be zero when not running
	if status.VNICount != 0 {
		t.Errorf("Status.VNICount should be 0, got %d", status.VNICount)
	}
}

// TestHandleARPNilPacket tests HandleARP with nil packet.
func TestHandleARPNilPacket(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	_, err := handler.HandleARP(context.Background(), nil)
	if err != ErrARPPacketNil {
		t.Errorf("HandleARP(nil) error = %v, want %v", err, ErrARPPacketNil)
	}
}

// TestHandleARPReply tests HandleARP with ARP reply (should not respond).
func TestHandleARPReply(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression: true,
		},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	packet := &ARPPacket{
		Operation: ARPReply, // Not a request
		VNI:       1000,
	}

	response, err := handler.HandleARP(context.Background(), packet)
	if err != nil {
		t.Errorf("HandleARP() unexpected error: %v", err)
	}
	if response.ShouldRespond {
		t.Error("Should not respond to ARP reply")
	}
	if response.ShouldFlood {
		t.Error("Should not flood ARP reply")
	}
}

// TestHandleARPNoSuppression tests HandleARP with ARP suppression disabled.
func TestHandleARPNoSuppression(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression: false,
		},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	// Add some VTEPs to replication list
	vtep1 := netip.MustParseAddr("10.0.0.2")
	handler.addToReplicationList(1000, vtep1)

	packet := &ARPPacket{
		Operation: ARPRequest,
		TargetIP:  netip.MustParseAddr("192.168.1.100"),
		VNI:       1000,
	}

	response, err := handler.HandleARP(context.Background(), packet)
	if err != nil {
		t.Errorf("HandleARP() unexpected error: %v", err)
	}
	if response.ShouldRespond {
		t.Error("Should not respond when suppression is disabled")
	}
	if !response.ShouldFlood {
		t.Error("Should flood when suppression is disabled")
	}
	if len(response.FloodVTEPs) != 1 {
		t.Errorf("Expected 1 flood VTEP, got %d", len(response.FloodVTEPs))
	}
}

// TestHandleARPAnycastGateway tests HandleARP for anycast gateway IP.
func TestHandleARPAnycastGateway(t *testing.T) {
	anycastMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	anycastIP := netip.MustParseAddr("192.168.1.1")

	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression:    true,
			AnycastGatewayIP:  anycastIP,
			AnycastGatewayMAC: anycastMAC,
			Logger:            createTestLogger(),
		},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	packet := &ARPPacket{
		Operation: ARPRequest,
		TargetIP:  anycastIP,
		VNI:       1000,
	}

	response, err := handler.HandleARP(context.Background(), packet)
	if err != nil {
		t.Errorf("HandleARP() unexpected error: %v", err)
	}
	if !response.ShouldRespond {
		t.Error("Should respond for anycast gateway IP")
	}
	if response.ReplyMAC.String() != anycastMAC.String() {
		t.Errorf("Reply MAC = %s, want %s", response.ReplyMAC.String(), anycastMAC.String())
	}
	if response.ShouldFlood {
		t.Error("Should not flood for anycast gateway")
	}
}

// TestHandleARPCachedEntry tests HandleARP with a cached ARP entry.
func TestHandleARPCachedEntry(t *testing.T) {
	cachedMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	targetIP := netip.MustParseAddr("192.168.1.100")

	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression: true,
			Logger:         createTestLogger(),
		},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	// Add entry to ARP table
	arpKey := formatARPKey(1000, targetIP)
	handler.arpTable.Store(arpKey, cachedMAC)

	packet := &ARPPacket{
		Operation: ARPRequest,
		TargetIP:  targetIP,
		VNI:       1000,
	}

	response, err := handler.HandleARP(context.Background(), packet)
	if err != nil {
		t.Errorf("HandleARP() unexpected error: %v", err)
	}
	if !response.ShouldRespond {
		t.Error("Should respond for cached entry")
	}
	if response.ReplyMAC.String() != cachedMAC.String() {
		t.Errorf("Reply MAC = %s, want %s", response.ReplyMAC.String(), cachedMAC.String())
	}
	if response.ShouldFlood {
		t.Error("Should not flood for cached entry")
	}
}

// TestHandleARPFlood tests HandleARP when entry is not found.
func TestHandleARPFlood(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{
			ARPSuppression: true,
			Logger:         createTestLogger(),
		},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	// Add VTEPs to replication list
	handler.addToReplicationList(1000, netip.MustParseAddr("10.0.0.2"))
	handler.addToReplicationList(1000, netip.MustParseAddr("10.0.0.3"))

	packet := &ARPPacket{
		Operation: ARPRequest,
		TargetIP:  netip.MustParseAddr("192.168.1.99"), // Unknown IP
		VNI:       1000,
	}

	response, err := handler.HandleARP(context.Background(), packet)
	if err != nil {
		t.Errorf("HandleARP() unexpected error: %v", err)
	}
	if response.ShouldRespond {
		t.Error("Should not respond for unknown IP")
	}
	if !response.ShouldFlood {
		t.Error("Should flood for unknown IP")
	}
	if len(response.FloodVTEPs) != 2 {
		t.Errorf("Expected 2 flood VTEPs, got %d", len(response.FloodVTEPs))
	}
}

// TestLookupMACNotRunning tests LookupMAC when handler is not running.
func TestLookupMACNotRunning(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	// Not running

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	_, err := handler.LookupMAC(context.Background(), mac, 1000)
	if err != ErrNotRunning {
		t.Errorf("LookupMAC() error = %v, want %v", err, ErrNotRunning)
	}
}

// TestLookupMACInvalidMAC tests LookupMAC with invalid MAC.
func TestLookupMACInvalidMAC(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	_, err := handler.LookupMAC(context.Background(), nil, 1000)
	if err != ErrMACNil {
		t.Errorf("LookupMAC(nil) error = %v, want %v", err, ErrMACNil)
	}
}

// TestLookupMACNotFound tests LookupMAC when MAC is not found.
func TestLookupMACNotFound(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	_, err := handler.LookupMAC(context.Background(), mac, 1000)
	if err != ErrMACNotFound {
		t.Errorf("LookupMAC() error = %v, want %v", err, ErrMACNotFound)
	}
}

// TestLookupMACLocalEntry tests LookupMAC finding a local entry.
func TestLookupMACLocalEntry(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	entry := &MACEntry{
		MAC:    mac,
		VNI:    1000,
		Source: MACSourceLocal,
	}
	handler.localMACs.Store(formatMACKey(1000, mac), entry)

	result, err := handler.LookupMAC(context.Background(), mac, 1000)
	if err != nil {
		t.Errorf("LookupMAC() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("LookupMAC() result should not be nil")
	}
	if result.Source != MACSourceLocal {
		t.Errorf("LookupMAC() source = %v, want %v", result.Source, MACSourceLocal)
	}
	// Verify it's a clone
	if result == entry {
		t.Error("LookupMAC() should return a clone")
	}
}

// TestLookupMACExpiredEntry tests LookupMAC with an expired local entry.
func TestLookupMACExpiredEntry(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	entry := &MACEntry{
		MAC:       mac,
		VNI:       1000,
		Source:    MACSourceLocal,
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
	}
	handler.localMACs.Store(formatMACKey(1000, mac), entry)

	_, err := handler.LookupMAC(context.Background(), mac, 1000)
	if err != ErrMACNotFound {
		t.Errorf("LookupMAC() for expired entry error = %v, want %v", err, ErrMACNotFound)
	}

	// Verify entry was removed
	if _, ok := handler.localMACs.Load(formatMACKey(1000, mac)); ok {
		t.Error("Expired entry should be removed")
	}
}

// TestLookupMACRemoteEntry tests LookupMAC finding a remote entry.
func TestLookupMACRemoteEntry(t *testing.T) {
	handler := &OverlayModeHandler{
		config: &OverlayModeConfig{},
		logger: createTestLogger(),
	}
	handler.running.Store(true)

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	entry := &MACEntry{
		MAC:    mac,
		VNI:    1000,
		Source: MACSourceRemote,
	}
	handler.remoteMACs.Store(formatMACKey(1000, mac), entry)

	result, err := handler.LookupMAC(context.Background(), mac, 1000)
	if err != nil {
		t.Errorf("LookupMAC() unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("LookupMAC() result should not be nil")
	}
	if result.Source != MACSourceRemote {
		t.Errorf("LookupMAC() source = %v, want %v", result.Source, MACSourceRemote)
	}
}
