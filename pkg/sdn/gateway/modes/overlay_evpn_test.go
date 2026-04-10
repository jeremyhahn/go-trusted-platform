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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// TestOverlayModeHandler_HandleEVPNRoute tests the handleEVPNRoute method.
func TestOverlayModeHandler_HandleEVPNRoute(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	t.Run("nil route returns nil", func(t *testing.T) {
		err := handler.handleEVPNRoute(ctx, nil)
		if err != nil {
			t.Errorf("expected nil error for nil route, got: %v", err)
		}
	})

	t.Run("unknown route type returns nil", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNRouteType(255), // Unknown type
		}
		err := handler.handleEVPNRoute(ctx, route)
		if err != nil {
			t.Errorf("expected nil error for unknown route type, got: %v", err)
		}
	})

	t.Run("type-2 MAC/IP advertisement", func(t *testing.T) {
		mac := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
		ip := netip.MustParseAddr("192.168.1.50")
		vtep := netip.MustParseAddr("10.0.0.5")

		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				IP:     ip,
				VNI:    1000,
				VTEPIP: vtep,
			},
		}
		err := handler.handleEVPNRoute(ctx, route)
		if err != nil {
			t.Errorf("handleEVPNRoute() error: %v", err)
		}

		// Verify MAC was learned
		key := formatMACKey(1000, mac)
		if _, ok := handler.remoteMACs.Load(key); !ok {
			t.Error("MAC should have been learned from Type-2 route")
		}
	})

	t.Run("type-3 inclusive multicast", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.10")

		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeInclusiveMulticast,
			IMET: &bgp.IMETEntry{
				VNI:    1000,
				VTEPIP: vtep,
			},
		}
		err := handler.handleEVPNRoute(ctx, route)
		if err != nil {
			t.Errorf("handleEVPNRoute() error: %v", err)
		}

		// Verify VTEP was added to replication list
		list := handler.getReplicationList(1000)
		found := false
		for _, v := range list {
			if v == vtep {
				found = true
				break
			}
		}
		if !found {
			t.Error("VTEP should have been added to replication list from Type-3 route")
		}
	})

	t.Run("type-5 IP prefix", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type:    bgp.EVPNTypeIPPrefix,
			NextHop: netip.MustParseAddr("10.0.0.20"),
			PrefixData: &bgp.PrefixRoute{
				Prefix: netip.MustParsePrefix("172.16.0.0/24"),
				VNI:    1000,
			},
		}
		err := handler.handleEVPNRoute(ctx, route)
		if err != nil {
			t.Errorf("handleEVPNRoute() error: %v", err)
		}
		// Type-5 routes are logged but not stored in memory (handled at L3)
	})
}

// TestOverlayModeHandler_HandleType2Route tests the handleType2Route method.
func TestOverlayModeHandler_HandleType2Route(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	t.Run("nil MACIP returns nil", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type:  bgp.EVPNTypeMACIPAdvertisement,
			MACIP: nil,
		}
		err := handler.handleType2Route(ctx, route)
		if err != nil {
			t.Errorf("expected nil error for nil MACIP, got: %v", err)
		}
	})

	t.Run("learn new MAC", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
		ip := netip.MustParseAddr("192.168.1.101")
		vtep := netip.MustParseAddr("10.0.0.50")

		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				IP:     ip,
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: false,
		}
		err := handler.handleType2Route(ctx, route)
		if err != nil {
			t.Errorf("handleType2Route() error: %v", err)
		}

		// Verify MAC was learned
		key := formatMACKey(1000, mac)
		if _, ok := handler.remoteMACs.Load(key); !ok {
			t.Error("MAC should have been learned")
		}

		// Verify ARP entry
		arpKey := formatARPKey(1000, ip)
		if _, ok := handler.arpTable.Load(arpKey); !ok {
			t.Error("ARP entry should have been created")
		}
	})

	t.Run("withdraw MAC", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
		ip := netip.MustParseAddr("192.168.1.102")
		vtep := netip.MustParseAddr("10.0.0.51")

		// First learn the MAC
		learnRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				IP:     ip,
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: false,
		}
		err := handler.handleType2Route(ctx, learnRoute)
		if err != nil {
			t.Fatalf("failed to learn MAC: %v", err)
		}

		// Verify MAC exists
		key := formatMACKey(1000, mac)
		if _, ok := handler.remoteMACs.Load(key); !ok {
			t.Fatal("MAC should exist before withdrawal")
		}

		// Now withdraw
		withdrawRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				IP:     ip,
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: true,
		}
		err = handler.handleType2Route(ctx, withdrawRoute)
		if err != nil {
			t.Errorf("handleType2Route() withdraw error: %v", err)
		}

		// Verify MAC was removed
		if _, ok := handler.remoteMACs.Load(key); ok {
			t.Error("MAC should have been withdrawn")
		}

		// Verify ARP entry was removed
		arpKey := formatARPKey(1000, ip)
		if _, ok := handler.arpTable.Load(arpKey); ok {
			t.Error("ARP entry should have been removed")
		}
	})

	t.Run("withdraw MAC without IP", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}
		vtep := netip.MustParseAddr("10.0.0.52")

		// First learn the MAC (without IP)
		learnRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: false,
		}
		err := handler.handleType2Route(ctx, learnRoute)
		if err != nil {
			t.Fatalf("failed to learn MAC: %v", err)
		}

		// Now withdraw
		withdrawRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeMACIPAdvertisement,
			MACIP: &bgp.MACIPEntry{
				MAC:    mac,
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: true,
		}
		err = handler.handleType2Route(ctx, withdrawRoute)
		if err != nil {
			t.Errorf("handleType2Route() withdraw error: %v", err)
		}

		// Verify MAC was removed
		key := formatMACKey(1000, mac)
		if _, ok := handler.remoteMACs.Load(key); ok {
			t.Error("MAC should have been withdrawn")
		}
	})
}

// TestOverlayModeHandler_HandleType3Route tests the handleType3Route method.
func TestOverlayModeHandler_HandleType3Route(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	t.Run("nil IMET returns nil", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeInclusiveMulticast,
			IMET: nil,
		}
		err := handler.handleType3Route(ctx, route)
		if err != nil {
			t.Errorf("expected nil error for nil IMET, got: %v", err)
		}
	})

	t.Run("add VTEP to replication list", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.100")

		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeInclusiveMulticast,
			IMET: &bgp.IMETEntry{
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: false,
		}
		err := handler.handleType3Route(ctx, route)
		if err != nil {
			t.Errorf("handleType3Route() error: %v", err)
		}

		// Verify VTEP was added
		list := handler.getReplicationList(1000)
		found := false
		for _, v := range list {
			if v == vtep {
				found = true
				break
			}
		}
		if !found {
			t.Error("VTEP should be in replication list")
		}
	})

	t.Run("withdraw VTEP from replication list", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.101")

		// First add
		addRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeInclusiveMulticast,
			IMET: &bgp.IMETEntry{
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: false,
		}
		err := handler.handleType3Route(ctx, addRoute)
		if err != nil {
			t.Fatalf("failed to add VTEP: %v", err)
		}

		// Now withdraw
		withdrawRoute := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeInclusiveMulticast,
			IMET: &bgp.IMETEntry{
				VNI:    1000,
				VTEPIP: vtep,
			},
			IsWithdraw: true,
		}
		err = handler.handleType3Route(ctx, withdrawRoute)
		if err != nil {
			t.Errorf("handleType3Route() withdraw error: %v", err)
		}

		// Verify VTEP was removed
		list := handler.getReplicationList(1000)
		for _, v := range list {
			if v == vtep {
				t.Error("VTEP should have been removed from replication list")
			}
		}
	})
}

// TestOverlayModeHandler_HandleType5Route tests the handleType5Route method.
func TestOverlayModeHandler_HandleType5Route(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	t.Run("nil PrefixData returns nil", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type:       bgp.EVPNTypeIPPrefix,
			PrefixData: nil,
		}
		err := handler.handleType5Route(ctx, route)
		if err != nil {
			t.Errorf("expected nil error for nil PrefixData, got: %v", err)
		}
	})

	t.Run("receive Type-5 route", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type:    bgp.EVPNTypeIPPrefix,
			NextHop: netip.MustParseAddr("10.0.0.200"),
			PrefixData: &bgp.PrefixRoute{
				Prefix: netip.MustParsePrefix("10.100.0.0/16"),
				VNI:    2000,
			},
			IsWithdraw: false,
		}
		err := handler.handleType5Route(ctx, route)
		if err != nil {
			t.Errorf("handleType5Route() error: %v", err)
		}
	})

	t.Run("withdraw Type-5 route", func(t *testing.T) {
		route := &bgp.EVPNRouteData{
			Type: bgp.EVPNTypeIPPrefix,
			PrefixData: &bgp.PrefixRoute{
				Prefix: netip.MustParsePrefix("10.100.0.0/16"),
				VNI:    2000,
			},
			IsWithdraw: true,
		}
		err := handler.handleType5Route(ctx, route)
		if err != nil {
			t.Errorf("handleType5Route() withdraw error: %v", err)
		}
	})
}

// TestOverlayModeHandler_RemoveRemoteMACFlow tests the removeRemoteMACFlow method.
func TestOverlayModeHandler_RemoveRemoteMACFlow(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	t.Run("remove MAC flow success", func(t *testing.T) {
		mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
		err := handler.removeRemoteMACFlow(ctx, 1000, mac)
		if err != nil {
			t.Errorf("removeRemoteMACFlow() error: %v", err)
		}

		// Verify flow was deleted
		if ofClient.delFlowCount.Load() == 0 {
			t.Error("expected flow deletion")
		}
	})

	t.Run("remove MAC flow with error", func(t *testing.T) {
		ofClient.delFlowErr = errMockError
		defer func() { ofClient.delFlowErr = nil }()

		mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
		err := handler.removeRemoteMACFlow(ctx, 1000, mac)
		if err == nil {
			t.Error("expected error when flow deletion fails")
		}
	})
}

// TestOverlayModeHandler_InstallAnycastGatewayFlows tests the installAnycastGatewayFlows method.
func TestOverlayModeHandler_InstallAnycastGatewayFlows(t *testing.T) {
	config := createTestOverlayConfig()
	config.AnycastGatewayIP = netip.MustParseAddr("192.168.1.1")
	config.AnycastGatewayMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	handler, err := NewOverlayModeHandler(config, ovsClient, ofClient)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	// Set running state manually for test
	handler.running.Store(true)
	handler.startedAt = time.Now()

	t.Run("install anycast flows success", func(t *testing.T) {
		initialCount := ofClient.addFlowCount.Load()
		err := handler.installAnycastGatewayFlows(ctx)
		if err != nil {
			t.Errorf("installAnycastGatewayFlows() error: %v", err)
		}

		// Should install 2 flows (ARP responder + L3 routing)
		flowsAdded := ofClient.addFlowCount.Load() - initialCount
		if flowsAdded != 2 {
			t.Errorf("expected 2 flows added, got %d", flowsAdded)
		}
	})

	t.Run("install anycast flows with error", func(t *testing.T) {
		ofClient.addFlowErr = errMockError
		defer func() { ofClient.addFlowErr = nil }()

		err := handler.installAnycastGatewayFlows(ctx)
		if err == nil {
			t.Error("expected error when flow installation fails")
		}
	})
}

// TestOverlayModeHandler_InstallOpenFlowPipeline tests the installOpenFlowPipeline method.
func TestOverlayModeHandler_InstallOpenFlowPipeline(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()
	handler.running.Store(true)
	handler.startedAt = time.Now()

	t.Run("install pipeline success", func(t *testing.T) {
		err := handler.installOpenFlowPipeline(ctx)
		if err != nil {
			t.Errorf("installOpenFlowPipeline() error: %v", err)
		}

		// Should install multiple flows for the pipeline tables
		if ofClient.addFlowCount.Load() == 0 {
			t.Error("expected flows to be installed")
		}
	})

	t.Run("install pipeline with first flow error", func(t *testing.T) {
		ofClient.addFlowErr = errMockError
		defer func() { ofClient.addFlowErr = nil }()

		err := handler.installOpenFlowPipeline(ctx)
		if err == nil {
			t.Error("expected error when flow installation fails")
		}
	})
}

// TestOverlayModeHandler_InstallOpenFlowPipelineWithAnycast tests pipeline with anycast gateway.
func TestOverlayModeHandler_InstallOpenFlowPipelineWithAnycast(t *testing.T) {
	config := createTestOverlayConfig()
	config.AnycastGatewayIP = netip.MustParseAddr("192.168.1.1")
	config.AnycastGatewayMAC = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	handler, err := NewOverlayModeHandler(config, ovsClient, ofClient)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	handler.running.Store(true)
	handler.startedAt = time.Now()

	t.Run("install pipeline with anycast", func(t *testing.T) {
		err := handler.installOpenFlowPipeline(ctx)
		if err != nil {
			t.Errorf("installOpenFlowPipeline() error: %v", err)
		}

		// Should install base pipeline + anycast flows
		if ofClient.addFlowCount.Load() < 8 { // 6 base + 2 anycast
			t.Errorf("expected at least 8 flows for pipeline with anycast, got %d", ofClient.addFlowCount.Load())
		}
	})
}

// TestOverlayModeHandler_LookupMAC tests the LookupMAC method.
func TestOverlayModeHandler_LookupMAC(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Learn a MAC
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	ip := netip.MustParseAddr("192.168.1.100")
	localVTEP := handler.config.VTEPConfig.LocalIP
	err = handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
	if err != nil {
		t.Fatalf("LearnMAC() error: %v", err)
	}

	t.Run("lookup existing local MAC", func(t *testing.T) {
		entry, err := handler.LookupMAC(ctx, mac, 1000)
		if err != nil {
			t.Errorf("LookupMAC() error: %v", err)
		}
		if entry == nil {
			t.Fatal("expected entry to be non-nil")
		}
		if entry.Source != MACSourceLocal {
			t.Errorf("expected local source, got %v", entry.Source)
		}
	})

	t.Run("lookup non-existent MAC", func(t *testing.T) {
		unknownMAC := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
		_, err := handler.LookupMAC(ctx, unknownMAC, 1000)
		if err != ErrMACNotFound {
			t.Errorf("expected ErrMACNotFound, got: %v", err)
		}
	})

	t.Run("lookup in wrong VNI", func(t *testing.T) {
		_, err := handler.LookupMAC(ctx, mac, 9999)
		if err != ErrMACNotFound {
			t.Errorf("expected ErrMACNotFound for wrong VNI, got: %v", err)
		}
	})

	t.Run("lookup nil MAC", func(t *testing.T) {
		_, err := handler.LookupMAC(ctx, nil, 1000)
		if err != ErrMACNil {
			t.Errorf("expected ErrMACNil, got: %v", err)
		}
	})

	t.Run("lookup invalid MAC length", func(t *testing.T) {
		shortMAC := net.HardwareAddr{0xaa, 0xbb}
		_, err := handler.LookupMAC(ctx, shortMAC, 1000)
		if err != ErrMACInvalid {
			t.Errorf("expected ErrMACInvalid, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_LookupMAC_NotRunning tests LookupMAC when not running.
func TestOverlayModeHandler_LookupMAC_NotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	_, err := handler.LookupMAC(ctx, mac, 1000)
	if err != ErrNotRunning {
		t.Errorf("expected ErrNotRunning, got: %v", err)
	}
}

// TestOverlayModeHandler_StartComponents tests Start with component initialization.
func TestOverlayModeHandler_StartComponents(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()

	t.Run("start installs OpenFlow pipeline", func(t *testing.T) {
		err := handler.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}
		defer handler.Stop(ctx)

		// Verify flows were installed for pipeline
		if ofClient.addFlowCount.Load() == 0 {
			t.Error("expected pipeline flows to be installed")
		}
	})
}

// TestOverlayModeHandler_StartWithFlowError tests Start when flow installation fails.
func TestOverlayModeHandler_StartWithFlowError(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()

	// Set error before start
	ofClient.addFlowErr = errMockError

	err := handler.Start(ctx)
	if err == nil {
		t.Error("expected error when pipeline installation fails")
	}

	// Handler should not be running
	if handler.running.Load() {
		t.Error("handler should not be running after failed start")
	}
}

// TestOverlayModeHandler_StopComponents tests Stop with component cleanup.
func TestOverlayModeHandler_StopComponents(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Add some VNIs
	handler.AddVNI(ctx, 1000, 100)
	handler.AddVNI(ctx, 2000, 200)

	// Stop should clean up
	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	if handler.running.Load() {
		t.Error("handler should not be running after stop")
	}
}

// errMockError is a mock error for testing.
var errMockError = &mockError{msg: "mock error"}

// mockError implements error for testing.
type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// TestOverlayModeHandler_GetStatusNotRunning tests GetStatus when not running.
func TestOverlayModeHandler_GetStatusNotRunning(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	status := handler.GetStatus()
	if status == nil {
		t.Fatal("GetStatus() should not return nil")
	}
	if status.Running {
		t.Error("status.Running should be false when not started")
	}
	if status.VNICount != 0 {
		t.Errorf("expected VNICount 0, got %d", status.VNICount)
	}
}

// TestOverlayModeHandler_CleanupVNIMACs tests the cleanupVNIMACs method.
func TestOverlayModeHandler_CleanupVNIMACs(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Learn some MACs
	localVTEP := handler.config.VTEPConfig.LocalIP
	for i := 0; i < 5; i++ {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}
		ip := netip.MustParseAddr("192.168.1.100")
		handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
	}

	// Verify MACs exist
	count := 0
	handler.localMACs.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 5 {
		t.Fatalf("expected 5 local MACs, got %d", count)
	}

	// Cleanup
	handler.cleanupVNIMACs(1000)

	// Verify MACs are removed
	count = 0
	handler.localMACs.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 local MACs after cleanup, got %d", count)
	}
}

// TestOverlayModeHandler_ReplicationListOperations tests replication list operations.
func TestOverlayModeHandler_ReplicationListOperations(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	t.Run("get empty replication list", func(t *testing.T) {
		list := handler.getReplicationList(9999)
		if list != nil {
			t.Errorf("expected nil for non-existent VNI, got %v", list)
		}
	})

	t.Run("add to replication list", func(t *testing.T) {
		vtep1 := netip.MustParseAddr("10.0.0.1")
		vtep2 := netip.MustParseAddr("10.0.0.2")

		handler.addToReplicationList(1000, vtep1)
		handler.addToReplicationList(1000, vtep2)

		list := handler.getReplicationList(1000)
		if len(list) != 2 {
			t.Errorf("expected 2 VTEPs, got %d", len(list))
		}
	})

	t.Run("add duplicate to replication list", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.1")

		// Should not add duplicate
		handler.addToReplicationList(1000, vtep)

		list := handler.getReplicationList(1000)
		if len(list) != 2 {
			t.Errorf("expected 2 VTEPs (no duplicate), got %d", len(list))
		}
	})

	t.Run("remove from replication list", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.1")

		handler.removeFromReplicationList(1000, vtep)

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("expected 1 VTEP after removal, got %d", len(list))
		}
	})

	t.Run("remove non-existent from replication list", func(t *testing.T) {
		vtep := netip.MustParseAddr("10.0.0.99")

		// Should not panic
		handler.removeFromReplicationList(1000, vtep)

		list := handler.getReplicationList(1000)
		if len(list) != 1 {
			t.Errorf("expected 1 VTEP (unchanged), got %d", len(list))
		}
	})
}

// TestOverlayModeHandler_VTEPInUse tests the vtepInUse method.
func TestOverlayModeHandler_VTEPInUse(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	vtep := netip.MustParseAddr("10.0.0.50")

	t.Run("VTEP not in use", func(t *testing.T) {
		if handler.vtepInUse(vtep) {
			t.Error("VTEP should not be in use initially")
		}
	})

	t.Run("VTEP in use after adding to replication list", func(t *testing.T) {
		handler.addToReplicationList(1000, vtep)

		if !handler.vtepInUse(vtep) {
			t.Error("VTEP should be in use after adding to replication list")
		}
	})

	t.Run("VTEP not in use after removal", func(t *testing.T) {
		handler.removeFromReplicationList(1000, vtep)

		if handler.vtepInUse(vtep) {
			t.Error("VTEP should not be in use after removal")
		}
	})
}

// TestOverlayModeHandler_FormatHelpers tests the format helper functions.
func TestOverlayModeHandler_FormatHelpers(t *testing.T) {
	t.Run("formatMACKey", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		key := formatMACKey(1000, mac)
		if key == "" {
			t.Error("key should not be empty")
		}
	})

	t.Run("formatARPKey", func(t *testing.T) {
		ip := netip.MustParseAddr("192.168.1.100")
		key := formatARPKey(1000, ip)
		if key == "" {
			t.Error("key should not be empty")
		}
	})

	t.Run("formatVNIPrefix", func(t *testing.T) {
		prefix := formatVNIPrefix(1000)
		if prefix == "" {
			t.Error("prefix should not be empty")
		}
	})

	t.Run("formatUint32", func(t *testing.T) {
		s := formatUint32(12345)
		if s != "12345" {
			t.Errorf("expected '12345', got '%s'", s)
		}
	})
}

// TestOverlayModeHandler_EncodeVLAN tests the encodeVLAN function.
func TestOverlayModeHandler_EncodeVLAN(t *testing.T) {
	t.Run("encode VLAN 100", func(t *testing.T) {
		encoded := encodeVLAN(100)
		if len(encoded) != 2 {
			t.Errorf("expected 2 bytes, got %d", len(encoded))
		}
		// VLAN 100 with CFI bit set: 0x1064
		expected := uint16(100) | 0x1000
		got := uint16(encoded[0])<<8 | uint16(encoded[1])
		if got != expected {
			t.Errorf("expected 0x%04X, got 0x%04X", expected, got)
		}
	})

	t.Run("encode VLAN 0", func(t *testing.T) {
		encoded := encodeVLAN(0)
		expected := uint16(0) | 0x1000
		got := uint16(encoded[0])<<8 | uint16(encoded[1])
		if got != expected {
			t.Errorf("expected 0x%04X, got 0x%04X", expected, got)
		}
	})

	t.Run("encode VLAN 4094", func(t *testing.T) {
		encoded := encodeVLAN(4094)
		expected := uint16(4094) | 0x1000
		got := uint16(encoded[0])<<8 | uint16(encoded[1])
		if got != expected {
			t.Errorf("expected 0x%04X, got 0x%04X", expected, got)
		}
	})
}

// TestOverlayModeHandler_ValidateMAC tests the validateMAC function.
func TestOverlayModeHandler_ValidateMAC(t *testing.T) {
	t.Run("valid MAC", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
		err := validateMAC(mac)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("nil MAC", func(t *testing.T) {
		err := validateMAC(nil)
		if err != ErrMACNil {
			t.Errorf("expected ErrMACNil, got: %v", err)
		}
	})

	t.Run("short MAC", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb}
		err := validateMAC(mac)
		if err != ErrMACInvalid {
			t.Errorf("expected ErrMACInvalid, got: %v", err)
		}
	})

	t.Run("long MAC (EUI-64) is invalid", func(t *testing.T) {
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
		err := validateMAC(mac)
		// Standard Ethernet MACs are 6 bytes, EUI-64 (8-byte) is not supported
		if err == nil {
			t.Error("expected error for EUI-64 MAC, but got nil")
		}
	})
}

// TestOverlayModeHandler_ValidateVNI tests the validateVNI function.
func TestOverlayModeHandler_ValidateVNI(t *testing.T) {
	t.Run("valid VNI", func(t *testing.T) {
		err := validateVNI(1000)
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
	})

	t.Run("VNI 0 invalid", func(t *testing.T) {
		err := validateVNI(0)
		if err != ErrVNIOutOfRange {
			t.Errorf("expected ErrVNIOutOfRange, got: %v", err)
		}
	})

	t.Run("VNI too large", func(t *testing.T) {
		err := validateVNI(16777216) // 2^24
		if err != ErrVNIOutOfRange {
			t.Errorf("expected ErrVNIOutOfRange, got: %v", err)
		}
	})

	t.Run("VNI max valid", func(t *testing.T) {
		err := validateVNI(16777215) // 2^24 - 1
		if err != nil {
			t.Errorf("expected no error for max VNI, got: %v", err)
		}
	})

	t.Run("VNI 1 valid", func(t *testing.T) {
		err := validateVNI(1)
		if err != nil {
			t.Errorf("expected no error for min VNI, got: %v", err)
		}
	})
}

// TestOverlayModeHandler_StartWithEVPN tests Start with EVPN manager.
func TestOverlayModeHandler_StartWithEVPN(t *testing.T) {
	config := createTestOverlayConfig()
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()

	handler, err := NewOverlayModeHandler(config, ovsClient, ofClient)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	ctx := context.Background()
	err = handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Verify handler started
	if !handler.running.Load() {
		t.Error("expected handler to be running")
	}

	// Stop and verify cleanup
	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	if handler.running.Load() {
		t.Error("expected handler to be stopped")
	}
}

// TestOverlayModeHandler_StopIdempotent tests that Stop is idempotent.
func TestOverlayModeHandler_StopIdempotent(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Stop twice
	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("first Stop() error: %v", err)
	}

	err = handler.Stop(ctx)
	if err != nil {
		t.Errorf("second Stop() should also succeed: %v", err)
	}
}

// TestOverlayModeHandler_NewWithNilConfig tests NewOverlayModeHandler with nil config.
func TestOverlayModeHandler_NewWithNilConfig(t *testing.T) {
	_, err := NewOverlayModeHandler(nil, nil, nil)
	if err != ErrConfigNil {
		t.Errorf("expected ErrConfigNil, got: %v", err)
	}
}

// TestOverlayModeHandler_NewWithNilOVS tests NewOverlayModeHandler with nil OVS client.
func TestOverlayModeHandler_NewWithNilOVS(t *testing.T) {
	config := createTestOverlayConfig()
	_, err := NewOverlayModeHandler(config, nil, nil)
	if err != ErrOVSClientNil {
		t.Errorf("expected ErrOVSClientNil, got: %v", err)
	}
}

// TestOverlayModeHandler_NewWithNilOpenFlow tests NewOverlayModeHandler with nil OpenFlow client.
func TestOverlayModeHandler_NewWithNilOpenFlow(t *testing.T) {
	config := createTestOverlayConfig()
	ovsClient := newMockOVSClient()
	_, err := NewOverlayModeHandler(config, ovsClient, nil)
	if err != ErrOpenFlowClientNil {
		t.Errorf("expected ErrOpenFlowClientNil, got: %v", err)
	}
}

// TestOverlayModeHandler_LearnMAC_LocalVTEP tests learning a MAC from local VTEP.
func TestOverlayModeHandler_LearnMAC_LocalVTEP(t *testing.T) {
	handler, _, _ := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Learn a MAC from local VTEP
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	ip := netip.MustParseAddr("192.168.1.10")
	localVTEP := handler.config.VTEPConfig.LocalIP

	err = handler.LearnMAC(ctx, mac, ip, 1000, localVTEP)
	if err != nil {
		t.Errorf("LearnMAC() error: %v", err)
	}

	// Verify MAC was learned as local
	entry, err := handler.LookupMAC(ctx, mac, 1000)
	if err != nil {
		t.Errorf("LookupMAC() error: %v", err)
	}
	if entry.Source != MACSourceLocal {
		t.Errorf("expected local source, got %v", entry.Source)
	}
}

// TestOverlayModeHandler_LearnMAC_RemoteVTEP tests learning a MAC from remote VTEP.
func TestOverlayModeHandler_LearnMAC_RemoteVTEP(t *testing.T) {
	handler, _, ofClient := createTestHandlerWithMocks(t)

	ctx := context.Background()
	err := handler.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer handler.Stop(ctx)

	// Add VNI first
	err = handler.AddVNI(ctx, 1000, 100)
	if err != nil {
		t.Fatalf("AddVNI() error: %v", err)
	}

	// Learn a MAC from remote VTEP
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	ip := netip.MustParseAddr("192.168.1.20")
	remoteVTEP := netip.MustParseAddr("10.0.0.100")

	initialFlowCount := ofClient.addFlowCount.Load()

	err = handler.LearnMAC(ctx, mac, ip, 1000, remoteVTEP)
	if err != nil {
		t.Errorf("LearnMAC() error: %v", err)
	}

	// Verify flow was installed for remote MAC
	if ofClient.addFlowCount.Load() <= initialFlowCount {
		t.Error("expected flow to be installed for remote MAC")
	}
}
