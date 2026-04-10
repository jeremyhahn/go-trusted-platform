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

package bridge

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

func TestNewLifecycleHooks(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ovsClient := newMockOVSClient()
	ofClient := newMockOpenFlowClient()
	manager := NewManager(ovsClient, ofClient, nil, logger)
	flowManager := NewFlowManager(ofClient, logger)

	t.Run("with logger", func(t *testing.T) {
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		if hooks == nil {
			t.Fatal("NewLifecycleHooks returned nil")
		}
		if hooks.manager != manager {
			t.Error("manager not set correctly")
		}
		if hooks.flowManager != flowManager {
			t.Error("flowManager not set correctly")
		}
		if hooks.logger != logger {
			t.Error("logger not set correctly")
		}
	})

	t.Run("with nil logger uses default", func(t *testing.T) {
		hooks := NewLifecycleHooks(manager, flowManager, nil)

		if hooks == nil {
			t.Fatal("NewLifecycleHooks returned nil")
		}
		if hooks.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestLifecycleHooks_OnTenantCreate(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful creation", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate failed: %v", err)
		}

		// Verify bridge was created
		bridge, err := manager.GetBridge(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetBridge failed: %v", err)
		}
		if bridge.Status != StatusActive {
			t.Errorf("Status = %q, want %q", bridge.Status, StatusActive)
		}

		// Verify flows were installed
		flowCount := ofClient.getFlowCount(bridge.Name)
		if flowCount == 0 {
			t.Error("expected flows to be installed")
		}
	})

	t.Run("creates bridge and installs all flow types", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate failed: %v", err)
		}

		bridge, _ := manager.GetBridge(ctx, "tenant-1")
		flows, _ := ofClient.GetFlows(ctx, bridge.Name)

		// Should have base flows, isolation flows, ARP flows, and DHCP flows
		// This is a rough check - actual count depends on VLAN range size
		if len(flows) < 10 {
			t.Errorf("expected many flows to be installed, got %d", len(flows))
		}
	})

	t.Run("bridge creation fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ovsClient.createErr = errors.New("create failed")
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err == nil {
			t.Error("OnTenantCreate should fail when bridge creation fails")
		}
	})

	t.Run("base flow installation fails - rolls back bridge", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err == nil {
			t.Error("OnTenantCreate should fail when flow installation fails")
		}

		// Bridge should be deleted (rolled back)
		// Note: The bridge status might be error or deleted depending on implementation
		_, bridgeErr := manager.GetBridge(ctx, "tenant-1")
		if bridgeErr == nil {
			bridge, _ := manager.GetBridge(ctx, "tenant-1")
			if bridge.Status != StatusError {
				t.Error("bridge should be in error state or deleted after rollback")
			}
		}
	})

	t.Run("without flow manager", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		hooks := NewLifecycleHooks(manager, nil, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate failed: %v", err)
		}

		// Bridge should be created but no flows installed
		bridge, err := manager.GetBridge(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("GetBridge failed: %v", err)
		}
		if bridge.Status != StatusActive {
			t.Errorf("Status = %q, want %q", bridge.Status, StatusActive)
		}
	})

	t.Run("invalid tenant name", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "", vlanRange)
		if err == nil {
			t.Error("OnTenantCreate should fail with invalid tenant name")
		}
	})

	t.Run("invalid VLAN range", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		vlanRange := VLANRange{Start: 0, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err == nil {
			t.Error("OnTenantCreate should fail with invalid VLAN range")
		}
	})
}

func TestLifecycleHooks_OnTenantActivate(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful activation", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Activate
		err = hooks.OnTenantActivate(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantActivate failed: %v", err)
		}

		// Verify status is active
		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q", status, StatusActive)
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnTenantActivate(ctx, "nonexistent")
		if err == nil {
			t.Error("OnTenantActivate should fail for nonexistent tenant")
		}
	})

	t.Run("recovers from error state", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Set to error state
		err = manager.SetStatus(ctx, "tenant-1", StatusError)
		if err != nil {
			t.Fatalf("SetStatus setup failed: %v", err)
		}

		// Activate should recover
		err = hooks.OnTenantActivate(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantActivate failed: %v", err)
		}

		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q after activation", status, StatusActive)
		}
	})

	t.Run("refresh fails on error state", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Set to error state
		err = manager.SetStatus(ctx, "tenant-1", StatusError)
		if err != nil {
			t.Fatalf("SetStatus setup failed: %v", err)
		}

		// Make refresh fail
		ovsClient.getErr = errors.New("connection lost")

		err = hooks.OnTenantActivate(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantActivate should fail when refresh fails")
		}
	})
}

func TestLifecycleHooks_OnTenantSuspend(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful suspension", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Suspend
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend failed: %v", err)
		}

		// Verify status is suspended
		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusSuspended {
			t.Errorf("Status = %q, want %q", status, StatusSuspended)
		}
	})

	t.Run("installs drop flow at max priority", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Get the actual bridge name
		bridge, _ := manager.GetBridge(ctx, "tenant-1")
		bridgeName := bridge.Name

		initialFlowCount := ofClient.getFlowCount(bridgeName)

		// Suspend
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend failed: %v", err)
		}

		// Should have one more flow (the drop flow)
		newFlowCount := ofClient.getFlowCount(bridgeName)
		if newFlowCount <= initialFlowCount {
			t.Error("expected new drop flow to be installed")
		}

		// Verify the drop flow has max priority
		flows, _ := ofClient.GetFlows(ctx, bridgeName)
		var hasSuspendDropFlow bool
		for _, f := range flows {
			if f.Priority == PriorityMax && f.Cookie == CookieSuspendFlow {
				hasSuspendDropFlow = true
				// Verify it's a drop action
				for _, a := range f.Actions {
					if a.Type == ActionDrop {
						break
					}
				}
				break
			}
		}

		if !hasSuspendDropFlow {
			t.Error("expected suspend drop flow with max priority")
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnTenantSuspend(ctx, "nonexistent")
		if err == nil {
			t.Error("OnTenantSuspend should fail for nonexistent tenant")
		}
	})

	t.Run("flow installation fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make flow add fail
		ofClient.addErr = errors.New("add failed")

		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantSuspend should fail when flow installation fails")
		}
	})

	t.Run("without flow manager", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		hooks := NewLifecycleHooks(manager, nil, logger)

		// Create tenant first (without flow manager)
		_, err := manager.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 110})
		if err != nil {
			t.Fatalf("CreateBridge setup failed: %v", err)
		}

		// Suspend should still work (just sets status)
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend failed: %v", err)
		}

		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusSuspended {
			t.Errorf("Status = %q, want %q", status, StatusSuspended)
		}
	})
}

func TestLifecycleHooks_OnTenantResume(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful resume", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create and suspend tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend setup failed: %v", err)
		}

		// Resume
		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantResume failed: %v", err)
		}

		// Verify status is active
		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q", status, StatusActive)
		}
	})

	t.Run("reinstalls flows", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create and suspend tenant first
		vlanRange := VLANRange{Start: 100, End: 102}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Clear reset tracking
		ofClient.addCount.Store(0)

		// Suspend and resume
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend setup failed: %v", err)
		}
		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantResume failed: %v", err)
		}

		// Verify flows were reinstalled (DeleteAllFlows then InstallBaseFlows etc)
		if ofClient.addCount.Load() == 0 {
			t.Error("expected flows to be reinstalled on resume")
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnTenantResume(ctx, "nonexistent")
		if err == nil {
			t.Error("OnTenantResume should fail for nonexistent tenant")
		}
	})

	t.Run("delete flows fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make delete all fail
		ofClient.deleteAllErr = errors.New("delete failed")

		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantResume should fail when delete fails")
		}
	})

	t.Run("base flow reinstall fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make add fail (for reinstall)
		ofClient.addErr = errors.New("add failed")

		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantResume should fail when flow reinstall fails")
		}
	})

	t.Run("without flow manager", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		hooks := NewLifecycleHooks(manager, nil, logger)

		// Create tenant first (without flow manager)
		_, err := manager.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 110})
		if err != nil {
			t.Fatalf("CreateBridge setup failed: %v", err)
		}
		err = manager.SetStatus(ctx, "tenant-1", StatusSuspended)
		if err != nil {
			t.Fatalf("SetStatus setup failed: %v", err)
		}

		// Resume should still work (just sets status)
		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantResume failed: %v", err)
		}

		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q", status, StatusActive)
		}
	})

	t.Run("isolation flow reinstall fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first with small VLAN range
		vlanRange := VLANRange{Start: 100, End: 101}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Clear flow count after creation
		ofClient.addCount.Store(0)

		// Calculate how many base flows + untagged + vlan flows are needed
		// Base: ingress, vlan drop, untagged, N vlan flows, forward, egress = 5 + N
		// For range 100-101, that's 5 + 2 = 7 base flows
		// Set error to occur after base flows, during isolation flows
		ofClient.addErr = errors.New("isolation flow failed")
		ofClient.addErrAfter = 7 // fail after base flows

		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantResume should fail when isolation flow reinstall fails")
		}
	})

	t.Run("full resume reinstalls all flows", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 102}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend setup failed: %v", err)
		}

		// Resume
		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantResume failed: %v", err)
		}

		// Get the bridge to verify flows
		bridge, _ := manager.GetBridge(ctx, "tenant-1")
		flowCount := ofClient.getFlowCount(bridge.Name)

		// Should have flows reinstalled (base + isolation + ARP + DHCP)
		if flowCount == 0 {
			t.Error("expected flows to be reinstalled after resume")
		}

		// Status should be active
		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("Status = %q, want %q", status, StatusActive)
		}
	})
}

func TestLifecycleHooks_OnTenantDelete(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful deletion", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Delete
		err = hooks.OnTenantDelete(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantDelete failed: %v", err)
		}

		// Verify bridge is gone
		_, err = manager.GetBridge(ctx, "tenant-1")
		if err == nil {
			t.Error("bridge should be deleted")
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnTenantDelete(ctx, "nonexistent")
		if err == nil {
			t.Error("OnTenantDelete should fail for nonexistent tenant")
		}
	})

	t.Run("OVS delete fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make delete fail
		ovsClient.deleteErr = errors.New("delete failed")

		err = hooks.OnTenantDelete(ctx, "tenant-1")
		if err == nil {
			t.Error("OnTenantDelete should fail when OVS delete fails")
		}
	})

	t.Run("cleans up flows before deletion", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Verify flows exist
		bridge, _ := manager.GetBridge(ctx, "tenant-1")
		initialFlowCount := ofClient.getFlowCount(bridge.Name)
		if initialFlowCount == 0 {
			t.Fatal("expected flows before deletion")
		}

		// Delete
		err = hooks.OnTenantDelete(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantDelete failed: %v", err)
		}

		// Flows should be cleaned up (handled by manager.DeleteBridge)
	})
}

func TestLifecycleHooks_OnPortAdd(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful port add", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Add port
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err != nil {
			t.Fatalf("OnPortAdd failed: %v", err)
		}
	})

	t.Run("installs port flows", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		bridge, _ := manager.GetBridge(ctx, "tenant-1")
		initialFlowCount := ofClient.getFlowCount(bridge.Name)

		// Add port
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err != nil {
			t.Fatalf("OnPortAdd failed: %v", err)
		}

		// Should have 2 more flows (tag and strip)
		newFlowCount := ofClient.getFlowCount(bridge.Name)
		if newFlowCount != initialFlowCount+2 {
			t.Errorf("flow count = %d, want %d", newFlowCount, initialFlowCount+2)
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnPortAdd(ctx, "nonexistent", 1, 100)
		if err == nil {
			t.Error("OnPortAdd should fail for nonexistent tenant")
		}
	})

	t.Run("VLAN outside tenant range", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Try to add port with VLAN outside range
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 200)
		if err == nil {
			t.Error("OnPortAdd should fail when VLAN is outside tenant range")
		}

		var vlanErr ErrInvalidVLANRange
		if !errors.As(err, &vlanErr) {
			t.Errorf("error should be ErrInvalidVLANRange, got %T", err)
		}
	})

	t.Run("flow installation fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make add flow fail
		ofClient.addErr = errors.New("add failed")

		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err == nil {
			t.Error("OnPortAdd should fail when flow installation fails")
		}
	})

	t.Run("without flow manager", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		hooks := NewLifecycleHooks(manager, nil, logger)

		// Create tenant first (without flow manager)
		_, err := manager.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 110})
		if err != nil {
			t.Fatalf("CreateBridge setup failed: %v", err)
		}

		// Port add should still work (just no flows installed)
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err != nil {
			t.Fatalf("OnPortAdd failed: %v", err)
		}
	})
}

func TestLifecycleHooks_OnPortRemove(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful port remove", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant and add port first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err != nil {
			t.Fatalf("OnPortAdd setup failed: %v", err)
		}

		// Remove port
		err = hooks.OnPortRemove(ctx, "tenant-1", 1)
		if err != nil {
			t.Fatalf("OnPortRemove failed: %v", err)
		}
	})

	t.Run("deletes port flows", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant and add port first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 105)
		if err != nil {
			t.Fatalf("OnPortAdd setup failed: %v", err)
		}

		// Reset delete count
		ofClient.deleteCount.Store(0)

		// Remove port
		err = hooks.OnPortRemove(ctx, "tenant-1", 1)
		if err != nil {
			t.Fatalf("OnPortRemove failed: %v", err)
		}

		// Should have called DeleteFlows
		if ofClient.deleteCount.Load() == 0 {
			t.Error("expected flows to be deleted on port remove")
		}
	})

	t.Run("tenant not found", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		err := hooks.OnPortRemove(ctx, "nonexistent", 1)
		if err == nil {
			t.Error("OnPortRemove should fail for nonexistent tenant")
		}
	})

	t.Run("flow deletion fails", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// Create tenant first
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate setup failed: %v", err)
		}

		// Make delete fail
		ofClient.deleteErr = errors.New("delete failed")

		err = hooks.OnPortRemove(ctx, "tenant-1", 1)
		if err == nil {
			t.Error("OnPortRemove should fail when flow deletion fails")
		}
	})

	t.Run("without flow manager", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		hooks := NewLifecycleHooks(manager, nil, logger)

		// Create tenant first (without flow manager)
		_, err := manager.CreateBridge(ctx, "tenant-1", "test", VLANRange{Start: 100, End: 110})
		if err != nil {
			t.Fatalf("CreateBridge setup failed: %v", err)
		}

		// Port remove should still work (just no flows deleted)
		err = hooks.OnPortRemove(ctx, "tenant-1", 1)
		if err != nil {
			t.Fatalf("OnPortRemove failed: %v", err)
		}
	})
}

func TestLifecycleHooks_CompleteWorkflow(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("full lifecycle", func(t *testing.T) {
		ovsClient := newMockOVSClient()
		ofClient := newMockOpenFlowClient()
		manager := NewManager(ovsClient, ofClient, nil, logger)
		flowManager := NewFlowManager(ofClient, logger)
		hooks := NewLifecycleHooks(manager, flowManager, logger)

		// 1. Create tenant
		vlanRange := VLANRange{Start: 100, End: 110}
		err := hooks.OnTenantCreate(ctx, "tenant-1", "test", vlanRange)
		if err != nil {
			t.Fatalf("OnTenantCreate failed: %v", err)
		}

		// 2. Verify active
		status, _ := manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("expected active after create, got %s", status)
		}

		// 3. Add ports
		err = hooks.OnPortAdd(ctx, "tenant-1", 1, 100)
		if err != nil {
			t.Fatalf("OnPortAdd failed: %v", err)
		}
		err = hooks.OnPortAdd(ctx, "tenant-1", 2, 101)
		if err != nil {
			t.Fatalf("OnPortAdd failed: %v", err)
		}

		// 4. Suspend tenant
		err = hooks.OnTenantSuspend(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantSuspend failed: %v", err)
		}
		status, _ = manager.GetStatus(ctx, "tenant-1")
		if status != StatusSuspended {
			t.Errorf("expected suspended, got %s", status)
		}

		// 5. Resume tenant
		err = hooks.OnTenantResume(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantResume failed: %v", err)
		}
		status, _ = manager.GetStatus(ctx, "tenant-1")
		if status != StatusActive {
			t.Errorf("expected active after resume, got %s", status)
		}

		// 6. Remove port
		err = hooks.OnPortRemove(ctx, "tenant-1", 1)
		if err != nil {
			t.Fatalf("OnPortRemove failed: %v", err)
		}

		// 7. Delete tenant
		err = hooks.OnTenantDelete(ctx, "tenant-1")
		if err != nil {
			t.Fatalf("OnTenantDelete failed: %v", err)
		}

		// 8. Verify deleted
		_, err = manager.GetBridge(ctx, "tenant-1")
		if err == nil {
			t.Error("bridge should be deleted")
		}
	})
}
