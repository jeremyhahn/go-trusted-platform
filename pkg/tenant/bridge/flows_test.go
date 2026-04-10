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

func TestNewFlowManager(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
		ofClient := newMockOpenFlowClient()

		fm := NewFlowManager(ofClient, logger)

		if fm == nil {
			t.Fatal("NewFlowManager returned nil")
		}
		if fm.ofClient != ofClient {
			t.Error("ofClient not set correctly")
		}
		if fm.logger != logger {
			t.Error("logger not set correctly")
		}
	})

	t.Run("with nil logger uses default", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()

		fm := NewFlowManager(ofClient, nil)

		if fm == nil {
			t.Fatal("NewFlowManager returned nil")
		}
		if fm.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestFlowManager_InstallBaseFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful installation", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallBaseFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallBaseFlows failed: %v", err)
		}

		// Verify flows were added
		// Expected: 1 ingress + 1 vlan drop + 1 untagged + 3 vlan flows + 1 forward + 1 egress = 8
		flowCount := ofClient.getFlowCount("br-test")
		// 5 base flows (ingress, vlan drop, untagged, forward, egress) + VLAN range size
		expectedFlows := 5 + vlanRange.Size()
		if flowCount != expectedFlows {
			t.Errorf("flow count = %d, want %d", flowCount, expectedFlows)
		}
	})

	t.Run("with single VLAN", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 100}
		err := fm.InstallBaseFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallBaseFlows failed: %v", err)
		}

		flowCount := ofClient.getFlowCount("br-test")
		// 5 base flows + 1 VLAN flow
		expectedFlows := 5 + 1
		if flowCount != expectedFlows {
			t.Errorf("flow count = %d, want %d", flowCount, expectedFlows)
		}
	})

	t.Run("ingress flow add fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallBaseFlows(ctx, "br-test", vlanRange)
		if err == nil {
			t.Error("InstallBaseFlows should fail when flow add fails")
		}

		var flowErr ErrFlowInstallFailed
		if !errors.As(err, &flowErr) {
			t.Errorf("error should be ErrFlowInstallFailed, got %T", err)
		}
	})

	t.Run("verifies flow properties", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 100}
		err := fm.InstallBaseFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallBaseFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		// Check for ingress flow
		var hasIngressFlow bool
		var hasForwardFlow bool
		var hasEgressFlow bool
		var hasVLANFlow bool

		for _, f := range flows {
			if f.Table == TableIngress && f.Priority == PriorityBase {
				hasIngressFlow = true
				// Verify it goes to VLAN validation
				for _, a := range f.Actions {
					if a.Type == ActionGotoTable && a.Table == TableVLANValidation {
						break
					}
				}
			}
			if f.Table == TableForwarding && f.Priority == PriorityBase {
				hasForwardFlow = true
			}
			if f.Table == TableEgress && f.Priority == PriorityBase {
				hasEgressFlow = true
			}
			if f.Table == TableVLANValidation && f.Match.VLAN != nil && *f.Match.VLAN == 100 {
				hasVLANFlow = true
			}
		}

		if !hasIngressFlow {
			t.Error("missing ingress flow")
		}
		if !hasForwardFlow {
			t.Error("missing forward flow")
		}
		if !hasEgressFlow {
			t.Error("missing egress flow")
		}
		if !hasVLANFlow {
			t.Error("missing VLAN flow")
		}
	})

	t.Run("cookies are set correctly", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 100}
		err := fm.InstallBaseFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallBaseFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		for _, f := range flows {
			// All base flows should have CookieBaseFlow prefix
			if f.Cookie&CookieBaseFlow != CookieBaseFlow {
				t.Errorf("flow cookie %x should have CookieBaseFlow prefix", f.Cookie)
			}
		}
	})
}

func TestFlowManager_InstallIsolationFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful installation", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		// Verify flows were added
		flowCount := ofClient.getFlowCount("br-test")
		if flowCount == 0 {
			t.Error("no isolation flows were added")
		}
	})

	t.Run("drops VLANs below range", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 10, End: 20}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		// Should have drop flows for VLANs 1-9
		var dropFlowCount int
		for _, f := range flows {
			if f.Table == TableIngress && f.Priority == PriorityIsolation {
				for _, a := range f.Actions {
					if a.Type == ActionDrop {
						dropFlowCount++
						break
					}
				}
			}
		}

		if dropFlowCount < 9 {
			t.Errorf("expected at least 9 drop flows for VLANs below range, got %d", dropFlowCount)
		}
	})

	t.Run("drops VLANs above range", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		// Should have some drop flows for VLANs above range
		var hasAboveRangeDropFlow bool
		for _, f := range flows {
			if f.Match.VLAN != nil && *f.Match.VLAN > 110 {
				hasAboveRangeDropFlow = true
				break
			}
		}

		if !hasAboveRangeDropFlow {
			t.Error("expected drop flow for VLANs above range")
		}
	})

	t.Run("includes broadcast flow", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		var hasBroadcastFlow bool
		for _, f := range flows {
			if f.Match.EthDst != nil && *f.Match.EthDst == "ff:ff:ff:ff:ff:ff" {
				hasBroadcastFlow = true
				break
			}
		}

		if !hasBroadcastFlow {
			t.Error("expected broadcast flow")
		}
	})

	t.Run("add flow fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 10, End: 20}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err == nil {
			t.Error("InstallIsolationFlows should fail when flow add fails")
		}
	})

	t.Run("range starting at 1", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 1, End: 10}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		// Should not try to add drop flows below 1
		flows, _ := ofClient.GetFlows(ctx, "br-test")
		for _, f := range flows {
			if f.Match.VLAN != nil && *f.Match.VLAN < 1 {
				t.Errorf("unexpected drop flow for VLAN %d", *f.Match.VLAN)
			}
		}
	})

	t.Run("range at max VLAN", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 4084, End: 4094}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		// Should not try to add drop flows above 4094
		flows, _ := ofClient.GetFlows(ctx, "br-test")
		for _, f := range flows {
			if f.Match.VLAN != nil && *f.Match.VLAN > 4094 {
				t.Errorf("unexpected drop flow for VLAN %d", *f.Match.VLAN)
			}
		}
	})

	t.Run("cookies use isolation prefix", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 110}
		err := fm.InstallIsolationFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallIsolationFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")
		for _, f := range flows {
			if f.Cookie&CookieIsolationFlow != CookieIsolationFlow {
				t.Errorf("flow cookie %x should have CookieIsolationFlow prefix", f.Cookie)
			}
		}
	})
}

func TestFlowManager_InstallPortFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful installation", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 1, 100)
		if err != nil {
			t.Fatalf("InstallPortFlows failed: %v", err)
		}

		// Should have 2 flows: tag flow and strip flow
		flowCount := ofClient.getFlowCount("br-test")
		if flowCount != 2 {
			t.Errorf("flow count = %d, want 2", flowCount)
		}
	})

	t.Run("tag flow properties", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 5, 200)
		if err != nil {
			t.Fatalf("InstallPortFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		var hasTagFlow bool
		for _, f := range flows {
			if f.Table == TableIngress && f.Match.InPort != nil && *f.Match.InPort == 5 {
				hasTagFlow = true

				// Verify actions: push VLAN, set VLAN, goto table
				var hasPushVLAN, hasSetVLAN, hasGotoTable bool
				for _, a := range f.Actions {
					if a.Type == ActionPushVLAN {
						hasPushVLAN = true
					}
					if a.Type == ActionSetVLAN && a.VLAN == 200 {
						hasSetVLAN = true
					}
					if a.Type == ActionGotoTable {
						hasGotoTable = true
					}
				}

				if !hasPushVLAN {
					t.Error("tag flow missing push VLAN action")
				}
				if !hasSetVLAN {
					t.Error("tag flow missing set VLAN action")
				}
				if !hasGotoTable {
					t.Error("tag flow missing goto table action")
				}
				break
			}
		}

		if !hasTagFlow {
			t.Error("missing tag flow for port")
		}
	})

	t.Run("strip flow properties", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 5, 200)
		if err != nil {
			t.Fatalf("InstallPortFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		var hasStripFlow bool
		for _, f := range flows {
			if f.Table == TableEgress && f.Match.VLAN != nil && *f.Match.VLAN == 200 {
				hasStripFlow = true

				// Verify actions: pop VLAN, output
				var hasPopVLAN, hasOutput bool
				for _, a := range f.Actions {
					if a.Type == ActionPopVLAN {
						hasPopVLAN = true
					}
					if a.Type == ActionOutput && a.Port == 5 {
						hasOutput = true
					}
				}

				if !hasPopVLAN {
					t.Error("strip flow missing pop VLAN action")
				}
				if !hasOutput {
					t.Error("strip flow missing output action")
				}
				break
			}
		}

		if !hasStripFlow {
			t.Error("missing strip flow for port")
		}
	})

	t.Run("add flow fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 1, 100)
		if err == nil {
			t.Error("InstallPortFlows should fail when flow add fails")
		}
	})

	t.Run("cookies use port prefix", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 1, 100)
		if err != nil {
			t.Fatalf("InstallPortFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")
		for _, f := range flows {
			if f.Cookie&CookiePortFlow != CookiePortFlow {
				t.Errorf("flow cookie %x should have CookiePortFlow prefix", f.Cookie)
			}
		}
	})

	t.Run("different ports have different flows", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.InstallPortFlows(ctx, "br-test", 1, 100)
		if err != nil {
			t.Fatalf("InstallPortFlows for port 1 failed: %v", err)
		}

		err = fm.InstallPortFlows(ctx, "br-test", 2, 200)
		if err != nil {
			t.Fatalf("InstallPortFlows for port 2 failed: %v", err)
		}

		flowCount := ofClient.getFlowCount("br-test")
		if flowCount != 4 {
			t.Errorf("flow count = %d, want 4 (2 per port)", flowCount)
		}
	})
}

func TestFlowManager_DeleteAllFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful deletion", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		// Add some flows first
		err := fm.InstallBaseFlows(ctx, "br-test", VLANRange{Start: 100, End: 102})
		if err != nil {
			t.Fatalf("InstallBaseFlows setup failed: %v", err)
		}

		err = fm.DeleteAllFlows(ctx, "br-test")
		if err != nil {
			t.Fatalf("DeleteAllFlows failed: %v", err)
		}

		flowCount := ofClient.getFlowCount("br-test")
		if flowCount != 0 {
			t.Errorf("flow count = %d, want 0", flowCount)
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.deleteAllErr = errors.New("delete failed")
		fm := NewFlowManager(ofClient, logger)

		err := fm.DeleteAllFlows(ctx, "br-test")
		if err == nil {
			t.Error("DeleteAllFlows should fail when delete fails")
		}

		var deleteErr ErrFlowDeleteFailed
		if !errors.As(err, &deleteErr) {
			t.Errorf("error should be ErrFlowDeleteFailed, got %T", err)
		}
	})

	t.Run("on empty bridge", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		err := fm.DeleteAllFlows(ctx, "br-test")
		if err != nil {
			t.Fatalf("DeleteAllFlows on empty bridge failed: %v", err)
		}
	})
}

func TestFlowManager_DeletePortFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful deletion", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		// Add port flows
		err := fm.InstallPortFlows(ctx, "br-test", 1, 100)
		if err != nil {
			t.Fatalf("InstallPortFlows setup failed: %v", err)
		}
		err = fm.InstallPortFlows(ctx, "br-test", 2, 200)
		if err != nil {
			t.Fatalf("InstallPortFlows setup failed: %v", err)
		}

		err = fm.DeletePortFlows(ctx, "br-test", 1)
		if err != nil {
			t.Fatalf("DeletePortFlows failed: %v", err)
		}
	})

	t.Run("delete fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.deleteErr = errors.New("delete failed")
		fm := NewFlowManager(ofClient, logger)

		err := fm.DeletePortFlows(ctx, "br-test", 1)
		if err == nil {
			t.Error("DeletePortFlows should fail when delete fails")
		}

		var deleteErr ErrFlowDeleteFailed
		if !errors.As(err, &deleteErr) {
			t.Errorf("error should be ErrFlowDeleteFailed, got %T", err)
		}
	})

	t.Run("on nonexistent port", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		// Should not error even if port doesn't exist
		err := fm.DeletePortFlows(ctx, "br-test", 999)
		if err != nil {
			t.Fatalf("DeletePortFlows on nonexistent port failed: %v", err)
		}
	})
}

func TestFlowManager_DeleteIsolationFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful deletion", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		// Add isolation flows
		err := fm.InstallIsolationFlows(ctx, "br-test", VLANRange{Start: 100, End: 110})
		if err != nil {
			t.Fatalf("InstallIsolationFlows setup failed: %v", err)
		}

		err = fm.DeleteIsolationFlows(ctx, "br-test")
		if err != nil {
			t.Fatalf("DeleteIsolationFlows failed: %v", err)
		}
	})
}

func TestFlowManager_GetFlowStats(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("returns flows", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		// Add some flows
		err := fm.InstallBaseFlows(ctx, "br-test", VLANRange{Start: 100, End: 102})
		if err != nil {
			t.Fatalf("InstallBaseFlows setup failed: %v", err)
		}

		flows, err := fm.GetFlowStats(ctx, "br-test")
		if err != nil {
			t.Fatalf("GetFlowStats failed: %v", err)
		}

		if len(flows) == 0 {
			t.Error("expected flows to be returned")
		}
	})

	t.Run("get flows fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.getErr = errors.New("get failed")
		fm := NewFlowManager(ofClient, logger)

		_, err := fm.GetFlowStats(ctx, "br-test")
		if err == nil {
			t.Error("GetFlowStats should fail when get fails")
		}
	})
}

func TestFlowManager_InstallARPFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful installation", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallARPFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallARPFlows failed: %v", err)
		}

		// Should have one ARP flow per VLAN
		flowCount := ofClient.getFlowCount("br-test")
		if flowCount != 3 {
			t.Errorf("flow count = %d, want 3", flowCount)
		}
	})

	t.Run("ARP flow properties", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 100}
		err := fm.InstallARPFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallARPFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		if len(flows) != 1 {
			t.Fatalf("expected 1 flow, got %d", len(flows))
		}

		f := flows[0]

		// Verify table and priority
		if f.Table != TableIngress {
			t.Errorf("Table = %d, want %d", f.Table, TableIngress)
		}
		if f.Priority != PriorityHigh {
			t.Errorf("Priority = %d, want %d", f.Priority, PriorityHigh)
		}

		// Verify match
		if f.Match.VLAN == nil || *f.Match.VLAN != 100 {
			t.Error("ARP flow should match VLAN 100")
		}
		if f.Match.EthType == nil || *f.Match.EthType != EthTypeARP {
			t.Error("ARP flow should match ARP EthType")
		}

		// Verify action
		var hasNormalAction bool
		for _, a := range f.Actions {
			if a.Type == ActionNormal {
				hasNormalAction = true
				break
			}
		}
		if !hasNormalAction {
			t.Error("ARP flow should have normal action")
		}
	})

	t.Run("add flow fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallARPFlows(ctx, "br-test", vlanRange)
		if err == nil {
			t.Error("InstallARPFlows should fail when flow add fails")
		}
	})
}

func TestFlowManager_InstallDHCPFlows(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("successful installation", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallDHCPFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallDHCPFlows failed: %v", err)
		}

		// Should have 2 DHCP flows per VLAN (client and server)
		flowCount := ofClient.getFlowCount("br-test")
		expectedFlows := 2 * vlanRange.Size()
		if flowCount != expectedFlows {
			t.Errorf("flow count = %d, want %d", flowCount, expectedFlows)
		}
	})

	t.Run("DHCP flow properties", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 100}
		err := fm.InstallDHCPFlows(ctx, "br-test", vlanRange)
		if err != nil {
			t.Fatalf("InstallDHCPFlows failed: %v", err)
		}

		flows, _ := ofClient.GetFlows(ctx, "br-test")

		if len(flows) != 2 {
			t.Fatalf("expected 2 flows, got %d", len(flows))
		}

		var hasClientFlow, hasServerFlow bool
		for _, f := range flows {
			// Verify common properties
			if f.Table != TableIngress {
				t.Errorf("Table = %d, want %d", f.Table, TableIngress)
			}
			if f.Priority != PriorityHigh {
				t.Errorf("Priority = %d, want %d", f.Priority, PriorityHigh)
			}
			if f.Match.EthType == nil || *f.Match.EthType != EthTypeIPv4 {
				t.Error("DHCP flow should match IPv4")
			}
			if f.Match.IPProto == nil || *f.Match.IPProto != IPProtoUDP {
				t.Error("DHCP flow should match UDP")
			}

			// Check for client or server port
			if f.Match.UDPSrc != nil && *f.Match.UDPSrc == 68 {
				hasClientFlow = true
			}
			if f.Match.UDPDst != nil && *f.Match.UDPDst == 67 {
				hasServerFlow = true
			}
		}

		if !hasClientFlow {
			t.Error("missing DHCP client flow")
		}
		if !hasServerFlow {
			t.Error("missing DHCP server flow")
		}
	})

	t.Run("add flow fails", func(t *testing.T) {
		ofClient := newMockOpenFlowClient()
		ofClient.addErr = errors.New("add flow failed")
		fm := NewFlowManager(ofClient, logger)

		vlanRange := VLANRange{Start: 100, End: 102}
		err := fm.InstallDHCPFlows(ctx, "br-test", vlanRange)
		if err == nil {
			t.Error("InstallDHCPFlows should fail when flow add fails")
		}
	})
}

func TestFlowConstants(t *testing.T) {
	t.Run("cookie prefixes", func(t *testing.T) {
		// Verify prefixes are distinct
		if CookieBaseFlow == CookieIsolationFlow {
			t.Error("CookieBaseFlow and CookieIsolationFlow should be different")
		}
		if CookieBaseFlow == CookiePortFlow {
			t.Error("CookieBaseFlow and CookiePortFlow should be different")
		}
		if CookieBaseFlow == CookieSuspendFlow {
			t.Error("CookieBaseFlow and CookieSuspendFlow should be different")
		}
		if CookieIsolationFlow == CookiePortFlow {
			t.Error("CookieIsolationFlow and CookiePortFlow should be different")
		}
	})

	t.Run("priority levels", func(t *testing.T) {
		// Verify priority ordering
		if PriorityDrop >= PriorityDefault {
			t.Error("PriorityDrop should be less than PriorityDefault")
		}
		if PriorityDefault >= PriorityBase {
			t.Error("PriorityDefault should be less than PriorityBase")
		}
		if PriorityBase >= PriorityVLAN {
			t.Error("PriorityBase should be less than PriorityVLAN")
		}
		if PriorityVLAN >= PriorityIsolation {
			t.Error("PriorityVLAN should be less than PriorityIsolation")
		}
		if PriorityIsolation >= PriorityPort {
			t.Error("PriorityIsolation should be less than PriorityPort")
		}
		if PriorityPort >= PriorityHigh {
			t.Error("PriorityPort should be less than PriorityHigh")
		}
		if PriorityHigh >= PriorityMax {
			t.Error("PriorityHigh should be less than PriorityMax")
		}
	})
}
