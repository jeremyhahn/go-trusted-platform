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

package bootstrap

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// TestBmcBootNode_PowerStateAwareReboot verifies the one-shot PXE override
// reboot logic: a node already powered on must be power-CYCLED (so the
// one-shot override is consumed), while an off/unknown node must be powered
// ON. A PowerStatus read failure must fall back to a best-effort PowerOn
// rather than aborting the provision.
func TestBmcBootNode_PowerStateAwareReboot(t *testing.T) {
	newOrch := func(client bmc.Client) *Orchestrator {
		return &Orchestrator{
			logger:     orchTestLogger(),
			bmcFactory: &mockBMCFactory{client: client},
		}
	}
	node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "lab-node-3", BMCProtocol: "ipmi"}}

	t.Run("powered on node is power cycled, not powered on", func(t *testing.T) {
		mock := bmc.NewMockClient()
		mock.Power = bmc.PowerStateOn
		o := newOrch(mock)

		if err := o.bmcBootNode(context.Background(), node); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.SetBootDeviceCalls() != 1 {
			t.Errorf("SetBootDevice calls = %d, want 1", mock.SetBootDeviceCalls())
		}
		if mock.PowerCycleCalls() != 1 {
			t.Errorf("PowerCycle calls = %d, want 1", mock.PowerCycleCalls())
		}
		if mock.PowerOnCalls() != 0 {
			t.Errorf("PowerOn calls = %d, want 0 (already on must not PowerOn)", mock.PowerOnCalls())
		}
	})

	t.Run("powered off node is powered on, not cycled", func(t *testing.T) {
		mock := bmc.NewMockClient()
		mock.Power = bmc.PowerStateOff
		o := newOrch(mock)

		if err := o.bmcBootNode(context.Background(), node); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.PowerOnCalls() != 1 {
			t.Errorf("PowerOn calls = %d, want 1", mock.PowerOnCalls())
		}
		if mock.PowerCycleCalls() != 0 {
			t.Errorf("PowerCycle calls = %d, want 0 (off node must not PowerCycle)", mock.PowerCycleCalls())
		}
	})

	t.Run("power status error falls back to PowerOn", func(t *testing.T) {
		mock := bmc.NewMockClient()
		mock.PowerStatusErr = errors.New("status read timeout")
		o := newOrch(mock)

		if err := o.bmcBootNode(context.Background(), node); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mock.PowerOnCalls() != 1 {
			t.Errorf("PowerOn calls = %d, want 1 (fallback)", mock.PowerOnCalls())
		}
		if mock.PowerCycleCalls() != 0 {
			t.Errorf("PowerCycle calls = %d, want 0", mock.PowerCycleCalls())
		}
	})

	t.Run("SetBootDevice failure aborts before power action", func(t *testing.T) {
		mock := bmc.NewMockClient()
		mock.SetBootDeviceErr = errors.New("boot override rejected")
		o := newOrch(mock)

		err := o.bmcBootNode(context.Background(), node)
		if err == nil {
			t.Fatal("expected error when SetBootDevice fails")
		}
		if mock.PowerOnCalls() != 0 || mock.PowerCycleCalls() != 0 {
			t.Errorf("no power action expected on SetBootDevice failure, got on=%d cycle=%d",
				mock.PowerOnCalls(), mock.PowerCycleCalls())
		}
	})
}
