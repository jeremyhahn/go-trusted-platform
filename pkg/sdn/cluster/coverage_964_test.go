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

package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// errInjected964 is the typed fault the tests below inject into the mocks.
type errInjected964 struct{ op string }

func (e errInjected964) Error() string { return "injected failure: " + e.op }

// newSingleAttemptSync964 builds a node-1 synchronizer that tries each OVS
// operation exactly once, so an injected fault surfaces without a retry wait.
func newSingleAttemptSync964(stateManager *mockStateManager, ovsClient *mockOVSClient) *quicbaasSynchronizer {
	s := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		createTestLogger(),
		WithRetryConfig(time.Millisecond, 0, 1.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	return s.(*quicbaasSynchronizer)
}

func seedBridge964(t *testing.T, stateManager *mockStateManager, id, name string, nodeID uint64) {
	t.Helper()
	if err := stateManager.CreateBridge(context.Background(), &BridgeState{ID: id, Name: name, NodeID: nodeID}); err != nil {
		t.Fatalf("seed bridge %s: %v", id, err)
	}
}

func seedFlow964(t *testing.T, stateManager *mockStateManager, bridgeID, flowID string, cookie uint64) {
	t.Helper()
	flow := &FlowState{ID: flowID, BridgeID: bridgeID, Priority: 100, Cookie: cookie, Match: &FlowMatch{}}
	if err := stateManager.CreateFlow(context.Background(), flow); err != nil {
		t.Fatalf("seed flow %s: %v", flowID, err)
	}
}

func TestSyncSingleBridge964_ForeignNodeCarriesMessageError(t *testing.T) {
	stateManager := newMockStateManager()
	seedBridge964(t, stateManager, "bridge-1", "br0", 99)
	s := newSingleAttemptSync964(stateManager, newMockOVSClient())

	err := s.SyncBridge("bridge-1")

	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("SyncBridge() error = %v, want a wrapped *MessageError", err)
	}
	if want := "bridge belongs to node 99, not 1"; msgErr.Error() != want {
		t.Errorf("MessageError.Error() = %q, want %q", msgErr.Error(), want)
	}
}

func TestSyncSingleBridge964_StateErrors(t *testing.T) {
	tests := []struct {
		name       string
		inject     func(sm *mockStateManager, oc *mockOVSClient)
		wantEntity string
		wantOp     string
	}{
		{
			name:       "get bridge fails",
			inject:     func(sm *mockStateManager, _ *mockOVSClient) { sm.getBridgeErr = errInjected964{op: "get bridge"} },
			wantEntity: "bridge",
			wantOp:     "get",
		},
		{
			name:       "list ports fails",
			inject:     func(sm *mockStateManager, _ *mockOVSClient) { sm.listPortsErr = errInjected964{op: "list ports"} },
			wantEntity: "ports",
			wantOp:     "list",
		},
		{
			name:       "list flows fails",
			inject:     func(sm *mockStateManager, _ *mockOVSClient) { sm.listFlowsErr = errInjected964{op: "list flows"} },
			wantEntity: "flows",
			wantOp:     "list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateManager := newMockStateManager()
			ovsClient := newMockOVSClient()
			seedBridge964(t, stateManager, "bridge-1", "br0", 1)
			tt.inject(stateManager, ovsClient)
			s := newSingleAttemptSync964(stateManager, ovsClient)

			err := s.SyncBridge("bridge-1")

			var syncErr ErrSyncFailed
			if !errors.As(err, &syncErr) {
				t.Fatalf("SyncBridge() error = %v, want ErrSyncFailed", err)
			}
			if syncErr.Entity != tt.wantEntity || syncErr.Operation != tt.wantOp {
				t.Errorf("ErrSyncFailed = {%s %s}, want {%s %s}", syncErr.Entity, syncErr.Operation, tt.wantEntity, tt.wantOp)
			}
			var injected errInjected964
			if !errors.As(err, &injected) {
				t.Errorf("SyncBridge() error = %v, want the injected cause preserved", err)
			}
		})
	}
}

func TestSyncSingleBridge964_OVSWriteFailuresReturnMaxRetries(t *testing.T) {
	tests := []struct {
		name     string
		existing *ovs.Bridge
		inject   func(oc *mockOVSClient)
		wantOp   string
	}{
		{
			name:   "create missing bridge fails",
			inject: func(oc *mockOVSClient) { oc.createBridgeErr = errInjected964{op: "create bridge"} },
			wantOp: "create bridge",
		},
		{
			name:     "update drifted bridge fails",
			existing: &ovs.Bridge{Name: "br0", FailMode: "standalone"},
			inject:   func(oc *mockOVSClient) { oc.updateBridgeErr = errInjected964{op: "update bridge"} },
			wantOp:   "update bridge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateManager := newMockStateManager()
			ovsClient := newMockOVSClient()
			seedBridge964(t, stateManager, "bridge-1", "br0", 1)
			if tt.existing != nil {
				ovsClient.bridges[tt.existing.Name] = tt.existing
			}
			tt.inject(ovsClient)
			s := newSingleAttemptSync964(stateManager, ovsClient)

			err := s.SyncBridge("bridge-1")

			var maxErr ErrMaxRetriesExceeded
			if !errors.As(err, &maxErr) {
				t.Fatalf("SyncBridge() error = %v, want ErrMaxRetriesExceeded", err)
			}
			if maxErr.Operation != tt.wantOp {
				t.Errorf("ErrMaxRetriesExceeded.Operation = %q, want %q", maxErr.Operation, tt.wantOp)
			}
		})
	}
}

func TestSyncSingleBridge964_RepairsDriftWithoutRecreating(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	if err := stateManager.CreateBridge(context.Background(), &BridgeState{
		ID: "bridge-1", Name: "br0", NodeID: 1, FailMode: "secure",
	}); err != nil {
		t.Fatalf("seed bridge: %v", err)
	}
	ovsClient.bridges["br0"] = &ovs.Bridge{Name: "br0", FailMode: "standalone"}
	s := newSingleAttemptSync964(stateManager, ovsClient)

	if err := s.SyncBridge("bridge-1"); err != nil {
		t.Fatalf("SyncBridge() error = %v", err)
	}

	if len(ovsClient.createBridgeCalls) != 0 {
		t.Errorf("CreateBridge called %d times for an existing bridge, want 0", len(ovsClient.createBridgeCalls))
	}
	if got := ovsClient.bridges["br0"].FailMode; got != "secure" {
		t.Errorf("OVS bridge FailMode = %q after sync, want %q", got, "secure")
	}
}

func TestSyncSingleBridge964_InstallsPortsAndFlows(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	seedBridge964(t, stateManager, "bridge-1", "br0", 1)
	if err := stateManager.CreatePort(context.Background(), &PortState{ID: "port-1", Name: "eth0", BridgeID: "bridge-1"}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	seedFlow964(t, stateManager, "bridge-1", "flow-1", 0x10)
	s := newSingleAttemptSync964(stateManager, ovsClient)

	if err := s.SyncBridge("bridge-1"); err != nil {
		t.Fatalf("SyncBridge() error = %v", err)
	}

	if _, ok := ovsClient.ports["br0"]["eth0"]; !ok {
		t.Error("port eth0 was not added to OVS bridge br0")
	}
	flows := ovsClient.flows["br0"]
	if len(flows) != 1 || flows[0].Cookie != "0x10" {
		t.Errorf("OVS flows on br0 = %v, want one flow with cookie 0x10", flows)
	}
}

// A port or flow that cannot be installed is logged and skipped: the bridge
// sync as a whole still succeeds, so one bad child cannot block the others.
func TestSyncSingleBridge964_ChildInstallFailuresDoNotFailSync(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	seedBridge964(t, stateManager, "bridge-1", "br0", 1)
	if err := stateManager.CreatePort(context.Background(), &PortState{ID: "port-1", Name: "eth0", BridgeID: "bridge-1"}); err != nil {
		t.Fatalf("seed port: %v", err)
	}
	seedFlow964(t, stateManager, "bridge-1", "flow-1", 0x10)
	ovsClient.addPortErr = errInjected964{op: "add port"}
	ovsClient.addFlowErr = errInjected964{op: "add flow"}
	s := newSingleAttemptSync964(stateManager, ovsClient)

	if err := s.SyncBridge("bridge-1"); err != nil {
		t.Fatalf("SyncBridge() error = %v, want nil when only children fail", err)
	}

	if len(ovsClient.addPortCalls) != 1 || len(ovsClient.addFlowCalls) != 1 {
		t.Errorf("AddPort/AddFlow calls = %d/%d, want 1/1", len(ovsClient.addPortCalls), len(ovsClient.addFlowCalls))
	}
	if len(ovsClient.flows["br0"]) != 0 {
		t.Errorf("OVS flows on br0 = %d, want 0 after a failed AddFlow", len(ovsClient.flows["br0"]))
	}
}

func TestReconcileFlows964_InstallsOnlyMissingLocalFlows(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	seedBridge964(t, stateManager, "bridge-1", "br0", 1)
	seedBridge964(t, stateManager, "bridge-2", "br-remote", 2)
	ovsClient.bridges["br0"] = &ovs.Bridge{Name: "br0"}
	ovsClient.bridges["br-remote"] = &ovs.Bridge{Name: "br-remote"}
	seedFlow964(t, stateManager, "bridge-1", "flow-1", 0x1)
	seedFlow964(t, stateManager, "bridge-1", "flow-2", 0x2)
	seedFlow964(t, stateManager, "bridge-2", "flow-remote", 0x3)
	// flow-1 is already installed in OVS under its cookie.
	ovsClient.flows["br0"] = []*ovs.Flow{{Cookie: "0x1"}}
	s := newSingleAttemptSync964(stateManager, ovsClient)
	ctx := context.Background()

	synced, err := s.reconcileFlows(ctx)
	if err != nil {
		t.Fatalf("reconcileFlows() error = %v", err)
	}
	if synced != 1 {
		t.Errorf("reconcileFlows() synced = %d, want 1 (only flow-2 is missing)", synced)
	}
	if len(ovsClient.flows["br-remote"]) != 0 {
		t.Error("reconcileFlows() installed a flow on another node's bridge")
	}

	// A second pass finds every flow present and installs nothing.
	synced, err = s.reconcileFlows(ctx)
	if err != nil || synced != 0 {
		t.Errorf("second reconcileFlows() = (%d, %v), want (0, nil)", synced, err)
	}
}

// Per-bridge failures are logged and skipped: reconcileFlows reports zero
// installed flows and no error, so one bad bridge does not abort the pass.
func TestReconcileFlows964_PerBridgeFailuresAreSkipped(t *testing.T) {
	tests := []struct {
		name   string
		inject func(sm *mockStateManager, oc *mockOVSClient)
	}{
		{
			name:   "desired flows unreadable",
			inject: func(sm *mockStateManager, _ *mockOVSClient) { sm.listFlowsErr = errInjected964{op: "list desired"} },
		},
		{
			name:   "current flows unreadable",
			inject: func(_ *mockStateManager, oc *mockOVSClient) { oc.listFlowsErr = errInjected964{op: "list current"} },
		},
		{
			name:   "flow install fails",
			inject: func(_ *mockStateManager, oc *mockOVSClient) { oc.addFlowErr = errInjected964{op: "add flow"} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateManager := newMockStateManager()
			ovsClient := newMockOVSClient()
			seedBridge964(t, stateManager, "bridge-1", "br0", 1)
			ovsClient.bridges["br0"] = &ovs.Bridge{Name: "br0"}
			seedFlow964(t, stateManager, "bridge-1", "flow-1", 0x1)
			tt.inject(stateManager, ovsClient)
			s := newSingleAttemptSync964(stateManager, ovsClient)

			synced, err := s.reconcileFlows(context.Background())
			if err != nil {
				t.Fatalf("reconcileFlows() error = %v, want nil", err)
			}
			if synced != 0 {
				t.Errorf("reconcileFlows() synced = %d, want 0", synced)
			}
		})
	}
}
