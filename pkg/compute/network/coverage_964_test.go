// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package network

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// newUnreachableOVSAdapter builds the real OVSFlowControllerAdapter over an
// OVS client whose OVSDB and OpenFlow sockets do not exist, so every call
// that reaches the controller fails in memory without touching the host.
func newUnreachableOVSAdapter(t *testing.T) *OVSFlowControllerAdapter {
	t.Helper()

	dir := t.TempDir()
	client, err := ovs.NewClient(
		filepath.Join(dir, "db.sock"),
		ovs.WithOpenFlowSocketDir(dir),
	)
	if err != nil {
		t.Fatalf("ovs.NewClient: %v", err)
	}
	controller, err := policy.NewOVSFlowController(client)
	if err != nil {
		t.Fatalf("policy.NewOVSFlowController: %v", err)
	}
	adapter, err := NewOVSFlowControllerAdapter(controller)
	if err != nil {
		t.Fatalf("NewOVSFlowControllerAdapter: %v", err)
	}
	return adapter
}

func testFlowRule() *FlowRule {
	return &FlowRule{
		ID:       "rule-1",
		PortID:   "port-1",
		Priority: 100,
		Match:    &FlowMatch{InPort: 1},
		Actions:  []FlowAction{{Type: FlowActionTypeDrop}},
	}
}

func TestCoverage964_NewOVSFlowControllerAdapter_Real(t *testing.T) {
	_, err := NewOVSFlowControllerAdapter(nil)
	var cfgErr ErrInvalidConfig
	if !errors.As(err, &cfgErr) || cfgErr.Field != "controller" {
		t.Fatalf("nil controller: want ErrInvalidConfig{Field: controller}, got %v", err)
	}

	adapter := newUnreachableOVSAdapter(t)
	if adapter.logger != slog.Default() {
		t.Error("adapter without a logger option should use slog.Default()")
	}

	logger := slog.New(slog.DiscardHandler)
	withLogger, err := NewOVSFlowControllerAdapter(adapter.controller, WithOVSAdapterLogger(logger))
	if err != nil {
		t.Fatalf("NewOVSFlowControllerAdapter with logger: %v", err)
	}
	if withLogger.logger != logger {
		t.Error("WithOVSAdapterLogger did not set the adapter logger")
	}
}

func TestCoverage964_OVSAdapter_CanceledContext(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		operation string
		call      func() error
	}{
		{"AddFlow", func() error { return adapter.AddFlow(ctx, "br0", testFlowRule()) }},
		{"DeleteFlow", func() error { return adapter.DeleteFlow(ctx, "br0", "rule-1") }},
		{"ModifyFlow", func() error { return adapter.ModifyFlow(ctx, "br0", testFlowRule()) }},
		{"GetFlows", func() error {
			rules, err := adapter.GetFlows(ctx, "br0")
			if rules != nil {
				t.Errorf("GetFlows on a canceled context returned rules: %v", rules)
			}
			return err
		}},
		{"SetPortVLAN", func() error { return adapter.SetPortVLAN(ctx, "br0", "port-1", 10) }},
	}

	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			var canceled ErrContextCanceled
			err := tt.call()
			if !errors.As(err, &canceled) || canceled.Operation != tt.operation {
				t.Fatalf("want ErrContextCanceled{Operation: %s}, got %v", tt.operation, err)
			}
		})
	}
}

func TestCoverage964_OVSAdapter_InvalidInput(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)
	ctx := context.Background()

	tests := []struct {
		name  string
		field string
		call  func() error
	}{
		{"AddFlow nil rule", "rule", func() error { return adapter.AddFlow(ctx, "br0", nil) }},
		{"AddFlow empty ID", "ID", func() error { return adapter.AddFlow(ctx, "br0", &FlowRule{PortID: "port-1"}) }},
		{"DeleteFlow empty ID", "ruleID", func() error { return adapter.DeleteFlow(ctx, "br0", "") }},
		{"ModifyFlow nil rule", "rule", func() error { return adapter.ModifyFlow(ctx, "br0", nil) }},
		{"SetPortVLAN empty port", "portID", func() error { return adapter.SetPortVLAN(ctx, "br0", "", 10) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfgErr ErrInvalidConfig
			err := tt.call()
			if !errors.As(err, &cfgErr) || cfgErr.Field != tt.field {
				t.Fatalf("want ErrInvalidConfig{Field: %s}, got %v", tt.field, err)
			}
		})
	}
}

func TestCoverage964_OVSAdapter_AddFlowControllerFailure(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)
	rule := testFlowRule()

	err := adapter.AddFlow(context.Background(), "br0", rule)
	var flowErr ErrFlowRule
	if !errors.As(err, &flowErr) {
		t.Fatalf("want ErrFlowRule, got %v", err)
	}
	if flowErr.Operation != "AddFlow" || flowErr.RuleID != rule.ID || flowErr.PortID != rule.PortID {
		t.Errorf("ErrFlowRule fields = %+v, want AddFlow for %s on %s", flowErr, rule.ID, rule.PortID)
	}
	if flowErr.Cause == nil {
		t.Error("ErrFlowRule should carry the controller error as its cause")
	}
	if _, tracked := adapter.ruleIndex.Load(rule.ID); tracked {
		t.Error("a rule that failed to install must not be tracked for deletion")
	}
}

func TestCoverage964_OVSAdapter_DeleteFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("untracked rule is a no-op", func(t *testing.T) {
		adapter := newUnreachableOVSAdapter(t)
		if err := adapter.DeleteFlow(ctx, "br0", "never-added"); err != nil {
			t.Fatalf("deleting an untracked rule should succeed, got %v", err)
		}
	})

	t.Run("controller failure keeps the rule tracked", func(t *testing.T) {
		adapter := newUnreachableOVSAdapter(t)
		adapter.ruleIndex.Store("rule-1", "in_port=port-1")

		err := adapter.DeleteFlow(ctx, "br0", "rule-1")
		var flowErr ErrFlowRule
		if !errors.As(err, &flowErr) || flowErr.Operation != "DeleteFlow" || flowErr.RuleID != "rule-1" {
			t.Fatalf("want ErrFlowRule{Operation: DeleteFlow, RuleID: rule-1}, got %v", err)
		}
		if flowErr.Cause == nil {
			t.Error("ErrFlowRule should carry the controller error as its cause")
		}
		if _, tracked := adapter.ruleIndex.Load("rule-1"); !tracked {
			t.Error("a rule whose deletion failed must stay tracked so it can be retried")
		}
	})
}

func TestCoverage964_OVSAdapter_ModifyFlowReturnsAddError(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)
	adapter.ruleIndex.Store("rule-1", "in_port=port-1")

	// The delete half fails and is only logged; the add half's error is returned.
	err := adapter.ModifyFlow(context.Background(), "br0", testFlowRule())
	var flowErr ErrFlowRule
	if !errors.As(err, &flowErr) || flowErr.Operation != "AddFlow" {
		t.Fatalf("want ErrFlowRule{Operation: AddFlow}, got %v", err)
	}
}

func TestCoverage964_OVSAdapter_GetFlowsControllerFailure(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)

	rules, err := adapter.GetFlows(context.Background(), "br0")
	var flowErr ErrFlowRule
	if !errors.As(err, &flowErr) || flowErr.Operation != "GetFlows" || flowErr.Cause == nil {
		t.Fatalf("want ErrFlowRule{Operation: GetFlows} with a cause, got %v", err)
	}
	if rules != nil {
		t.Errorf("GetFlows should return no rules on failure, got %v", rules)
	}
}

func TestCoverage964_OVSAdapter_SetPortVLANControllerFailure(t *testing.T) {
	adapter := newUnreachableOVSAdapter(t)

	err := adapter.SetPortVLAN(context.Background(), "br0", "port-1", 42)
	var vlanErr ErrVLANFailed
	if !errors.As(err, &vlanErr) {
		t.Fatalf("want ErrVLANFailed, got %v", err)
	}
	if vlanErr.PortID != "port-1" || vlanErr.ToVLAN != 42 || vlanErr.Cause == nil {
		t.Errorf("ErrVLANFailed = %+v, want port-1 to VLAN 42 with a cause", vlanErr)
	}
}
