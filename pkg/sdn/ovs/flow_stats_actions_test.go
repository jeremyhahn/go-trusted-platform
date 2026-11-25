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

package ovs

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// TestFlowActionsFromStatsInstructions decodes the instructions a flow stats
// reply carries into the action string GetFlowStats sets on Flow.Actions, so
// a caller comparing installed actions sees what the switch holds.
func TestFlowActionsFromStatsInstructions(t *testing.T) {
	applyOutput := func(port uint32) []byte {
		t.Helper()
		data, err := openflow.NewInstructionApplyActions(openflow.NewActionOutput(port, 0)).MarshalBinary()
		if err != nil {
			t.Fatalf("marshal apply-actions(output:%d): %v", port, err)
		}
		return data
	}
	emptyApply, err := openflow.NewInstructionApplyActions().MarshalBinary()
	if err != nil {
		t.Fatalf("marshal empty apply-actions: %v", err)
	}
	gotoTable, err := openflow.NewInstructionGotoTable(1).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal goto-table: %v", err)
	}
	meter, err := openflow.NewInstructionMeter(1).MarshalBinary()
	if err != nil {
		t.Fatalf("marshal meter: %v", err)
	}

	tests := []struct {
		name         string
		instructions []byte
		want         string
	}{
		{"normal", applyOutput(openflow.OFPPNormal), "normal"},
		{"controller", applyOutput(openflow.OFPPController), "controller"},
		{"numeric port", applyOutput(3), "output:3"},
		{"no instructions", nil, "drop"},
		{"empty apply-actions", emptyApply, "drop"},
		// An instruction the renderer cannot express changes forwarding:
		// such a flow renders "" so it never equals a policy flow's actions.
		{"goto-table only", gotoTable, ""},
		{"meter + apply normal", append(append([]byte{}, meter...), applyOutput(openflow.OFPPNormal)...), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := flowActionsFromInstructions(tt.instructions); got != tt.want {
				t.Fatalf("flowActionsFromInstructions = %q, want %q", got, tt.want)
			}
		})
	}
}
