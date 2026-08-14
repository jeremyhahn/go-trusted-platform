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
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// newDisconnectedClient builds a client that has never connected, so group
// operations fail at ensureConnected without touching the network.
func newDisconnectedClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient("/nonexistent/db.sock")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestAddGroupValidation(t *testing.T) {
	client := newDisconnectedClient(t)
	ctx := context.Background()
	group := openflow.NewGroupMod(openflow.OFPGCAdd, openflow.OFPGTSelect, 1)

	if err := client.AddGroup(ctx, "", group); !errors.Is(err, ErrInvalidBridgeName) {
		t.Errorf("AddGroup empty bridge = %v", err)
	}
	if err := client.AddGroup(ctx, "br0", nil); !errors.Is(err, ErrInvalidFlow) {
		t.Errorf("AddGroup nil group = %v", err)
	}
	// Not connected: the connect attempt to the bogus endpoint fails.
	if err := client.AddGroup(ctx, "br0", group); err == nil {
		t.Error("AddGroup succeeded without a connection")
	}
}

func TestModifyGroupValidation(t *testing.T) {
	client := newDisconnectedClient(t)
	ctx := context.Background()
	group := openflow.NewGroupMod(openflow.OFPGCModify, openflow.OFPGTSelect, 1)

	if err := client.ModifyGroup(ctx, "", group); !errors.Is(err, ErrInvalidBridgeName) {
		t.Errorf("ModifyGroup empty bridge = %v", err)
	}
	if err := client.ModifyGroup(ctx, "br0", nil); !errors.Is(err, ErrInvalidFlow) {
		t.Errorf("ModifyGroup nil group = %v", err)
	}
	if err := client.ModifyGroup(ctx, "br0", group); err == nil {
		t.Error("ModifyGroup succeeded without a connection")
	}
}

func TestDeleteGroupValidation(t *testing.T) {
	client := newDisconnectedClient(t)
	ctx := context.Background()

	if err := client.DeleteGroup(ctx, "", 1); !errors.Is(err, ErrInvalidBridgeName) {
		t.Errorf("DeleteGroup empty bridge = %v", err)
	}
	if err := client.DeleteGroup(ctx, "br0", 1); err == nil {
		t.Error("DeleteGroup succeeded without a connection")
	}
}

func TestGetGroupDescValidation(t *testing.T) {
	client := newDisconnectedClient(t)
	ctx := context.Background()

	if _, err := client.GetGroupDesc(ctx, ""); !errors.Is(err, ErrInvalidBridgeName) {
		t.Errorf("GetGroupDesc empty bridge = %v", err)
	}
	if _, err := client.GetGroupDesc(ctx, "br0"); err == nil {
		t.Error("GetGroupDesc succeeded without a connection")
	}
}

// TestParseCTActionBareNAT proves the flow string parser understands the
// bare "nat" argument used by the load balancer divert flow
// ct(table=26,zone=7,nat). The encoded bytes were verified against Open
// vSwitch 3.3.4:
//
//	$ echo ffff002800002320002300000000000000071a0000000000\
//	  ffff0010000023200024000000000000 | ovs-ofctl parse-actions OpenFlow13
//	actions=ct(table=26,zone=7,nat)
func TestParseCTActionBareNAT(t *testing.T) {
	action, err := parseCTAction("ct(table=26,zone=7,nat)")
	if err != nil {
		t.Fatalf("parseCTAction: %v", err)
	}
	if action.RecircTable != 26 || action.Zone != 7 || action.Flags != 0 {
		t.Errorf("action = %+v", action)
	}
	if len(action.Actions) != 1 {
		t.Fatalf("nested actions = %d, want 1", len(action.Actions))
	}
	nat, ok := action.Actions[0].(*openflow.ActionNAT)
	if !ok {
		t.Fatalf("nested action is %T, want *openflow.ActionNAT", action.Actions[0])
	}
	if nat.Flags != 0 || nat.RangePresent != 0 {
		t.Errorf("bare nat = %+v, want zero flags and range", nat)
	}

	data, err := nat.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	const golden = "ffff0010000023200024000000000000"
	if got := hex.EncodeToString(data); got != golden {
		t.Errorf("bare nat bytes:\n got  %s\n want %s", got, golden)
	}
}

// TestParseCTActionRejectsUnknownArg guards the parser against silently
// dropping unsupported ct arguments.
func TestParseCTActionRejectsUnknownArg(t *testing.T) {
	if _, err := parseCTAction("ct(zone=7,frobnicate)"); err == nil {
		t.Error("parseCTAction accepted an unknown argument")
	}
}
