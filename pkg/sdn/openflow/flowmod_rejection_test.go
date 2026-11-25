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

package openflow

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ofpbrcIsSlave is OFPBRC_IS_SLAVE: the switch treats this controller as a
// slave and refuses state-changing messages from it.
const ofpbrcIsSlave = 10

func newPriorityFlow() *FlowMod {
	flow := NewFlowMod(0)
	flow.Priority = 100
	return flow
}

// TestClient_FlowModWritesReportSwitchRejection checks that an OFPT_ERROR the
// switch sends for a single flow mod is returned even though the barrier
// that follows it succeeds.
func TestClient_FlowModWritesReportSwitchRejection(t *testing.T) {
	cases := []struct {
		name  string
		write func(*Client, context.Context, *FlowMod) error
	}{
		{"AddFlow", (*Client).AddFlow},
		{"DeleteFlow", (*Client).DeleteFlow},
		{"DeleteFlowStrict", (*Client).DeleteFlowStrict},
		{"ModifyFlow", (*Client).ModifyFlow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := connectMock(t)
			server.failFlowModAt(OFPETBadRequest, ofpbrcIsSlave, 0)

			err := tc.write(client, context.Background(), newPriorityFlow())

			var ofErr *OFError
			require.True(t, errors.As(err, &ofErr), "a rejected flow mod must not report success: %v", err)
			assert.Equal(t, uint16(OFPETBadRequest), ofErr.Type)
			assert.Equal(t, uint16(ofpbrcIsSlave), ofErr.Code)
			assert.Equal(t, 1, server.getReceivedBarriers())
			assert.Len(t, server.getReceivedFlowMods(), 1)
		})
	}
}

// TestClient_DeleteFlowStrictAfterRejectionSucceeds checks that the xid of a
// rejected flow mod is unregistered, so a later write on the same client is
// not charged with the earlier error.
func TestClient_DeleteFlowStrictAfterRejectionSucceeds(t *testing.T) {
	server, client := connectMock(t)
	server.failFlowModAt(OFPETBadRequest, ofpbrcIsSlave, 0)

	var ofErr *OFError
	err := client.DeleteFlowStrict(context.Background(), newPriorityFlow())
	require.True(t, errors.As(err, &ofErr), "a rejected strict delete must not report success: %v", err)

	require.NoError(t, client.DeleteFlowStrict(context.Background(), newPriorityFlow()))
	assert.Len(t, server.getReceivedFlowMods(), 2)
}

// TestClient_FlowModRejectionWithFlowModFailed checks that the switch's own
// error type and code reach the caller.
func TestClient_FlowModRejectionWithFlowModFailed(t *testing.T) {
	server, client := connectMock(t)
	server.failFlowModAt(OFPETFlowModFailed, 6, 0) // OFPFMFC_BAD_COMMAND

	err := client.AddFlow(context.Background(), newPriorityFlow())

	var ofErr *OFError
	require.True(t, errors.As(err, &ofErr), "a rejected flow add must not report success: %v", err)
	assert.Equal(t, uint16(OFPETFlowModFailed), ofErr.Type)
	assert.Equal(t, uint16(6), ofErr.Code)
}

// TestClient_GroupModWritesReportSwitchRejection checks that an OFPT_ERROR the
// switch sends for a group mod is returned even though the barrier succeeds.
func TestClient_GroupModWritesReportSwitchRejection(t *testing.T) {
	newGroup := func() *GroupMod {
		group := NewGroupMod(OFPGCAdd, OFPGTSelect, 10)
		group.AddBucket(1, NewActionOutput(1, 0))
		return group
	}
	cases := []struct {
		name  string
		write func(*Client) error
	}{
		{"AddGroup", func(c *Client) error { return c.AddGroup(context.Background(), newGroup()) }},
		{"ModifyGroup", func(c *Client) error { return c.ModifyGroup(context.Background(), newGroup()) }},
		{"DeleteGroup", func(c *Client) error { return c.DeleteGroup(context.Background(), 10) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := connectMock(t)
			server.mu.Lock()
			server.sendErrorOnGroupMod = true
			server.errorType = OFPETGroupModFailed
			server.errorCode = 0
			server.mu.Unlock()

			err := tc.write(client)

			var ofErr *OFError
			require.True(t, errors.As(err, &ofErr), "a rejected group mod must not report success: %v", err)
			assert.Equal(t, uint16(OFPETGroupModFailed), ofErr.Type)
			assert.Len(t, server.getReceivedGroupMods(), 1)
		})
	}
}
