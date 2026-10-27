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

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestPbToOvsFlowMod_IPAndTransportMatches(t *testing.T) {
	tests := []struct {
		name  string
		match *platformv1.FlowMatch
		want  string
	}{
		{
			name:  "IPv4 addresses imply the IPv4 EtherType",
			match: &platformv1.FlowMatch{IpSrc: "10.0.0.0/24", IpDst: "10.0.1.5"},
			want:  "dl_type=0x0800,nw_src=10.0.0.0/24,nw_dst=10.0.1.5",
		},
		{
			name:  "IPv6 addresses imply the IPv6 EtherType",
			match: &platformv1.FlowMatch{IpSrc: "2001:db8::/32", IpDst: "2001:db8::1"},
			want:  "dl_type=0x86dd,ipv6_src=2001:db8::/32,ipv6_dst=2001:db8::1",
		},
		{
			name:  "ip_proto alone implies IPv4",
			match: &platformv1.FlowMatch{IpProto: 47},
			want:  "dl_type=0x0800,nw_proto=47",
		},
		{
			name:  "an explicit EtherType is kept",
			match: &platformv1.FlowMatch{EthType: 0x0806},
			want:  "dl_type=0x0806",
		},
		{
			name:  "TCP ports imply protocol 6",
			match: &platformv1.FlowMatch{TcpSrc: 1024, TcpDst: 443},
			want:  "dl_type=0x0800,nw_proto=6,tp_src=1024,tp_dst=443",
		},
		{
			name:  "UDP ports imply protocol 17",
			match: &platformv1.FlowMatch{UdpSrc: 68, UdpDst: 67},
			want:  "dl_type=0x0800,nw_proto=17,tp_src=68,tp_dst=67",
		},
		{
			name:  "UDP over IPv6",
			match: &platformv1.FlowMatch{IpDst: "2001:db8::53", UdpDst: 53},
			want:  "dl_type=0x86dd,nw_proto=17,ipv6_dst=2001:db8::53,tp_dst=53",
		},
		{
			name: "every layer, prerequisites first",
			match: &platformv1.FlowMatch{
				InPort: "1", VlanId: 10, EthSrc: "00:11:22:33:44:55", EthDst: "66:77:88:99:aa:bb",
				EthType: 0x0800, IpProto: 6, IpSrc: "10.0.0.1", IpDst: "10.0.0.2", TcpDst: 22,
			},
			want: "in_port=1,dl_vlan=10,dl_src=00:11:22:33:44:55,dl_dst=66:77:88:99:aa:bb," +
				"dl_type=0x0800,nw_proto=6,nw_src=10.0.0.1,nw_dst=10.0.0.2,tp_dst=22",
		},
	}

	svc := &SDNService{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowMod, err := svc.pbToOvsFlowMod(&platformv1.FlowConfig{Match: tt.match})
			require.NoError(t, err)
			assert.Equal(t, tt.want, flowMod.Match)
		})
	}
}

func TestPbToOvsFlowMod_Actions(t *testing.T) {
	tests := []struct {
		name   string
		action *platformv1.FlowAction
		want   string
	}{
		{
			name:   "SET_FIELD writes the value into the field",
			action: &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "ip_dst", Value: "10.0.0.9"},
			want:   "set_field:10.0.0.9->ip_dst",
		},
		{
			name:   "SET_FIELD keeps a MAC value whole",
			action: &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "eth_dst", Value: "00:11:22:33:44:55"},
			want:   "set_field:00:11:22:33:44:55->eth_dst",
		},
		{
			name:   "GOTO_TABLE continues at a later table",
			action: &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 3},
			want:   "goto_table:3",
		},
		{
			name:   "CONTROLLER sends the packet to the controller",
			action: &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
			want:   "CONTROLLER",
		},
		{
			name:   "OUTPUT with no port forwards NORMAL",
			action: &platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT},
			want:   "NORMAL",
		},
	}

	svc := &SDNService{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowMod, err := svc.pbToOvsFlowMod(&platformv1.FlowConfig{
				Table:   platformv1.FlowTable_FLOW_TABLE_0,
				Actions: []*platformv1.FlowAction{tt.action},
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, flowMod.Actions)
		})
	}

	t.Run("actions keep their order", func(t *testing.T) {
		flowMod, err := svc.pbToOvsFlowMod(&platformv1.FlowConfig{
			Table: platformv1.FlowTable_FLOW_TABLE_0,
			Actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "ip_src", Value: "10.0.0.1"},
				{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
				{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 2},
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "set_field:10.0.0.1->ip_src,CONTROLLER,goto_table:2", flowMod.Actions)
	})
}

func TestPbToOvsFlowMod_CarriesTimeouts(t *testing.T) {
	flowMod, err := (&SDNService{}).pbToOvsFlowMod(&platformv1.FlowConfig{IdleTimeout: 30, HardTimeout: 300})
	require.NoError(t, err)
	assert.Equal(t, 30, flowMod.IdleTimeout)
	assert.Equal(t, 300, flowMod.HardTimeout)
}

func TestPbToOvsFlowMod_RefusesWhatOVSCannotInstallExactly(t *testing.T) {
	tcpRule := func(m *platformv1.FlowMatch) *platformv1.FlowConfig { return &platformv1.FlowConfig{Match: m} }
	action := func(a *platformv1.FlowAction) *platformv1.FlowConfig {
		return &platformv1.FlowConfig{Table: platformv1.FlowTable_FLOW_TABLE_1, Actions: []*platformv1.FlowAction{a}}
	}

	tests := []struct {
		name   string
		config *platformv1.FlowConfig
		field  string
	}{
		{"tcp and udp ports", tcpRule(&platformv1.FlowMatch{TcpDst: 80, UdpDst: 53}), "match"},
		{"ip_proto conflicts with tcp ports", tcpRule(&platformv1.FlowMatch{IpProto: 17, TcpDst: 80}), "match.ip_proto"},
		{"mixed address families", tcpRule(&platformv1.FlowMatch{IpSrc: "10.0.0.1", IpDst: "2001:db8::1"}), "match.ip_dst"},
		{"address family against eth_type", tcpRule(&platformv1.FlowMatch{EthType: 0x86dd, IpSrc: "10.0.0.1"}), "match.ip_src"},
		{"not an address", tcpRule(&platformv1.FlowMatch{IpSrc: "not-an-ip"}), "match.ip_src"},
		{"an address with a zone", tcpRule(&platformv1.FlowMatch{IpDst: "fe80::1%eth0"}), "match.ip_dst"},
		{"match metadata", tcpRule(&platformv1.FlowMatch{Metadata: map[string]string{"ct_state": "+trk"}}), "match.metadata"},
		{"VLAN out of range", tcpRule(&platformv1.FlowMatch{VlanId: 4096}), "match.vlan_id"},
		{"port out of range", tcpRule(&platformv1.FlowMatch{TcpDst: 70000}), "match.tcp_dst"},
		{"priority out of range", &platformv1.FlowConfig{Priority: 70000}, "priority"},
		{"unspecified action", action(&platformv1.FlowAction{}), "actions[0].type"},
		{"SET_FIELD with no value", action(&platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "ip_dst"}), "actions.field"},
		{"SET_FIELD splicing an action", action(&platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "ip_dst", Value: "10.0.0.1,output:9"}), "actions.field"},
		{"SET_VLAN out of range", action(&platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, VlanId: 5000}), "actions.vlan_id"},
		{"GOTO_TABLE to its own table", action(&platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 2}), "actions.table_id"},
		{"GOTO_TABLE past OFPTT_MAX", action(&platformv1.FlowAction{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 255}), "actions.table_id"},
	}

	svc := &SDNService{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flowMod, err := svc.pbToOvsFlowMod(tt.config)
			assert.Nil(t, flowMod)
			var unencodable ErrUnencodableFlow
			require.True(t, errors.As(err, &unencodable), "err = %v", err)
			assert.Equal(t, tt.field, unencodable.Field)
		})
	}
}

func TestSDNService_AddFlow_RefusesAnUnencodableFlowBeforeOVS(t *testing.T) {
	mockClient := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mockClient)
	svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

	resp, err := svc.AddFlow(context.Background(), &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId: "br0",
			Match:    &platformv1.FlowMatch{TcpDst: 80, UdpDst: 53},
		},
	})
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, mockClient.calls["AddFlow"])
}

// TestSDNService_FlowRoundTrip adds a flow and lists it back through the
// OVS mock: the listing reports the config that was added, and the
// flow's traffic counters.
func TestSDNService_FlowRoundTrip(t *testing.T) {
	configs := map[string]*platformv1.FlowConfig{
		"TCP over IPv4 with every action": {
			Table:       platformv1.FlowTable_FLOW_TABLE_1,
			Priority:    200,
			IdleTimeout: 30,
			HardTimeout: 300,
			Match: &platformv1.FlowMatch{
				InPort: "1", VlanId: 10, EthSrc: "00:11:22:33:44:55", EthDst: "66:77:88:99:aa:bb",
				EthType: 0x0800, IpProto: 6, IpSrc: "10.0.0.0/24", IpDst: "10.0.1.5", TcpSrc: 1024, TcpDst: 443,
			},
			Actions: []*platformv1.FlowAction{
				{Type: platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, VlanId: 20},
				{Type: platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, Field: "ip_dst", Value: "10.0.0.9"},
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "2"},
				{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT},
				{Type: platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
				{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
				{Type: platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, TableId: 3},
			},
		},
		"UDP over IPv6 dropped": {
			Table:    platformv1.FlowTable_FLOW_TABLE_0,
			Priority: 10,
			Match:    &platformv1.FlowMatch{EthType: 0x86dd, IpProto: 17, IpSrc: "2001:db8::/32", UdpSrc: 68, UdpDst: 67},
			Actions:  []*platformv1.FlowAction{{Type: platformv1.FlowActionType_FLOW_ACTION_DROP}},
		},
	}

	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			var installed []*ovs.Flow
			mockClient := NewConfigurableMockOVSClient()
			mockClient.OnAddFlow(func(_ context.Context, _ string, mod *ovs.FlowMod) error {
				installed = append(installed, &ovs.Flow{
					Table: mod.Table, Priority: mod.Priority, Match: mod.Match, Actions: mod.Actions,
					IdleAge: mod.IdleTimeout, HardAge: mod.HardTimeout, Cookie: mod.Cookie,
					PacketCount: 12, ByteCount: 3400, Duration: 56,
				})
				return nil
			})
			mockClient.OnListFlows(func(context.Context, string) ([]*ovs.Flow, error) { return installed, nil })
			svc := newTestSDNService(mockClient)
			svc.bridges["br0"] = &bridgeResource{id: "uuid-br0", name: "br0"}

			config.BridgeId = "br0"
			added, err := svc.AddFlow(context.Background(), &platformv1.AddFlowRequest{Config: config})
			require.NoError(t, err)

			listed, err := svc.ListFlows(context.Background(), &platformv1.ListFlowsRequest{BridgeId: "br0"})
			require.NoError(t, err)
			require.Len(t, listed.GetFlows(), 1)
			flow := listed.GetFlows()[0]
			assert.Equal(t, added.GetFlow().GetId(), flow.GetId())
			assert.True(t, proto.Equal(config, flow.GetConfig()), "listed %v\nadded  %v", flow.GetConfig(), config)
			assert.True(t, proto.Equal(&platformv1.FlowStats{PacketCount: 12, ByteCount: 3400, DurationSeconds: 56}, flow.GetStats()))
		})
	}
}

func TestOvsMatchToPb_KeepsTermsWithNoField(t *testing.T) {
	match := ovsMatchToPb("ct_state=+trk+est,reg0=0x1,ip,dl_vlan=abc,nw_proto=6,tp_dst=22")
	assert.Equal(t, map[string]string{"ct_state": "+trk+est", "reg0": "0x1", "ip": "", "dl_vlan": "abc"}, match.GetMetadata())
	assert.Equal(t, uint32(6), match.GetIpProto())
	assert.Equal(t, uint32(22), match.GetTcpDst())
	assert.Nil(t, ovsMatchToPb(""), "an empty match string has no FlowMatch")
}

func TestOvsActionsToPb_LeavesOutActionsWithNoType(t *testing.T) {
	actions := ovsActionsToPb("resubmit(,2),CONTROLLER:65535,output:3,mod_vlan_vid:x")
	want := []*platformv1.FlowAction{
		{Type: platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
		{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "3"},
	}
	require.Len(t, actions, len(want))
	for i := range want {
		assert.True(t, proto.Equal(want[i], actions[i]), "action %d = %v", i, actions[i])
	}
	assert.Nil(t, ovsActionsToPb(""))
}
