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
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// TestParseCTState tests the ct_state match grammar.
func TestParseCTState(t *testing.T) {
	tests := []struct {
		name      string
		spec      string
		wantValue uint32
		wantMask  uint32
		wantErr   bool
	}{
		{
			name:      "new and tracked",
			spec:      "+new+trk",
			wantValue: openflow.CTStateNew | openflow.CTStateTrk,
			wantMask:  openflow.CTStateNew | openflow.CTStateTrk,
		},
		{
			name:      "positive and negative bits",
			spec:      "+new-est+trk",
			wantValue: openflow.CTStateNew | openflow.CTStateTrk,
			wantMask:  openflow.CTStateNew | openflow.CTStateEst | openflow.CTStateTrk,
		},
		{
			name:      "established tracked",
			spec:      "+est+trk",
			wantValue: openflow.CTStateEst | openflow.CTStateTrk,
			wantMask:  openflow.CTStateEst | openflow.CTStateTrk,
		},
		{
			name:      "all bit names",
			spec:      "+new+est+rel+rpl+inv+trk+snat+dnat",
			wantValue: 0xff,
			wantMask:  0xff,
		},
		{name: "empty", spec: "", wantErr: true},
		{name: "missing prefix", spec: "new+trk", wantErr: true},
		{name: "unknown bit", spec: "+bogus", wantErr: true},
		{name: "trailing prefix", spec: "+new+", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, mask, err := parseCTState(tt.spec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, value)
			assert.Equal(t, tt.wantMask, mask)
		})
	}
}

// TestParseCTMark tests the ct_mark match grammar.
func TestParseCTMark(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		wantMark uint32
		wantMask uint32
		wantErr  bool
	}{
		{name: "decimal exact", spec: "42", wantMark: 42, wantMask: 0xffffffff},
		{name: "hex exact", spec: "0xdead", wantMark: 0xdead, wantMask: 0xffffffff},
		{name: "hex with hex mask", spec: "0x1/0xff", wantMark: 0x1, wantMask: 0xff},
		{name: "decimal with decimal mask", spec: "5/255", wantMark: 5, wantMask: 255},
		{name: "invalid mark", spec: "junk", wantErr: true},
		{name: "invalid mask", spec: "1/junk", wantErr: true},
		{name: "mark overflow", spec: "0x1ffffffff", wantErr: true},
		{name: "mask overflow", spec: "1/0x1ffffffff", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mark, mask, err := parseCTMark(tt.spec)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMark, mark)
			assert.Equal(t, tt.wantMask, mask)
		})
	}
}

// TestParseMatchString_Conntrack tests ct field parsing through the public
// match-string entry point.
func TestParseMatchString_Conntrack(t *testing.T) {
	t.Run("ct_state ct_zone ct_mark parse", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "ct_state=+new+trk,ct_zone=7,ct_mark=0x5/0xff")
		require.NoError(t, err)

		want := openflow.NewMatch()
		want.AddCTState(openflow.CTStateNew|openflow.CTStateTrk, openflow.CTStateNew|openflow.CTStateTrk)
		want.AddCTZone(7)
		want.AddCTMark(0x5, 0xff)

		gotBytes, err := match.MarshalBinary()
		require.NoError(t, err)
		wantBytes, err := want.MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, wantBytes, gotBytes)
	})

	t.Run("invalid ct_state", func(t *testing.T) {
		err := parseMatchString(openflow.NewMatch(), "ct_state=bogus")
		require.Error(t, err)
	})

	t.Run("invalid ct_zone", func(t *testing.T) {
		err := parseMatchString(openflow.NewMatch(), "ct_zone=70000")
		require.Error(t, err)
	})

	t.Run("invalid ct_mark", func(t *testing.T) {
		err := parseMatchString(openflow.NewMatch(), "ct_mark=zz")
		require.Error(t, err)
	})
}

// TestSplitTopLevel tests paren-aware action splitting.
func TestSplitTopLevel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{name: "plain", in: "a,b,c", want: []string{"a", "b", "c"}},
		{name: "single", in: "drop", want: []string{"drop"}},
		{name: "nested parens", in: "ct(commit,zone=5),goto_table:30", want: []string{"ct(commit,zone=5)", "goto_table:30"}},
		{
			name: "doubly nested",
			in:   "ct(commit,zone=5,nat(src=192.0.2.1:1-2)),goto_table:30",
			want: []string{"ct(commit,zone=5,nat(src=192.0.2.1:1-2))", "goto_table:30"},
		},
		{name: "unbalanced close ignored", in: "a),b", want: []string{"a)", "b"}},
		{name: "empty", in: "", want: []string{""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, splitTopLevel(tt.in))
		})
	}
}

// buildStructured constructs an openflow.FlowMod directly with the
// structured builders, mirroring what the parser should produce.
func buildStructured(table uint8, priority uint16, build func(f *openflow.FlowMod)) *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.TableID = table
	f.Priority = priority
	build(f)
	return f
}

// TestConvertToOpenFlow_ConntrackRoundTrip proves the string grammar by
// byte-comparing parser output against FlowMods built directly with the
// structured (golden-validated) encoders.
func TestConvertToOpenFlow_ConntrackRoundTrip(t *testing.T) {
	mustAddr := func(s string) netip.Addr {
		addr, err := netip.ParseAddr(s)
		require.NoError(t, err)
		return addr
	}

	tests := []struct {
		name string
		flow *FlowMod
		want *openflow.FlowMod
	}{
		{
			name: "ct gate flow",
			flow: &FlowMod{
				Table:    20,
				Priority: 100,
				Match:    "dl_vlan=100,dl_type=0x0800",
				Actions:  "ct(table=21,zone=11)",
			},
			want: buildStructured(20, 100, func(f *openflow.FlowMod) {
				f.Match.AddVLANVid(100)
				f.Match.AddEthType(0x0800)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionCT(0, 11, 21)))
			}),
		},
		{
			name: "ct commit with goto",
			flow: &FlowMod{
				Table:    21,
				Priority: 100,
				Match:    "ct_state=+new+trk,dl_vlan=100,dl_type=0x0800,nw_dst=10.0.200.0/24",
				Actions:  "ct(commit,zone=11),goto_table:30",
			},
			want: buildStructured(21, 100, func(f *openflow.FlowMod) {
				trk := openflow.CTStateNew | openflow.CTStateTrk
				f.Match.AddCTState(trk, trk)
				f.Match.AddVLANVid(100)
				f.Match.AddEthType(0x0800)
				_, ipNet, err := net.ParseCIDR("10.0.200.0/24")
				require.NoError(t, err)
				f.Match.AddIPv4DstMasked(ipNet.IP, ipNet.Mask)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionCTCommit(11)),
					openflow.NewInstructionGotoTable(30))
			}),
		},
		{
			name: "snat commit",
			flow: &FlowMod{
				Table:    25,
				Priority: 100,
				Match:    "ct_state=+new+trk,dl_type=0x0800,nw_src=10.0.100.0/24",
				Actions:  "ct(commit,zone=9,nat(src=203.0.113.10:1024-65535)),goto_table:30",
			},
			want: buildStructured(25, 100, func(f *openflow.FlowMod) {
				trk := openflow.CTStateNew | openflow.CTStateTrk
				f.Match.AddCTState(trk, trk)
				f.Match.AddEthType(0x0800)
				_, ipNet, err := net.ParseCIDR("10.0.100.0/24")
				require.NoError(t, err)
				f.Match.AddIPv4SrcMasked(ipNet.IP, ipNet.Mask)
				nat := openflow.NewActionNATSrc(mustAddr("203.0.113.10"), netip.Addr{}, 1024, 65535)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionCTCommit(9, nat)),
					openflow.NewInstructionGotoTable(30))
			}),
		},
		{
			name: "snat address range",
			flow: &FlowMod{
				Table:    25,
				Priority: 100,
				Match:    "dl_type=0x0800",
				Actions:  "ct(commit,zone=9,nat(src=203.0.113.10-203.0.113.20:1024-65535))",
			},
			want: buildStructured(25, 100, func(f *openflow.FlowMod) {
				f.Match.AddEthType(0x0800)
				nat := openflow.NewActionNATSrc(mustAddr("203.0.113.10"), mustAddr("203.0.113.20"), 1024, 65535)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionCTCommit(9, nat)))
			}),
		},
		{
			name: "dnat commit",
			flow: &FlowMod{
				Table:    25,
				Priority: 200,
				Match:    "ct_state=+new+trk,in_port=7,dl_type=0x0800,nw_proto=6,nw_dst=203.0.113.10,tp_dst=443",
				Actions:  "ct(commit,zone=9,nat(dst=10.0.100.5:8443)),goto_table:30",
			},
			want: buildStructured(25, 200, func(f *openflow.FlowMod) {
				trk := openflow.CTStateNew | openflow.CTStateTrk
				f.Match.AddCTState(trk, trk)
				f.Match.AddInPort(7)
				f.Match.AddEthType(0x0800)
				f.Match.AddIPProto(6)
				f.Match.AddIPv4Dst(net.ParseIP("203.0.113.10"))
				f.Match.AddTCPDst(443)
				nat := openflow.NewActionNATDst(mustAddr("10.0.100.5"), 8443)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionCTCommit(9, nat)),
					openflow.NewInstructionGotoTable(30))
			}),
		},
		{
			name: "goto only",
			flow: &FlowMod{
				Table:    20,
				Priority: 1,
				Actions:  "goto_table:30",
			},
			want: buildStructured(20, 1, func(f *openflow.FlowMod) {
				f.Instructions = append(f.Instructions, openflow.NewInstructionGotoTable(30))
			}),
		},
		{
			name: "group action",
			flow: &FlowMod{
				Table:    21,
				Priority: 50,
				Match:    "dl_type=0x0800",
				Actions:  "group:7",
			},
			want: buildStructured(21, 50, func(f *openflow.FlowMod) {
				f.Match.AddEthType(0x0800)
				f.Instructions = append(f.Instructions,
					openflow.NewInstructionApplyActions(openflow.NewActionGroup(7)))
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToOpenFlow(tt.flow)
			require.NoError(t, err)

			gotBytes, err := got.MarshalBinary()
			require.NoError(t, err)
			wantBytes, err := tt.want.MarshalBinary()
			require.NoError(t, err)

			assert.Equal(t, wantBytes, gotBytes)
		})
	}
}

// TestParseCTAction_Errors tests ct(...) action error handling.
func TestParseCTAction_Errors(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{name: "unterminated", spec: "ct(commit"},
		{name: "bad table", spec: "ct(table=999)"},
		{name: "bad zone", spec: "ct(zone=70000)"},
		{name: "unknown argument", spec: "ct(frobnicate)"},
		{name: "bad nested nat", spec: "ct(nat(src=not-an-ip))"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCTAction(tt.spec)
			require.Error(t, err)
		})
	}
}

// TestParseCTAction_Empty tests the bare ct() action.
func TestParseCTAction_Empty(t *testing.T) {
	action, err := parseCTAction("ct()")
	require.NoError(t, err)
	assert.Equal(t, uint16(0), action.Flags)
	assert.Equal(t, openflow.CTRecircNone, action.RecircTable)
	assert.Empty(t, action.Actions)
}

// TestParseNATAction_Errors tests nat(...) error handling.
func TestParseNATAction_Errors(t *testing.T) {
	tests := []struct {
		name string
		spec string
	}{
		{name: "unterminated", spec: "nat(src=1.2.3.4"},
		{name: "no direction", spec: "nat(1.2.3.4)"},
		{name: "empty value", spec: "nat(src=)"},
		{name: "bad direction", spec: "nat(both=1.2.3.4)"},
		{name: "ipv6 src", spec: "nat(src=2001:db8::1)"},
		{name: "bad src range max", spec: "nat(src=1.2.3.4-bogus)"},
		{name: "bad src port range", spec: "nat(src=1.2.3.4:a-b)"},
		{name: "bad src port range max", spec: "nat(src=1.2.3.4:1-b)"},
		{name: "bad dst addr", spec: "nat(dst=bogus)"},
		{name: "bad dst port", spec: "nat(dst=1.2.3.4:notaport)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseNATAction(tt.spec)
			require.Error(t, err)
		})
	}
}

// TestParseNATAction_SinglePort tests the single-port SNAT form.
func TestParseNATAction_SinglePort(t *testing.T) {
	nat, err := parseNATAction("nat(src=203.0.113.10:4000)")
	require.NoError(t, err)
	assert.Equal(t, uint16(4000), nat.ProtoMin)
	assert.Equal(t, uint16(4000), nat.ProtoMax)
	assert.Equal(t, openflow.NXNATFSrc, nat.Flags&openflow.NXNATFSrc)
}

// TestParseActions_InvalidComposite tests error propagation through the
// top-level action parser.
func TestParseActions_InvalidComposite(t *testing.T) {
	tests := []string{
		"ct(commit,zone=bogus)",
		"group:notanumber",
		"goto_table:999",
		"goto_table:notanumber",
	}
	for _, spec := range tests {
		t.Run(spec, func(t *testing.T) {
			_, _, err := parseActions(spec)
			require.Error(t, err)
		})
	}
}

// TestDeleteFlowsByCookie_Validation tests argument validation.
func TestDeleteFlowsByCookie_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowsByCookie(ctx, "", 0x1, ^uint64(0))
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("zero cookie mask", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowsByCookie(ctx, "br0", 0x1, 0)
		assert.ErrorIs(t, err, ErrInvalidCookieMask)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected.Store(false)
		err := client.DeleteFlowsByCookie(ctx, "br0", 0x1, ^uint64(0))
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("getOpenFlowClient failure", func(t *testing.T) {
		// Connected but no OpenFlow socket exists to dial.
		client, _ := setupTestClient(t)
		err := client.DeleteFlowsByCookie(ctx, "br0", 0x1, ^uint64(0))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get OpenFlow client")
	})
}

// TestDeleteFlowStrict_Validation tests argument validation and fail-fast
// conversion before any connection is attempted.
func TestDeleteFlowStrict_Validation(t *testing.T) {
	ctx := context.Background()

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowStrict(ctx, "", &FlowMod{Priority: 1})
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("nil flow", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowStrict(ctx, "br0", nil)
		assert.ErrorIs(t, err, ErrInvalidFlow)
	})

	t.Run("invalid match fails before dialing", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowStrict(ctx, "br0", &FlowMod{Match: "in_port=bogus"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to convert flow")
	})

	t.Run("invalid cookie fails before dialing", func(t *testing.T) {
		client, _ := setupTestClient(t)
		err := client.DeleteFlowStrict(ctx, "br0", &FlowMod{Cookie: "not-a-cookie"})
		var invalid *ErrInvalidCookie
		require.ErrorAs(t, err, &invalid)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected.Store(false)
		err := client.DeleteFlowStrict(ctx, "br0", &FlowMod{Priority: 1, Cookie: "0xf1be000100000000"})
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("getOpenFlowClient failure", func(t *testing.T) {
		// Connected but no OpenFlow socket exists to dial.
		client, _ := setupTestClient(t)
		err := client.DeleteFlowStrict(ctx, "br0", &FlowMod{Priority: 1, Cookie: "0xf1be000100000000"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get OpenFlow client")
	})
}
