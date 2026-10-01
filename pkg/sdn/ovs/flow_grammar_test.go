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
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// The flow grammar used to skip any match field or action it did not know,
// so a flow was installed broader (a dropped match) or weaker (a dropped
// action) than it was written. The gateway load balancer's register mark
// and resubmit, the NAT service's uplink selector register, and the zone
// flows' ICMPv6 types and IPv6 destinations were all being dropped (#718).

func TestParseActions_RegisterLoadResubmitSetField(t *testing.T) {
	// Golden bytes decoded by `ovs-ofctl parse-actions OpenFlow13` to the
	// input string (Open vSwitch 3.3).
	tests := map[string]string{
		"load:1->NXM_NX_REG1[0]":               "ffff00180000232000070000000102040000000000000001",
		"load:5->reg2[3..6]":                   "ffff001800002320000700c3000104040000000000000005",
		"load:7->NXM_NX_REG0[]":                "ffff0018000023200007001f000100040000000000000007",
		"resubmit(,20)":                        "ffff001000002320000efff814000000",
		"resubmit(3,28)":                       "ffff001000002320000e00031c000000",
		"resubmit(in_port,9)":                  "ffff001000002320000efff809000000",
		"set_field:0e:1b:00:00:00:aa->eth_src": "00190010800008060e1b000000aa0000",
	}
	for spec, golden := range tests {
		actions, err := parseActionsString(spec)
		require.NoError(t, err, spec)
		require.Len(t, actions, 1, spec)
		data, err := actions[0].MarshalBinary()
		require.NoError(t, err)
		assert.Equal(t, golden, hex.EncodeToString(data), spec)
	}
}

func TestParseActions_RefusesWhatItCannotEncode(t *testing.T) {
	for _, spec := range []string{
		"load:1->NXM_NX_REG16[0]",      // no such register
		"load:1->NXM_OF_ETH_DST[]",     // not a register
		"load:x->reg1[0]",              // value
		"load:2->reg1[0]",              // value wider than the range
		"load:1->reg1[5..2]",           // reversed range
		"load:1->reg1[0",               // unterminated range
		"load:1",                       // no destination
		"resubmit(,)",                  // no table
		"resubmit(,255)",               // OFPTT_ALL is not a table
		"resubmit(70000,1)",            // port
		"resubmit(,1",                  // unterminated
		"set_field:1.2.3.4->tun_dst",   // destination
		"set_field:not-a-mac->eth_dst", // value
		"set_field:2001:db8::1->ip_src",
		"set_field:eth_src",
		"mod_nw_dst=192.0.2.1", // the typo the old parser hid
	} {
		_, err := parseActionsString(spec)
		var grammarErr *MessageError
		var encodeErr *openflow.MessageError
		assert.True(t, errors.As(err, &grammarErr) || errors.As(err, &encodeErr),
			"%s: want a typed refusal, got %v", spec, err)
	}
}

func TestParseMatch_RegistersICMPAndIPv6(t *testing.T) {
	match := openflow.NewMatch()
	require.NoError(t, parseMatchString(match,
		"reg1=0/0x1,dl_type=0x86dd,nw_proto=58,icmp_type=135,ipv6_dst=2001:db8::/64,ipv6_src=fe80::1"))
	assert.Equal(t,
		"reg1=0x0/0x1,dl_type=0x86dd,nw_proto=58,icmp_type=135,ipv6_dst=2001:db8::/64,ipv6_src=fe80::1",
		formatMatchString(match), "every field survives, and lists back as written")

	var reg, icmp6 *openflow.OXMField
	for i := range match.Fields {
		f := &match.Fields[i]
		switch {
		case f.Class == openflow.OFPXMCNxm1 && f.Field == 1:
			reg = f
		case f.Class == openflow.OFPXMCOpenflowBasic && f.Field == openflow.OFPXMTOFBICMPv6Type:
			icmp6 = f
		}
	}
	require.NotNil(t, reg, "reg1 is an NXM_NX_REG1 field")
	require.NotNil(t, icmp6, "icmp_type under nw_proto=58 is the ICMPv6 type")
	assert.Equal(t, []byte{135}, icmp6.Value)
}

func TestParseMatch_ICMPv4AndShorthands(t *testing.T) {
	match := openflow.NewMatch()
	require.NoError(t, parseMatchString(match, "icmp,icmp_type=8,icmp_code=0"))
	assert.Equal(t, "dl_type=0x0800,nw_proto=1,icmp_type=8,icmp_code=0", formatMatchString(match))

	match = openflow.NewMatch()
	require.NoError(t, parseMatchString(match, "udp,tp_src=53"))
	assert.Equal(t, uint8(openflow.OFPXMTOFBUDPSrc), match.Fields[2].Field,
		"a shorthand protocol picks the port field the way nw_proto does")

	for spec, want := range map[string]string{
		"ip":    "dl_type=0x0800",
		"ipv6":  "dl_type=0x86dd",
		"tcp6":  "dl_type=0x86dd,nw_proto=6",
		"icmp6": "dl_type=0x86dd,nw_proto=58",
	} {
		m := openflow.NewMatch()
		require.NoError(t, parseMatchString(m, spec))
		assert.Equal(t, want, formatMatchString(m), spec)
	}
}

func TestParseMatch_RefusesWhatItCannotEncode(t *testing.T) {
	for _, spec := range []string{
		"reg16=1",                 // no such register
		"reg1=x",                  // value
		"reg1=1/x",                // mask
		"icmp_type=300",           // a byte
		"ipv6_dst=10.0.0.1",       // not IPv6
		"ipv6_dst=::ffff:1.2.3.4", // IPv4-mapped is not an IPv6 destination
		"ipv6_src=2001:db8::/129",
		"tun_id=5", // a real ovs-ofctl field this grammar does not carry
		"arpx",
	} {
		err := parseMatchString(openflow.NewMatch(), spec)
		var msgErr *MessageError
		assert.ErrorAs(t, err, &msgErr, spec)
	}
}

func TestParseMatch_IPv6HostAndFullPrefix(t *testing.T) {
	for _, spec := range []string{"ipv6_dst=2001:db8::1", "ipv6_dst=2001:db8::1/128"} {
		m := openflow.NewMatch()
		require.NoError(t, parseMatchString(m, spec))
		require.Len(t, m.Fields, 1)
		assert.False(t, m.Fields[0].HasMask, "%s is an exact match", spec)
		assert.Equal(t, "ipv6_dst=2001:db8::1", formatMatchString(m))
	}
}
