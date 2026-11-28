package ovs

import (
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// transportPortFields returns the OFPXMC_OPENFLOW_BASIC TCP/UDP port fields of m.
func transportPortFields(m *openflow.Match) []openflow.OXMField {
	var out []openflow.OXMField
	for _, f := range m.Fields {
		if f.Class != openflow.OFPXMCOpenflowBasic {
			continue
		}
		switch int(f.Field) {
		case int(openflow.OFPXMTOFBUDPSrc), int(openflow.OFPXMTOFBUDPDst),
			int(openflow.OFPXMTOFBTCPSrc), int(openflow.OFPXMTOFBTCPDst):
			out = append(out, f)
		}
	}
	return out
}

var maskedTransportPortCases = []struct {
	match string
	token string
	field int
	value uint16
	mask  uint16
}{
	{"dl_type=0x0800,nw_proto=17,tp_dst=0x0400/0xfc00", "tp_dst=0x0400/0xfc00", int(openflow.OFPXMTOFBUDPDst), 0x0400, 0xfc00},
	{"dl_type=0x0800,nw_proto=17,tp_dst=0x8000/0x8000", "tp_dst=0x8000/0x8000", int(openflow.OFPXMTOFBUDPDst), 0x8000, 0x8000},
	{"dl_type=0x86dd,nw_proto=17,tp_dst=0x1000/0xf000", "tp_dst=0x1000/0xf000", int(openflow.OFPXMTOFBUDPDst), 0x1000, 0xf000},
	{"dl_type=0x0800,nw_proto=6,tp_dst=0x2000/0xe000", "tp_dst=0x2000/0xe000", int(openflow.OFPXMTOFBTCPDst), 0x2000, 0xe000},
	{"dl_type=0x0800,nw_proto=17,tp_src=0x4000/0xc000", "tp_src=0x4000/0xc000", int(openflow.OFPXMTOFBUDPSrc), 0x4000, 0xc000},
	{"dl_type=0x86dd,nw_proto=6,tp_src=0x0800/0xf800", "tp_src=0x0800/0xf800", int(openflow.OFPXMTOFBTCPSrc), 0x0800, 0xf800},
}

func TestParseMatchString_MaskedTransportPorts(t *testing.T) {
	for _, tc := range maskedTransportPortCases {
		t.Run(tc.match, func(t *testing.T) {
			m := openflow.NewMatch()
			require.NoError(t, parseMatchString(m, tc.match))
			fields := transportPortFields(m)
			require.Len(t, fields, 1)
			f := fields[0]
			assert.Equal(t, tc.field, int(f.Field))
			assert.True(t, f.HasMask)
			assert.Equal(t, uint8(4), f.Length)
			require.Len(t, f.Value, 2)
			require.Len(t, f.Mask, 2)
			assert.Equal(t, tc.value, openflow.ByteOrder.Uint16(f.Value))
			assert.Equal(t, tc.mask, openflow.ByteOrder.Uint16(f.Mask))
		})
	}

	t.Run("unmasked", func(t *testing.T) {
		m := openflow.NewMatch()
		require.NoError(t, parseMatchString(m, "dl_type=0x0800,nw_proto=17,tp_dst=67"))
		fields := transportPortFields(m)
		require.Len(t, fields, 1)
		f := fields[0]
		assert.Equal(t, int(openflow.OFPXMTOFBUDPDst), int(f.Field))
		assert.False(t, f.HasMask)
		assert.Equal(t, uint8(2), f.Length)
		require.Len(t, f.Value, 2)
		assert.Equal(t, uint16(67), openflow.ByteOrder.Uint16(f.Value))
	})
}

func TestParseMatchString_MaskedTransportPortsRefused(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		{"tp_dst=0x0401/0xfc00", "invalid tp_dst"},  // value bits outside the mask
		{"tp_dst=0x0400/0x0000", "invalid tp_dst"},  // zero mask
		{"tp_dst=0x10000/0xffff", "invalid tp_dst"}, // over 16 bits
		{"tp_dst=0x0400/zz", "invalid tp_dst"},
		{"tp_src=0x4001/0xc000", "invalid tp_src"},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			err := parseMatchString(openflow.NewMatch(), "dl_type=0x0800,nw_proto=17,"+tc.token)
			require.Error(t, err)
			var msgErr *MessageError
			require.ErrorAs(t, err, &msgErr)
			assert.Contains(t, msgErr.Msg, tc.want)
		})
	}
}

func TestFormatMatchString_MaskedTransportPortsRoundTrip(t *testing.T) {
	for _, tc := range maskedTransportPortCases {
		t.Run(tc.match, func(t *testing.T) {
			m := openflow.NewMatch()
			require.NoError(t, parseMatchString(m, tc.match))
			got := formatMatchString(m)
			assert.Contains(t, strings.Split(got, ","), tc.token, "formatted %q", got)
		})
	}

	t.Run("unmasked", func(t *testing.T) {
		m := openflow.NewMatch()
		require.NoError(t, parseMatchString(m, "dl_type=0x0800,nw_proto=17,tp_dst=67"))
		got := formatMatchString(m)
		assert.Contains(t, strings.Split(got, ","), "tp_dst=67", "formatted %q", got)
	})
}

func TestConvertToOpenFlow_ZoneFlowRulesWithBootServers(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	gs.SetProvisioningBootServers(net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10"))
	gs.AddProvisioningBootHTTPPorts(8080, 8081, 10809)

	ingresses := []zoneflows.Ingress{zoneflows.Untagged(100), zoneflows.Tagged(100)}
	for _, in := range ingresses {
		rules := gs.Generate("7", zone.ZoneProvisioning, in)
		require.NotEmpty(t, rules)
		masked, tftp := 0, 0
		for _, r := range rules {
			if strings.Contains(r.Match, "tp_dst=0x") {
				masked++
			}
			fields := strings.Split(r.Match, ",")
			if slices.Contains(fields, "nw_proto=17") && slices.Contains(fields, "tp_dst=69") {
				tftp++
			}
			_, err := convertToOpenFlow(&FlowMod{
				Table:    r.Table,
				Priority: r.Priority,
				Match:    r.Match,
				Actions:  r.Actions,
				Cookie:   r.Cookie,
			})
			assert.NoError(t, err, "rule match=%q actions=%q cookie=%q", r.Match, r.Actions, r.Cookie)
		}
		assert.Equal(t, 0, masked, "no masked TFTP transfer-port rules: the boot server answers from port 69")
		assert.Equal(t, 2, tftp, "one exact UDP 69 rule per boot server (IPv4 and IPv6)")
	}
}
