package ovs

import (
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertToOpenFlow_ZoneFlowRules feeds every rule the zone generators
// emit for an OpenFlow port number through the encoder: a rule the switch
// cannot take (a named in_port, a non-numeric cookie) fails the whole batch
// a device registration installs (#1694).
func TestConvertToOpenFlow_ZoneFlowRules(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		BridgeName: "br0",
		Quarantine: zoneflows.QuarantineConfig{
			DNSServerIP:          net.ParseIP("10.0.0.53"),
			NotificationServerIP: net.ParseIP("10.0.0.80"),
			ScanningServerIPs:    []net.IP{net.ParseIP("10.0.0.90")},
			RemediationServerIPs: []net.IP{net.ParseIP("10.0.0.91")},
		},
	})
	gs.AddProvisioningBootHTTPPorts(8080, 8081, 10809)

	zones := []zone.Zone{
		zone.ZoneQuarantine,
		zone.ZoneProvisioning,
		zone.ZoneControlPlane,
		zone.ZoneManagement,
	}
	ingresses := []zoneflows.Ingress{zoneflows.Untagged(100), zoneflows.Tagged(100)}
	for _, z := range zones {
		for _, in := range ingresses {
			rules := gs.Generate("7", z, in)
			if len(rules) == 0 {
				t.Fatalf("zone %s: no rules generated", z)
			}
			for _, r := range rules {
				_, err := convertToOpenFlow(&FlowMod{
					Table:    r.Table,
					Priority: r.Priority,
					Match:    r.Match,
					Actions:  r.Actions,
					Cookie:   r.Cookie,
				})
				if err != nil {
					t.Errorf("zone %s: rule match=%q actions=%q cookie=%q: %v",
						z, r.Match, r.Actions, r.Cookie, err)
				}
			}
		}
	}
}

// TestParseMatchString_VLANTCI: vlan_tci's VID and CFI bits are OXM
// VLAN_VID (CFI is OFPVID_PRESENT), so the access-port spelling
// vlan_tci=0x0000/0x1fff is VLAN_VID=OFPVID_NONE; a full PCP mask on a
// tagged frame is an exact VLAN_PCP after its VLAN_VID prerequisite.
func TestParseMatchString_VLANTCI(t *testing.T) {
	type field struct {
		field uint8
		value []byte
		mask  []byte
	}
	cases := map[string][]field{
		"vlan_tci=0x0000/0x1fff": {{openflow.OFPXMTOFBVlanVid, []byte{0x00, 0x00}, nil}},
		"vlan_tci=0":             {{openflow.OFPXMTOFBVlanVid, []byte{0x00, 0x00}, nil}},
		"vlan_tci=0x1000/0x1000": {{openflow.OFPXMTOFBVlanVid, []byte{0x10, 0x00}, []byte{0x10, 0x00}}},
		"vlan_tci=0x1064/0x1fff": {{openflow.OFPXMTOFBVlanVid, []byte{0x10, 0x64}, nil}},
		"vlan_tci=0xb064": {
			{openflow.OFPXMTOFBVlanVid, []byte{0x10, 0x64}, nil},
			{openflow.OFPXMTOFBVlanPcp, []byte{0x05}, nil},
		},
		"vlan_tci=0x0000/0x0000": nil,
	}
	for spec, want := range cases {
		t.Run(spec, func(t *testing.T) {
			m := openflow.NewMatch()
			require.NoError(t, parseMatchString(m, spec))
			var got []field
			for _, f := range m.Fields {
				if f.Class == openflow.OFPXMCOpenflowBasic {
					got = append(got, field{f.Field, f.Value, f.Mask})
				}
			}
			assert.Equal(t, want, got)
		})
	}

	for _, bad := range []string{
		"vlan_tci=zz",
		"vlan_tci=0x10000",
		"vlan_tci=0x2000/0x2000", // partial PCP mask
		"vlan_tci=0xa000/0xe000", // a PCP with no tag to carry it
	} {
		assert.Error(t, parseMatchString(openflow.NewMatch(), bad), bad)
	}
}
