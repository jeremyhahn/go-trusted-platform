package ovs

import (
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
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
