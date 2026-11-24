package zoneflows_test

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestQuarantine_CookiesAreNumeric checks every quarantine rule's cookie is
// a decimal or hex uint64: the OpenFlow encoder rejects anything else and
// fails the whole quarantine batch (#1694).
func TestQuarantine_CookiesAreNumeric(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	var cookies int
	for _, r := range gs.Generate("7", zone.ZoneQuarantine, zoneflows.Untagged(100)) {
		if r.Cookie == "" {
			continue
		}
		cookies++
		if _, err := strconv.ParseUint(r.Cookie, 0, 64); err != nil {
			t.Errorf("cookie %q of rule %q is not a uint64: %v", r.Cookie, r.Match, err)
		}
	}
	if cookies == 0 {
		t.Fatal("the quarantine default drop carries no cookie")
	}
}

// TestProvisioning_BootPortsReachOnlyBootServers pins that the PXE boot
// ports are open only to the boot servers: with none set they stay closed,
// with servers set every allowance names one, and an explicit inter-zone
// deny at matrix priority still wins for any other destination.
func TestProvisioning_BootPortsReachOnlyBootServers(t *testing.T) {
	ports := []uint16{8080, 8081, 10809}
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	gs.AddProvisioningBootHTTPPorts(ports...)

	portRules := func(rules []zoneflows.FlowRule, p uint16) []zoneflows.FlowRule {
		var out []zoneflows.FlowRule
		for _, r := range rules {
			if r.Actions == "drop" {
				continue
			}
			if v, ok := matchFields(r.Match)["tp_dst"]; ok && v == strconv.Itoa(int(p)) {
				out = append(out, r)
			}
		}
		return out
	}

	closed := gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100))
	for _, p := range ports {
		if rs := portRules(closed, p); len(rs) != 0 {
			t.Errorf("no boot server set, yet port %d is allowed by %q", p, rs[0].Match)
		}
	}

	gs.SetProvisioningBootServers(net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8:1::10"))
	rules := gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100))
	for _, p := range ports {
		var v4, v6 int
		for _, r := range portRules(rules, p) {
			f := matchFields(r.Match)
			switch {
			case f["nw_dst"] == "192.0.2.10":
				v4++
			case f["ipv6_dst"] == "2001:db8:1::10":
				v6++
			default:
				t.Errorf("port %d allowance %q is not scoped to a boot server", p, r.Match)
			}
		}
		if v4 == 0 || v6 == 0 {
			t.Errorf("port %d: want one allowance per boot server, got v4=%d v6=%d", p, v4, v6)
		}
	}

	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	rules = append(rules, deny)
	for _, p := range ports {
		pkt := map[string]string{"dl_type": "0x0800", "nw_proto": "6",
			"nw_dst": "198.51.100.7", "tp_dst": strconv.Itoa(int(p))}
		w, ok := winner(rules, pkt)
		if !ok {
			t.Fatalf("port %d: no rule matches the denied packet", p)
		}
		// The deny, or the zone's own default drop above it, must win: no
		// normal rule may forward the denied destination.
		if w.Actions != "drop" {
			t.Errorf("port %d: denied destination forwarded by %q (%s, priority %d), want a drop",
				p, w.Match, w.Actions, w.Priority)
		}
	}
}

// TestProvisioning_ServerPortsFailClosedWithoutServers pins that the
// provisioning template's DNS, ACME and package-repository allowances name a
// destination: with no server addresses configured they open nothing, so the
// inter-zone denies below them still drop traffic to a denied zone (#1896
// Codex round 1).
func TestProvisioning_ServerPortsFailClosedWithoutServers(t *testing.T) {
	type svcPort struct {
		proto string
		port  uint16
	}
	ports := []svcPort{
		{"6", 80}, {"6", 443}, {"6", 8443}, {"6", 9443},
		{"17", 53}, {"17", 8053}, {"17", 9053},
	}
	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	denied := func(p svcPort, dst string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": p.proto,
			"nw_dst": dst, "tp_dst": strconv.Itoa(int(p.port))}
	}

	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	rules := append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	for _, p := range ports {
		for _, r := range rules {
			if r.Actions == "drop" {
				continue
			}
			f := matchFields(r.Match)
			if f["tp_dst"] != strconv.Itoa(int(p.port)) {
				continue
			}
			if _, v4 := f["nw_dst"]; !v4 {
				if _, v6 := f["ipv6_dst"]; !v6 {
					t.Errorf("no server configured, yet port %d is open to any destination by %q (priority %d)",
						p.port, r.Match, r.Priority)
				}
			}
		}
		w, ok := winner(rules, denied(p, "198.51.100.7"))
		if !ok {
			t.Fatalf("port %d: no rule matches the denied packet", p.port)
		}
		if w.Actions != "drop" {
			t.Errorf("port %d: denied destination forwarded by %q (%s, priority %d), want a drop",
				p.port, w.Match, w.Actions, w.Priority)
		}
	}

	gs = zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Provisioning: zoneflows.ProvisioningConfig{ACMEServerIPs: []net.IP{net.ParseIP("192.0.2.20")}},
	})
	rules = append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	https := svcPort{"6", 443}
	if w, ok := winner(rules, denied(https, "192.0.2.20")); !ok || w.Actions != "normal" {
		t.Errorf("TCP 443 to the configured ACME server: winner %q (%s), want a normal rule", w.Match, w.Actions)
	}
	if w, ok := winner(rules, denied(https, "198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("TCP 443 to a denied destination with an ACME server set: winner %q (%s), want a drop", w.Match, w.Actions)
	}
}

// TestQuarantine_DNSFailsClosedWithoutServer: the quarantine DNS allow sits
// above the inter-zone denies, so it may only reach the configured DNS
// server; with none configured it opens nothing.
func TestQuarantine_DNSFailsClosedWithoutServer(t *testing.T) {
	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	dns := func(dst string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": "17", "nw_dst": dst, "tp_dst": "53"}
	}

	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	rules := append(gs.Generate("7", zone.ZoneQuarantine, zoneflows.Untagged(100)), deny)
	for _, r := range rules {
		if r.Actions == "drop" {
			continue
		}
		f := matchFields(r.Match)
		if f["tp_dst"] != "53" {
			continue
		}
		_, v4 := f["nw_dst"]
		_, v6 := f["ipv6_dst"]
		if !v4 && !v6 {
			t.Errorf("no DNS server configured, yet UDP 53 is open to any destination by %q (priority %d)", r.Match, r.Priority)
		}
	}
	if w, ok := winner(rules, dns("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 53 to a denied destination with no DNS server: winner %q (%s), want a drop", w.Match, w.Actions)
	}

	gs = zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{
		Quarantine: zoneflows.QuarantineConfig{DNSServerIP: net.ParseIP("192.0.2.53")},
	})
	rules = append(gs.Generate("7", zone.ZoneQuarantine, zoneflows.Untagged(100)), deny)
	if w, ok := winner(rules, dns("192.0.2.53")); !ok || w.Actions != "normal" {
		t.Errorf("UDP 53 to the configured DNS server: winner %q (%s), want a normal rule", w.Match, w.Actions)
	}
	if w, ok := winner(rules, dns("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 53 to a denied destination with a DNS server set: winner %q (%s), want a drop", w.Match, w.Actions)
	}
}

// TestProvisioning_TFTPReachesOnlyBootServers: the provisioning TFTP allow
// sits above the inter-zone denies, so it may only reach the boot servers;
// with none configured it opens nothing.
func TestProvisioning_TFTPReachesOnlyBootServers(t *testing.T) {
	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	tftp := func(dst string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": "17", "nw_dst": dst, "tp_dst": "69"}
	}

	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	rules := append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	for _, r := range rules {
		if r.Actions != "drop" && matchFields(r.Match)["tp_dst"] == "69" {
			t.Errorf("no boot server configured, yet UDP 69 is open by %q (priority %d)", r.Match, r.Priority)
		}
	}
	if w, ok := winner(rules, tftp("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 69 to a denied destination with no boot server: winner %q (%s), want a drop", w.Match, w.Actions)
	}

	gs.SetProvisioningBootServers(net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10"))
	rules = append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	for _, r := range rules {
		if r.Actions == "drop" {
			continue
		}
		f := matchFields(r.Match)
		if f["tp_dst"] != "69" {
			continue
		}
		if f["nw_dst"] != "192.0.2.10" && f["ipv6_dst"] != "2001:db8::10" {
			t.Errorf("UDP 69 allowed beyond the boot servers by %q (priority %d)", r.Match, r.Priority)
		}
	}
	if w, ok := winner(rules, tftp("192.0.2.10")); !ok || w.Actions != "normal" {
		t.Errorf("UDP 69 to the boot server: winner %q (%s), want a normal rule", w.Match, w.Actions)
	}
	if w, ok := winner(rules, tftp("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 69 to a denied destination with a boot server set: winner %q (%s), want a drop", w.Match, w.Actions)
	}
}

// The TFTP server answers each transfer from an ephemeral UDP port, so the
// device's ACKs to that port need an allowance: UDP 1024-65535, to the boot
// servers only.
func TestProvisioning_TFTPTransferPortReachesOnlyBootServers(t *testing.T) {
	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	udp4 := func(dst, port string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": "17", "nw_dst": dst, "tp_dst": port}
	}
	udp6 := func(dst, port string) map[string]string {
		return map[string]string{"dl_type": "0x86dd", "nw_proto": "17", "ipv6_dst": dst, "tp_dst": port}
	}

	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	rules := append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	if w, ok := winner(rules, udp4("192.0.2.10", "49152")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 49152 with no boot server: winner %q (%s), want a drop", w.Match, w.Actions)
	}

	gs.SetProvisioningBootServers(net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10"))
	rules = append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)
	for _, r := range rules {
		if strings.Contains(r.Match, "tp_dst=0x") {
			t.Logf("provisioning flow: priority=%d %s actions=%s", r.Priority, r.Match, r.Actions)
		}
	}
	for _, port := range []string{"49152", "1024", "65535"} {
		if w, ok := winner(rules, udp4("192.0.2.10", port)); !ok || w.Actions != "normal" {
			t.Errorf("UDP %s to the IPv4 boot server: winner %q (%s), want a normal rule", port, w.Match, w.Actions)
		}
		if w, ok := winner(rules, udp6("2001:db8::10", port)); !ok || w.Actions != "normal" {
			t.Errorf("UDP %s to the IPv6 boot server: winner %q (%s), want a normal rule", port, w.Match, w.Actions)
		}
	}
	if w, ok := winner(rules, udp4("198.51.100.7", "49152")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 49152 to a denied destination: winner %q (%s), want a drop", w.Match, w.Actions)
	}
	if w, ok := winner(rules, udp4("192.0.2.10", "1023")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 1023 to the boot server: winner %q (%s, priority %d), want a drop", w.Match, w.Actions, w.Priority)
	}
	tcp := map[string]string{"dl_type": "0x0800", "nw_proto": "6", "nw_dst": "192.0.2.10", "tp_dst": "49152"}
	if w, ok := winner(rules, tcp); !ok || w.Actions != "drop" {
		t.Errorf("TCP 49152 to the boot server: winner %q (%s), want a drop", w.Match, w.Actions)
	}
}

// matchFields splits an OVS match string into its key=value fields.
func matchFields(match string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(match, ",") {
		k, v, _ := strings.Cut(part, "=")
		if k != "" {
			out[k] = v
		}
	}
	return out
}

// winner returns the highest-priority rule whose dl_type, nw_proto, tp_dst,
// nw_dst and ipv6_dst fields all fit pkt; a field the rule omits matches
// anything, and a destination is a prefix or a single address.
func winner(rules []zoneflows.FlowRule, pkt map[string]string) (zoneflows.FlowRule, bool) {
	var best zoneflows.FlowRule
	found := false
	for _, r := range rules {
		f := matchFields(r.Match)
		fits := true
		for _, k := range []string{"dl_type", "nw_proto"} {
			if v, ok := f[k]; ok && v != pkt[k] {
				fits = false
			}
		}
		if v, ok := f["tp_dst"]; ok && !tpDstMatches(v, pkt["tp_dst"]) {
			fits = false
		}
		for _, k := range []string{"nw_dst", "ipv6_dst"} {
			if v, ok := f[k]; ok && !dstContains(v, pkt[k]) {
				fits = false
			}
		}
		if fits && (!found || r.Priority > best.Priority) {
			best, found = r, true
		}
	}
	return best, found
}

// tpDstMatches reports whether a rule's tp_dst field matches a probe port:
// an exact number compares as today, and the OVS masked form value/mask
// (hex) matches when port&mask == value&mask.
func tpDstMatches(rule, port string) bool {
	value, mask, masked := strings.Cut(rule, "/")
	if !masked {
		return rule == port
	}
	v, err1 := strconv.ParseUint(value, 0, 16)
	m, err2 := strconv.ParseUint(mask, 0, 16)
	p, err3 := strconv.ParseUint(port, 10, 16)
	if err1 != nil || err2 != nil || err3 != nil {
		return false
	}
	return p&m == v&m
}

// dstContains reports whether the rule destination dst covers addr.
func dstContains(dst, addr string) bool {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	if pfx, err := netip.ParsePrefix(dst); err == nil {
		return pfx.Contains(a)
	}
	d, err := netip.ParseAddr(dst)
	return err == nil && d == a
}

// TestProvisioning_SetProvisioningServersOpensOnlyThoseServers pins the
// setter the daemon uses to carry the pxe: section's ACME and DNS servers
// into the provisioning template: TCP 443 and UDP 53 win as normal to the
// configured servers and lose to a deny for any other destination.
func TestProvisioning_SetProvisioningServersOpensOnlyThoseServers(t *testing.T) {
	deny := zoneflows.FlowRule{Table: 0, Priority: 200,
		Match: "in_port=7,dl_vlan=100,dl_type=0x0800,nw_dst=198.51.100.0/24", Actions: "drop"}
	https := func(dst string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": "6", "nw_dst": dst, "tp_dst": "443"}
	}
	dns := func(dst string) map[string]string {
		return map[string]string{"dl_type": "0x0800", "nw_proto": "17", "nw_dst": dst, "tp_dst": "53"}
	}

	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	gs.SetProvisioningServers([]net.IP{net.ParseIP("192.0.2.10")}, []net.IP{net.ParseIP("192.0.2.53")})
	rules := append(gs.Generate("7", zone.ZoneProvisioning, zoneflows.Untagged(100)), deny)

	if w, ok := winner(rules, https("192.0.2.10")); !ok || w.Actions != "normal" {
		t.Errorf("TCP 443 to the ACME server: winner %q (%s), want a normal rule", w.Match, w.Actions)
	}
	if w, ok := winner(rules, dns("192.0.2.53")); !ok || w.Actions != "normal" {
		t.Errorf("UDP 53 to the DNS server: winner %q (%s), want a normal rule", w.Match, w.Actions)
	}
	if w, ok := winner(rules, https("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("TCP 443 to a denied destination: winner %q (%s), want a drop", w.Match, w.Actions)
	}
	if w, ok := winner(rules, dns("198.51.100.7")); !ok || w.Actions != "drop" {
		t.Errorf("UDP 53 to a denied destination: winner %q (%s), want a drop", w.Match, w.Actions)
	}
}
