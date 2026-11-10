// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Tests for the installer's dnsmasq.conf generation (issue #128): the
// `local=/<domain>/` directive answers from /etc/hosts only and never
// forwards — not even to platformd's own zone on 127.0.0.1#9053 — so it
// must be emitted only when no upstream route governs the domain. On
// nodes that forward to a control plane (remote or loopback), local=
// blackholes the zone: dnsmasq answers NXDOMAIN instead of forwarding,
// and platformd FATALs at ACME registration on first start.
package installer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBuildDNSMasqConf_LoopbackUpstreamForwards covers the control
// plane shape: platformd serves the zone at 127.0.0.1#9053 and dnsmasq
// forwards to it, so the domain must NOT be declared local — local=
// would stop forwarding even to loopback.
func TestBuildDNSMasqConf_LoopbackUpstreamForwards(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled:         true,
		UpstreamServers: []string{"127.0.0.1#9053"},
		LocalDomain:     "example.internal",
	})

	assert.Contains(t, conf, "server=127.0.0.1#9053\n")
	assert.Contains(t, conf, "domain=example.internal\n")
	assert.NotContains(t, conf, "local=")
}

// TestBuildDNSMasqConf_RemoteUpstreamForwardsInternalDomain is the
// regression test for issue #128 (node-05, run 8): a worker forwarding
// to the control plane's IP must NOT declare the internal domain local,
// or cp.<domain> resolves NXDOMAIN and platformd cannot reach the ACME
// directory.
func TestBuildDNSMasqConf_RemoteUpstreamForwardsInternalDomain(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled:         true,
		UpstreamServers: []string{"192.0.2.140#9053"},
		LocalDomain:     "example.internal",
	})

	assert.Contains(t, conf, "server=192.0.2.140#9053\n")
	assert.Contains(t, conf, "domain=example.internal\n")
	assert.NotContains(t, conf, "local=")
}

// TestBuildDNSMasqConf_DomainScopedUpstreamPreserved covers the template
// shape that pins the internal zone to the control plane while sending
// everything else to a second upstream — the shape the unconditional
// local= used to defeat.
func TestBuildDNSMasqConf_DomainScopedUpstreamPreserved(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled: true,
		UpstreamServers: []string{
			"/example.internal/10.4.200.10#9053",
			"10.4.200.10#8053",
		},
		LocalDomain: "example.internal",
	})

	assert.Contains(t, conf, "server=/example.internal/10.4.200.10#9053\n")
	assert.Contains(t, conf, "server=10.4.200.10#8053\n")
	assert.Contains(t, conf, "domain=example.internal\n")
	assert.NotContains(t, conf, "local=")
}

// TestBuildDNSMasqConf_NoUpstreamsKeepsLocal covers the purely local
// resolver: with no server= lines dnsmasq can only answer from
// /etc/hosts, so declaring the domain local is correct and preserves the
// standalone shape.
func TestBuildDNSMasqConf_NoUpstreamsKeepsLocal(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled:     true,
		LocalDomain: "example.internal",
	})

	assert.Contains(t, conf, "domain=example.internal\n")
	assert.Contains(t, conf, "local=/example.internal/\n")
	assert.NotContains(t, conf, "server=")
}

// TestBuildDNSMasqConf_UncoveredDomainStaysLocal covers a node whose
// only upstream is scoped to a different zone: nothing routes the local
// domain, so it is answered from /etc/hosts and declared local.
func TestBuildDNSMasqConf_UncoveredDomainStaysLocal(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled:         true,
		UpstreamServers: []string{"/other.zone/10.0.0.1#9053"},
		LocalDomain:     "example.internal",
	})

	assert.Contains(t, conf, "server=/other.zone/10.0.0.1#9053\n")
	assert.Contains(t, conf, "domain=example.internal\n")
	assert.Contains(t, conf, "local=/example.internal/\n")
}

// TestBuildDNSMasqConf_NoLocalDomain ensures neither domain= nor local=
// appears when no local domain is configured.
func TestBuildDNSMasqConf_NoLocalDomain(t *testing.T) {
	for _, upstream := range []string{"127.0.0.1#9053", "10.0.1.1#9053"} {
		conf := BuildDNSMasqConf(&DNSMasqConfig{
			Enabled:         true,
			UpstreamServers: []string{upstream},
		})

		assert.Contains(t, conf, "server="+upstream+"\n")
		assert.NotContains(t, conf, "domain=")
		assert.NotContains(t, conf, "local=")
	}
}

// TestBuildDNSMasqConf_BaseDirectivesAlwaysPresent guards the forwarder
// invariants every node shape relies on.
func TestBuildDNSMasqConf_BaseDirectivesAlwaysPresent(t *testing.T) {
	for _, upstreams := range [][]string{
		{"127.0.0.1#9053"},
		{"192.0.2.140#9053"},
		nil,
	} {
		conf := BuildDNSMasqConf(&DNSMasqConfig{
			Enabled:         true,
			UpstreamServers: upstreams,
			LocalDomain:     "example.internal",
		})

		assert.Contains(t, conf, "no-resolv\n")
		assert.Contains(t, conf, "listen-address=127.0.0.1\n")
		assert.Contains(t, conf, "bind-interfaces\n")
		assert.Contains(t, conf, "cache-size=1000\n")
	}
}

// TestBuildDNSMasqConf_NormalizesPortSeparator ensures the YAML `:`
// shorthand never reaches dnsmasq.conf verbatim — dnsmasq accepts only
// `#` before the port and fails to start on `server=ip:port` lines.
func TestBuildDNSMasqConf_NormalizesPortSeparator(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled: true,
		UpstreamServers: []string{
			"10.0.1.1:9053",
			"/example.internal/10.4.200.10:9053",
		},
		LocalDomain: "example.internal",
	})

	assert.Contains(t, conf, "server=10.0.1.1#9053\n")
	assert.Contains(t, conf, "server=/example.internal/10.4.200.10#9053\n")
	assert.NotContains(t, conf, ":9053")
	assert.NotContains(t, conf, "local=")
}

// TestBuildDNSMasqConf_NormalizesIPv6 ensures bracketed IPv6 upstreams
// are emitted in dnsmasq syntax — dnsmasq has no bracket form and
// rejects `server=[::1]#9053` at startup.
func TestBuildDNSMasqConf_NormalizesIPv6(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled: true,
		UpstreamServers: []string{
			"[::1]:9053",
			"[::1]#8053",
			"/example.internal/[::1]#9053",
		},
		LocalDomain: "example.internal",
	})

	assert.Contains(t, conf, "server=::1#9053\n")
	assert.Contains(t, conf, "server=::1#8053\n")
	assert.Contains(t, conf, "server=/example.internal/::1#9053\n")
	assert.NotContains(t, conf, "[")
	assert.NotContains(t, conf, "local=")
}

// TestBuildDNSMasqConf_MalformedEntryWrittenVerbatim pins the documented
// contract for unparseable entries: preserved verbatim in the generated
// config (dnsmasq rejects the line at startup) and counted as unscoped
// routes, so the local= blackhole is never emitted on a typo.
func TestBuildDNSMasqConf_MalformedEntryWrittenVerbatim(t *testing.T) {
	conf := BuildDNSMasqConf(&DNSMasqConfig{
		Enabled: true,
		UpstreamServers: []string{
			"/unterminated-scope",
			"192.0.2.140#9053#extra",
		},
		LocalDomain: "example.internal",
	})

	assert.Contains(t, conf, "server=/unterminated-scope\n")
	assert.Contains(t, conf, "server=192.0.2.140#9053#extra\n")
	assert.NotContains(t, conf, "local=")
}

// TestNormalizeDNSMasqUpstream verifies each entry form is rewritten
// into dnsmasq server= syntax, with unparseable input passed through.
func TestNormalizeDNSMasqUpstream(t *testing.T) {
	tests := []struct {
		name  string
		entry string
		want  string
	}{
		{"hash form unchanged", "192.0.2.140#9053", "192.0.2.140#9053"},
		{"colon form rewritten", "10.0.1.1:9053", "10.0.1.1#9053"},
		{"bare ipv4 unchanged", "1.1.1.1", "1.1.1.1"},
		{"bare ipv6 unchanged", "::1", "::1"},
		{"bracketed ipv6 rewritten", "[::1]:9053", "::1#9053"},
		{"bracketed ipv6 hash form unbracketed", "[::1]#9053", "::1#9053"},
		{"domain-scoped bracketed hash form", "/example.internal/[::1]#9053", "/example.internal/::1#9053"},
		{"bare bracketed ipv6 unbracketed", "[::1]", "::1"},
		{"double hash passed through", "192.0.2.140#9053#extra", "192.0.2.140#9053#extra"},
		{"domain-scoped hash unchanged", "/example.internal/10.4.200.10#9053", "/example.internal/10.4.200.10#9053"},
		{"domain-scoped colon rewritten", "/example.internal/10.4.200.10:9053", "/example.internal/10.4.200.10#9053"},
		{"hostname colon rewritten", "cp.example.internal:9053", "cp.example.internal#9053"},
		{"surrounding whitespace trimmed", " 127.0.0.1:9053 ", "127.0.0.1#9053"},
		{"unparseable passed through", "/unterminated-scope", "/unterminated-scope"},
		{"empty string passed through", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeDNSMasqUpstream(tt.entry))
		})
	}
}

// TestDnsmasqZoneHasUpstreamRoute exercises the governing-route
// decision that gates local=: any unscoped entry routes every zone,
// scoped entries route only the zones their scope covers, and malformed
// entries count as unscoped routes so a typo can never blackhole the
// zone.
func TestDnsmasqZoneHasUpstreamRoute(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		upstreams []string
		want      bool
	}{
		{"unscoped remote routes the zone", "example.internal", []string{"192.0.2.140#9053"}, true},
		{"unscoped loopback routes the zone", "example.internal", []string{"127.0.0.1#9053"}, true},
		{"unscoped colon shorthand routes the zone", "example.internal", []string{"10.0.1.1:9053"}, true},
		{"scoped exact match routes the zone", "example.internal", []string{"/example.internal/10.4.200.10#9053"}, true},
		{"parent scope covers subdomain", "node.example.internal", []string{"/example.internal/10.0.0.1#9053"}, true},
		{"scope match is case-insensitive", "Example.Internal", []string{"/EXAMPLE.INTERNAL/10.0.0.1#9053"}, true},
		{"trailing dot on scope still matches", "example.internal", []string{"/example.internal./10.0.0.1#9053"}, true},
		{"scoped mismatch plus unscoped routes the zone", "example.internal", []string{"/other.zone/10.0.0.1#9053", "1.1.1.1"}, true},
		{"malformed entry counts as unscoped route", "example.internal", []string{"/unterminated-scope"}, true},
		{"no upstreams leaves the zone local", "example.internal", nil, false},
		{"only empty entries leave the zone local", "example.internal", []string{"", "  "}, false},
		{"only mismatched scopes leave the zone local", "example.internal", []string{"/other.zone/10.0.0.1#9053"}, false},
		{"child scope does not cover parent domain", "example.internal", []string{"/node.example.internal/10.0.0.1#9053"}, false},
		{"suffix without label boundary does not match", "notexample.internal", []string{"/example.internal/10.0.0.1#9053"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dnsmasqZoneHasUpstreamRoute(tt.domain, tt.upstreams))
		})
	}
}
