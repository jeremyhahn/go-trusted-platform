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

package dns

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dns64"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serverConfig() *Config {
	return &Config{
		InternalServer: &InternalServer{Port: 9053},
		PublicServer:   &PublicServer{Port: 8053},
	}
}

func TestDNS64Config_Defaults(t *testing.T) {
	c := &DNS64Config{Enabled: true}

	assert.True(t, c.Active())
	assert.Equal(t, DefaultDNS64Prefix, c.ResolvedPrefix(),
		"an unset prefix is the RFC 6052 Well-Known Prefix")
	assert.Equal(t, []string{DNS64ServerInternal}, c.ResolvedServers(),
		"synthesis defaults to the internal listener only")
	assert.True(t, c.ServesServer(DNS64ServerInternal))
	assert.False(t, c.ServesServer(DNS64ServerPublic),
		"the public authoritative server must not hand out the Well-Known Prefix by default")
}

func TestDNS64Config_NilAndDisabledAreInert(t *testing.T) {
	var nilCfg *DNS64Config
	assert.False(t, nilCfg.Active())
	assert.False(t, nilCfg.ServesServer(DNS64ServerInternal))
	assert.Equal(t, DefaultDNS64Prefix, nilCfg.ResolvedPrefix())
	assert.Empty(t, nilCfg.CorefileStanza(DNS64ServerInternal))
	assert.NoError(t, nilCfg.Validate(serverConfig()))

	off := &DNS64Config{Enabled: false, Prefix: "not-a-prefix"}
	assert.False(t, off.Active())
	assert.NoError(t, off.Validate(serverConfig()),
		"a disabled section is not validated; it programs nothing")
	assert.Empty(t, off.CorefileStanza(DNS64ServerInternal))
}

func TestDNS64Config_ResolvedServersNormalises(t *testing.T) {
	c := &DNS64Config{
		Enabled: true,
		Servers: []string{" Public ", "internal", "public", ""},
	}
	assert.Equal(t, []string{DNS64ServerInternal, DNS64ServerPublic}, c.ResolvedServers(),
		"case, padding, duplicates and blanks are normalised away")
}

func TestDNS64Config_ValidatePrefixes(t *testing.T) {
	for _, prefix := range []string{
		"64:ff9b::/96",
		"2001:db8::/32",
		"2001:db8:aa00::/40",
		"2001:db8:aabb::/48",
		"2001:db8:aabb:cc00::/56",
		"2001:db8:aabb:ccdd::/64",
	} {
		t.Run("accepts "+prefix, func(t *testing.T) {
			c := &DNS64Config{Enabled: true, Prefix: prefix}
			assert.NoError(t, c.Validate(serverConfig()))
		})
	}

	refused := map[string]string{
		// The plugin itself accepts every multiple of eight from 32 to 96,
		// which admits three lengths RFC 6052 never defined. A translator
		// cannot reverse them.
		"2001:db8:aabb:ccdd::/72": "length",
		"2001:db8:aabb:ccdd::/80": "length",
		"2001:db8:aabb:ccdd::/88": "length",
		"2001:db8::/33":           "length",
		"2001:db8::/128":          "length",
		"192.0.2.0/24":            "not an IPv6 prefix",
		"::ffff:192.0.2.0/96":     "not an IPv6 prefix",
		"2001:db8::1/32":          "host bits are set",
		"nonsense":                "",
		// RFC 6052 §3.1: the Well-Known Prefix is defined at /96 only.
		"64:ff9b::/64": "Well-Known Prefix",
	}
	for prefix, reason := range refused {
		t.Run("refuses "+prefix, func(t *testing.T) {
			c := &DNS64Config{Enabled: true, Prefix: prefix}
			err := c.Validate(serverConfig())
			require.Error(t, err)
			var typed ErrInvalidDNS64Prefix
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, prefix, typed.Prefix)
			if reason != "" {
				assert.Contains(t, typed.Error(), reason)
			}
		})
	}
}

func TestDNS64Config_ValidateServers(t *testing.T) {
	unknown := &DNS64Config{Enabled: true, Servers: []string{"edge"}}
	err := unknown.Validate(serverConfig())
	var badServer ErrInvalidDNS64Server
	require.ErrorAs(t, err, &badServer)
	assert.Equal(t, "edge", badServer.Server)
	assert.Contains(t, badServer.Error(), "edge")
	assert.Contains(t, badServer.Error(), DNS64ServerInternal,
		"the message names the listeners that do exist")

	// Selecting a listener the daemon does not start would synthesise
	// nowhere, which is the silent-drop failure this refuses.
	missing := &DNS64Config{Enabled: true, Servers: []string{DNS64ServerPublic}}
	err = missing.Validate(&Config{InternalServer: &InternalServer{Port: 9053}})
	var notConfigured ErrDNS64ServerNotConfigured
	require.ErrorAs(t, err, &notConfigured)
	assert.Equal(t, DNS64ServerPublic, notConfigured.Server)
	assert.Contains(t, notConfigured.Error(), DNS64ServerPublic)

	err = (&DNS64Config{Enabled: true}).Validate(&Config{PublicServer: &PublicServer{Port: 8053}})
	require.ErrorAs(t, err, &notConfigured)
	assert.Equal(t, DNS64ServerInternal, notConfigured.Server)

	// A public server declared with no port is not a listener either.
	err = (&DNS64Config{Enabled: true, Servers: []string{DNS64ServerPublic}}).
		Validate(&Config{PublicServer: &PublicServer{Port: 0}})
	require.ErrorAs(t, err, &notConfigured)
}

func TestDNS64Config_CorefileStanza(t *testing.T) {
	c := &DNS64Config{
		Enabled:      true,
		Prefix:       "2001:db8::/96",
		TranslateAll: true,
		AllowIPv4:    true,
		Servers:      []string{DNS64ServerInternal},
	}

	stanza := c.CorefileStanza(DNS64ServerInternal)
	assert.Equal(t, "\tdns64 {\n\t\tprefix 2001:db8::/96\n\t\ttranslate_all\n\t\tallow_ipv4\n\t}\n", stanza)

	assert.Empty(t, c.CorefileStanza(DNS64ServerPublic),
		"a listener that does not synthesise renders no directive")

	plain := &DNS64Config{Enabled: true}
	assert.Equal(t, "\tdns64 {\n\t\tprefix "+DefaultDNS64Prefix+"\n\t}\n",
		plain.CorefileStanza(DNS64ServerInternal),
		"the optional flags are omitted, not rendered false")
}

func TestNewCorefileForServer(t *testing.T) {
	cfg := &DNS64Config{Enabled: true, Servers: []string{DNS64ServerInternal}}

	internal := NewCorefileForServer(DNS64ServerInternal, 9053, []string{"192.168.1.1"}, cfg)
	assert.Contains(t, internal, ".:9053")
	assert.Contains(t, internal, "dns64 {")
	assert.Contains(t, internal, "prefix "+DefaultDNS64Prefix)
	assert.Contains(t, internal, "forward . 192.168.1.1")
	assert.Less(t, strings.Index(internal, "dns64 {"), strings.Index(internal, "forward ."),
		"dns64 must be rendered ahead of forward so it can intercept the answer")

	public := NewCorefileForServer(DNS64ServerPublic, 8053, []string{"8.8.8.8"}, cfg)
	assert.Contains(t, public, ".:8053")
	assert.NotContains(t, public, "dns64")

	assert.NotContains(t, NewCorefileForServer(DNS64ServerInternal, 9053, nil, nil), "dns64",
		"no dns64 section means no directive")
}

// fakeResponseWriter captures the message the handler writes.
type fakeResponseWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
	err error
}

func (w *fakeResponseWriter) WriteMsg(m *dns.Msg) error {
	if w.err != nil {
		return w.err
	}
	w.msg = m
	return nil
}

func (w *fakeResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9053}
}

func (w *fakeResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000}
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func withDNS64(t *testing.T, cfg *DNS64Config) {
	t.Helper()
	previous := Configuration
	Configuration = &Config{DNS64: cfg}
	t.Cleanup(func() { Configuration = previous })
}

func TestServeRFC7050_AnswersTheDiscoveryName(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: true})

	w := &fakeResponseWriter{}
	r := query(rfc7050Name, dns.TypeA)
	rcode, handled, err := serveRFC7050(w, r, rfc7050Name, dns.TypeA)

	require.NoError(t, err)
	require.True(t, handled)
	assert.Equal(t, dns.RcodeSuccess, rcode)
	require.NotNil(t, w.msg)
	assert.True(t, w.msg.Authoritative)
	require.Len(t, w.msg.Answer, 2)

	var addrs []string
	for _, rr := range w.msg.Answer {
		a, ok := rr.(*dns.A)
		require.True(t, ok)
		addrs = append(addrs, a.A.String())
		assert.Equal(t, uint32(rfc7050TTL), a.Hdr.Ttl)
	}
	assert.Equal(t, rfc7050Addresses, addrs, "the addresses RFC 7050 §8 assigns")
}

func TestServeRFC7050_AAAAIsDeliberateNODATA(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: true})

	w := &fakeResponseWriter{}
	r := query(rfc7050Name, dns.TypeAAAA)
	_, handled, err := serveRFC7050(w, r, rfc7050Name, dns.TypeAAAA)

	require.NoError(t, err)
	require.True(t, handled)
	require.NotNil(t, w.msg)
	assert.Equal(t, dns.RcodeSuccess, w.msg.Rcode,
		"NODATA, not NXDOMAIN: RFC 6147 §5.1.2 stops synthesis on a Name Error")
	assert.Empty(t, w.msg.Answer,
		"the absence of AAAA here is the whole discovery mechanism")
	require.Len(t, w.msg.Ns, 1)
	_, ok := w.msg.Ns[0].(*dns.SOA)
	assert.True(t, ok, "a negative answer carries its authority")
}

func TestServeRFC7050_MixedCaseNameIsTheSameName(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: true})

	w := &fakeResponseWriter{}
	name := "IPv4Only.ARPA."
	_, handled, err := serveRFC7050(w, query(name, dns.TypeA), name, dns.TypeA)

	require.NoError(t, err)
	assert.True(t, handled, "DNS names are compared case-insensitively")
}

func TestServeRFC7050_DeclinesWhatIsNotItsToAnswer(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: true})

	w := &fakeResponseWriter{}
	_, handled, err := serveRFC7050(w, query("example.com.", dns.TypeA), "example.com.", dns.TypeA)
	require.NoError(t, err)
	assert.False(t, handled, "any other name goes down the normal zone path")
	assert.Nil(t, w.msg)
}

func TestServeRFC7050_SilentWhenSynthesisIsOff(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: false})

	w := &fakeResponseWriter{}
	_, handled, err := serveRFC7050(w, query(rfc7050Name, dns.TypeA), rfc7050Name, dns.TypeA)
	require.NoError(t, err)
	assert.False(t, handled,
		"without a translator the discovery name would advertise a prefix that routes nowhere")

	previous := Configuration
	Configuration = nil
	t.Cleanup(func() { Configuration = previous })
	_, handled, err = serveRFC7050(w, query(rfc7050Name, dns.TypeA), rfc7050Name, dns.TypeA)
	require.NoError(t, err)
	assert.False(t, handled, "an unconfigured package answers nothing")
}

func TestServeRFC7050_WriteFailureIsTyped(t *testing.T) {
	withDNS64(t, &DNS64Config{Enabled: true})

	w := &fakeResponseWriter{err: assert.AnError}
	rcode, handled, err := serveRFC7050(w, query(rfc7050Name, dns.TypeA), rfc7050Name, dns.TypeA)

	require.Error(t, err)
	assert.True(t, handled, "the query was ours even though the write failed")
	assert.Equal(t, dns.RcodeServerFailure, rcode)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, assert.AnError)
}

// TestDNS64Config_DecodesHyphenatedKeys is the keystone test for this
// section: configuration the daemon accepts must be configuration it
// programs. Every key here is hyphenated, which is the spelling mapstructure
// drops when a field carries no tag — the defect class that has now been
// found four times in this codebase.
func TestDNS64Config_DecodesHyphenatedKeys(t *testing.T) {
	const yaml = `
dns64:
  enabled: true
  prefix: "2001:db8:aabb::/48"
  translate-all: true
  allow-ipv4: true
  servers: [internal, public]
`
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))

	var cfg Config
	require.NoError(t, v.Unmarshal(&cfg))

	require.NotNil(t, cfg.DNS64, "the dns64 section must reach the config")
	assert.True(t, cfg.DNS64.Enabled)
	assert.Equal(t, "2001:db8:aabb::/48", cfg.DNS64.Prefix)
	assert.True(t, cfg.DNS64.TranslateAll, "translate-all, not translateall")
	assert.True(t, cfg.DNS64.AllowIPv4, "allow-ipv4, not allowipv4")
	assert.Equal(t, []string{DNS64ServerInternal, DNS64ServerPublic}, cfg.DNS64.ResolvedServers())

	assert.NoError(t, cfg.DNS64.Validate(serverConfig()))
}

// stubUpstream answers the dns64 plugin's follow-up A lookup.
type stubUpstream struct {
	answer *dns.Msg
	err    error
}

func (u stubUpstream) Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error) {
	return u.answer, u.err
}

// authoritative is the rest of the plugin chain as far as dns64 can see it.
type authoritative struct {
	answer *dns.Msg
}

func (a authoritative) Name() string { return "authoritative" }

func (a authoritative) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	msg := a.answer.Copy()
	msg.SetReply(r)
	msg.Answer = a.answer.Answer
	msg.Ns = a.answer.Ns
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return msg.Rcode, nil
}

func mustA(name, addr string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(addr).To4(),
	}
}

func mustAAAA(name, addr string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP(addr),
	}
}

// newPluginUnderTest builds the upstream plugin the way the rendered Corefile
// configures it, so this exercises the real synthesis rather than a local
// imitation of it.
func newPluginUnderTest(t *testing.T, cfg *DNS64Config, next plugin.Handler, upstreamAnswer *dns.Msg) *dns64.DNS64 {
	t.Helper()
	_, prefix, err := net.ParseCIDR(cfg.ResolvedPrefix())
	require.NoError(t, err)
	return &dns64.DNS64{
		Prefix:       prefix,
		TranslateAll: cfg.TranslateAll,
		AllowIPv4:    cfg.AllowIPv4,
		Upstream:     stubUpstream{answer: upstreamAnswer},
		Next:         next,
	}
}

func TestDNS64Synthesis_AOnlyNameBecomesAAAAInThePrefix(t *testing.T) {
	cfg := &DNS64Config{Enabled: true, Prefix: "2001:db8::/96"}

	// The authoritative half has the name but no AAAA for it.
	nodata := new(dns.Msg)
	nodata.Rcode = dns.RcodeSuccess

	upstream := new(dns.Msg)
	upstream.Answer = []dns.RR{mustA("service.example.internal.", "192.0.2.10")}

	d := newPluginUnderTest(t, cfg, authoritative{answer: nodata}, upstream)

	w := &fakeResponseWriter{}
	_, err := d.ServeDNS(context.Background(), w, query("service.example.internal.", dns.TypeAAAA))
	require.NoError(t, err)

	require.NotNil(t, w.msg)
	require.Len(t, w.msg.Answer, 1)
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	require.True(t, ok, "the A answer is returned as AAAA")
	assert.Equal(t, "2001:db8::c000:20a", aaaa.AAAA.String(),
		"192.0.2.10 embedded in the configured /96 (RFC 6052 §2.2)")
}

func TestDNS64Synthesis_NameWithAAAAIsUntouched(t *testing.T) {
	cfg := &DNS64Config{Enabled: true, Prefix: "2001:db8::/96"}

	native := new(dns.Msg)
	native.Answer = []dns.RR{mustAAAA("dual.example.internal.", "2001:db8:1::5")}

	upstream := new(dns.Msg)
	upstream.Answer = []dns.RR{mustA("dual.example.internal.", "192.0.2.10")}

	d := newPluginUnderTest(t, cfg, authoritative{answer: native}, upstream)

	w := &fakeResponseWriter{}
	_, err := d.ServeDNS(context.Background(), w, query("dual.example.internal.", dns.TypeAAAA))
	require.NoError(t, err)

	require.NotNil(t, w.msg)
	require.Len(t, w.msg.Answer, 1)
	aaaa, ok := w.msg.Answer[0].(*dns.AAAA)
	require.True(t, ok)
	assert.Equal(t, "2001:db8:1::5", aaaa.AAAA.String(),
		"a name that already resolves over IPv6 must not be redirected through the translator")
}

func TestDNS64Synthesis_TranslateAllOverridesANativeAnswer(t *testing.T) {
	cfg := &DNS64Config{Enabled: true, Prefix: "2001:db8::/96", TranslateAll: true}

	native := new(dns.Msg)
	native.Answer = []dns.RR{mustAAAA("dual.example.internal.", "2001:db8:1::5")}

	upstream := new(dns.Msg)
	upstream.Answer = []dns.RR{mustA("dual.example.internal.", "192.0.2.10")}

	d := newPluginUnderTest(t, cfg, authoritative{answer: native}, upstream)

	w := &fakeResponseWriter{}
	_, err := d.ServeDNS(context.Background(), w, query("dual.example.internal.", dns.TypeAAAA))
	require.NoError(t, err)

	require.Len(t, w.msg.Answer, 1)
	aaaa := w.msg.Answer[0].(*dns.AAAA)
	assert.Equal(t, "2001:db8::c000:20a", aaaa.AAAA.String(),
		"translate_all is for a network with no route to native IPv6 at all")
}

func TestDNS64Synthesis_ARecordQueriesPassStraightThrough(t *testing.T) {
	cfg := &DNS64Config{Enabled: true}

	answer := new(dns.Msg)
	answer.Answer = []dns.RR{mustA("service.example.internal.", "192.0.2.10")}

	d := newPluginUnderTest(t, cfg, authoritative{answer: answer}, new(dns.Msg))

	w := &fakeResponseWriter{}
	_, err := d.ServeDNS(context.Background(), w, query("service.example.internal.", dns.TypeA))
	require.NoError(t, err)

	require.Len(t, w.msg.Answer, 1)
	_, ok := w.msg.Answer[0].(*dns.A)
	assert.True(t, ok, "only AAAA questions are eligible (RFC 6147 §5.1)")
}
