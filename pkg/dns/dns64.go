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
	"net/netip"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// DefaultDNS64Prefix is the RFC 6052 Well-Known Prefix. It is only routable
// to a translator that owns it, so it is the right default for a gateway
// running the platform's own NAT64 (PLAT) beside this resolver.
const DefaultDNS64Prefix = "64:ff9b::/96"

// wellKnownDNS64Prefix is the Well-Known Prefix without its length. RFC 6052
// §3.1 permits it at /96 and at no other length.
const wellKnownDNS64Prefix = "64:ff9b::"

// RFC 7050 heuristic discovery: a client learns the translator's prefix by
// asking for AAAA of ipv4only.arpa, a name that has A records and
// deliberately no AAAA, and reading the prefix out of the synthesised
// answer. The two addresses are assigned by RFC 7050 §8.
const (
	rfc7050Name = "ipv4only.arpa."
	rfc7050TTL  = 3600
)

var rfc7050Addresses = []string{"192.0.0.170", "192.0.0.171"}

// rfc6052PrefixLengths are the only prefix lengths RFC 6052 §2.2 defines.
// The CoreDNS plugin accepts any multiple of eight between 32 and 96, which
// additionally admits /72, /80 and /88 — lengths no RFC 6052 translator can
// reverse. Those are refused here rather than passed to the plugin, because
// a prefix the translator cannot undo produces answers that resolve to
// nothing and look like a network fault.
var rfc6052PrefixLengths = map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}

// DNS64 server selectors. DNS64 is a property of the resolver a client
// population is pointed at, not of a zone: the same name must synthesise for
// an IPv6-only client and stay untouched for a dual-stack one, and the only
// thing that distinguishes them here is which listener they query.
const (
	DNS64ServerInternal = "internal"
	DNS64ServerPublic   = "public"
)

// DNS64Config configures RFC 6147 DNS64 synthesis: when an IPv6-only client
// asks for a name that has only A records, the resolver answers with an AAAA
// built from the NAT64 translator's prefix, and the translator turns the
// resulting flow back into IPv4.
//
// The synthesis itself is the CoreDNS dns64 plugin. This type is the
// platform's configuration contract for it: what the daemon accepts here is
// exactly what reaches the rendered Corefile, and anything it cannot program
// is refused at load rather than dropped.
type DNS64Config struct {
	// Enabled turns on synthesis for the selected servers.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Prefix is the translator's RFC 6052 prefix. Empty means
	// DefaultDNS64Prefix. It must match the NAT64 service's prefix on a
	// node that runs both; a mismatch synthesises addresses that route to
	// no translator.
	Prefix string `yaml:"prefix" json:"prefix" mapstructure:"prefix"`

	// TranslateAll synthesises even for names that already have AAAA
	// records. RFC 6147 §5.1.1 says not to; it exists for a network whose
	// clients have no route to native IPv6 destinations at all.
	TranslateAll bool `yaml:"translate-all" json:"translate_all" mapstructure:"translate-all"`

	// AllowIPv4 synthesises for queries that arrive over IPv4. The plugin
	// declines these by default because in a dual-stack network the client
	// that asked over IPv4 can usually reach the IPv4 destination itself.
	AllowIPv4 bool `yaml:"allow-ipv4" json:"allow_ipv4" mapstructure:"allow-ipv4"`

	// Servers selects the listeners that synthesise: "internal", "public",
	// or both. Empty means internal only, because the IPv6-only client
	// networks a platform gateway serves are internal ones and synthesising
	// on the authoritative public server would hand the Well-Known Prefix
	// to resolvers with no route to this translator.
	Servers []string `yaml:"servers" json:"servers" mapstructure:"servers"`
}

// ErrInvalidDNS64Prefix is returned when the configured prefix is not one
// RFC 6052 defines, or is the Well-Known Prefix at a length RFC 6052 §3.1
// forbids.
type ErrInvalidDNS64Prefix struct {
	Prefix string
	Reason string
}

// Error implements the error interface.
func (e ErrInvalidDNS64Prefix) Error() string {
	return "dns64: invalid prefix " + e.Prefix + ": " + e.Reason
}

// ErrInvalidDNS64Server is returned when the servers list names a listener
// that does not exist. Accepting it would silently synthesise nowhere.
type ErrInvalidDNS64Server struct {
	Server string
}

// Error implements the error interface.
func (e ErrInvalidDNS64Server) Error() string {
	return "dns64: unknown server " + e.Server + ", want " +
		DNS64ServerInternal + " or " + DNS64ServerPublic
}

// ErrDNS64ServerNotConfigured is returned when synthesis is requested on a
// listener the configuration does not start.
type ErrDNS64ServerNotConfigured struct {
	Server string
}

// Error implements the error interface.
func (e ErrDNS64ServerNotConfigured) Error() string {
	return "dns64: server " + e.Server + " is selected for synthesis but is not configured"
}

// Active reports whether synthesis is configured and turned on.
func (c *DNS64Config) Active() bool {
	return c != nil && c.Enabled
}

// ResolvedPrefix returns the configured prefix, or the Well-Known Prefix when
// none is set.
func (c *DNS64Config) ResolvedPrefix() string {
	if c == nil || strings.TrimSpace(c.Prefix) == "" {
		return DefaultDNS64Prefix
	}
	return strings.TrimSpace(c.Prefix)
}

// ResolvedServers returns the listeners that synthesise, defaulting to the
// internal server.
func (c *DNS64Config) ResolvedServers() []string {
	if c == nil || len(c.Servers) == 0 {
		return []string{DNS64ServerInternal}
	}
	out := make([]string, 0, len(c.Servers))
	seen := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ServesServer reports whether the named listener synthesises.
func (c *DNS64Config) ServesServer(server string) bool {
	if !c.Active() {
		return false
	}
	for _, s := range c.ResolvedServers() {
		if s == server {
			return true
		}
	}
	return false
}

// Validate refuses a DNS64 configuration this process cannot program. It is
// called before anything is registered, so an unusable prefix is a startup
// error rather than a resolver that answers with addresses routing nowhere.
func (c *DNS64Config) Validate(cfg *Config) error {
	if !c.Active() {
		return nil
	}

	prefix, err := netip.ParsePrefix(c.ResolvedPrefix())
	if err != nil {
		return ErrInvalidDNS64Prefix{Prefix: c.ResolvedPrefix(), Reason: err.Error()}
	}
	if !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return ErrInvalidDNS64Prefix{Prefix: c.ResolvedPrefix(), Reason: "not an IPv6 prefix"}
	}
	if prefix.Addr() != prefix.Masked().Addr() {
		return ErrInvalidDNS64Prefix{Prefix: c.ResolvedPrefix(), Reason: "host bits are set"}
	}
	if !rfc6052PrefixLengths[prefix.Bits()] {
		return ErrInvalidDNS64Prefix{
			Prefix: c.ResolvedPrefix(),
			Reason: "length must be one of /32, /40, /48, /56, /64 or /96 (RFC 6052 §2.2)",
		}
	}
	if prefix.Addr() == netip.MustParseAddr(wellKnownDNS64Prefix) && prefix.Bits() != 96 {
		return ErrInvalidDNS64Prefix{
			Prefix: c.ResolvedPrefix(),
			Reason: "the Well-Known Prefix is only defined at /96 (RFC 6052 §3.1)",
		}
	}

	for _, server := range c.ResolvedServers() {
		switch server {
		case DNS64ServerInternal:
			if cfg == nil || cfg.InternalServer == nil {
				return ErrDNS64ServerNotConfigured{Server: server}
			}
		case DNS64ServerPublic:
			if cfg == nil || cfg.PublicServer == nil || cfg.PublicServer.Port <= 0 {
				return ErrDNS64ServerNotConfigured{Server: server}
			}
		default:
			return ErrInvalidDNS64Server{Server: server}
		}
	}
	return nil
}

// CorefileStanza renders the plugin directive for one server block, indented
// to match the rest of the rendered Corefile. It returns the empty string
// when the named listener does not synthesise, so a block simply omits it.
func (c *DNS64Config) CorefileStanza(server string) string {
	if !c.ServesServer(server) {
		return ""
	}
	var b strings.Builder
	b.WriteString("\tdns64 {\n")
	b.WriteString("\t\tprefix " + c.ResolvedPrefix() + "\n")
	if c.TranslateAll {
		b.WriteString("\t\ttranslate_all\n")
	}
	if c.AllowIPv4 {
		b.WriteString("\t\tallow_ipv4\n")
	}
	b.WriteString("\t}\n")
	return b.String()
}

// serveRFC7050 answers ipv4only.arpa so a client can discover the
// translator's prefix heuristically (RFC 7050 §3).
//
// The name is answered here, in the authoritative plugin, rather than left to
// a forwarder: the dns64 plugin sits ahead of this one in the chain, so an
// AAAA query for ipv4only.arpa reaches this handler, gets the deliberate
// NODATA below, and is then synthesised from the A records this handler
// serves on the plugin's own follow-up query. That is the whole discovery
// mechanism, and it only works if both halves are local.
//
// It reports handled=false when synthesis is off or the name is not
// ipv4only.arpa, leaving the query to the normal zone path.
func serveRFC7050(w dns.ResponseWriter, r *dns.Msg, qname string, qtype uint16) (int, bool, error) {
	if Configuration == nil || !Configuration.DNS64.Active() {
		return dns.RcodeSuccess, false, nil
	}
	if !strings.EqualFold(qname, rfc7050Name) {
		return dns.RcodeSuccess, false, nil
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if qtype == dns.TypeA || qtype == dns.TypeANY {
		for _, addr := range rfc7050Addresses {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   rfc7050Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    rfc7050TTL,
				},
				A: netip.MustParseAddr(addr).AsSlice(),
			})
		}
	}

	// Every other type, AAAA included, is an authoritative empty answer:
	// ipv4only.arpa exists and deliberately has no AAAA, which is exactly
	// the condition the dns64 plugin synthesises from.
	if len(msg.Answer) == 0 {
		msg.Ns = append(msg.Ns, rfc7050SOA())
	}

	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, true, &WrappedError{
			Msg: "dns64: failed to write the ipv4only.arpa response", Err: err,
		}
	}
	return dns.RcodeSuccess, true, nil
}

// rfc7050SOA is the negative-caching authority for the synthesised
// ipv4only.arpa answers.
func rfc7050SOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   rfc7050Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    rfc7050TTL,
		},
		Ns:      rfc7050Name,
		Mbox:    "hostmaster." + rfc7050Name,
		Serial:  1,
		Refresh: 86400,
		Retry:   7200,
		Expire:  86400,
		Minttl:  rfc7050TTL,
	}
}
