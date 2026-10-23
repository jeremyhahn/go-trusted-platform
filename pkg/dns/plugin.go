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
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"

	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

const (
	trustedPlatformPlugin = "trustedPlatform"
)

// Define log to be a logger with the plugin name in it.
var (
	log = clog.NewWithPlugin(trustedPlatformPlugin)

	zoneDAO          dao.ZoneDAO
	datastoreFactory *quicbaas.Factory

	ErrInternalZoneQueryViolation = errors.New("received public query for internal zone")

	// ErrServerZoneUndefined reports a public or internal server with no zone
	// in the configuration.
	ErrServerZoneUndefined = errors.New("server zone not defined in configuration")

	// ErrNoDNSSECSigner reports DNSSEC enabled with no key backend wired, so
	// a zone would be stored unsigned.
	ErrNoDNSSECSigner = errors.New("DNSSEC enabled but no key store and no XKMS adapter are configured; " +
		"set one with SetDNSSECKeyStore or SetXKMSAdapter before loading zones")
)

func (cp TrustedPlatformPlugin) Name() string { return trustedPlatformPlugin }

func init() {
	plugin.Register(trustedPlatformPlugin, setup)
}

// // requestCount tracks the number of DNS queries handled by the plugin.
// var requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
// 	Namespace: plugin.Namespace,
// 	Subsystem: trustedPlatformPlugin,
// 	Name:      "request_count_total",
// 	Help:      "Total number of requests handled by the custom plugin.",
// }, []string{"server"})

// TrustedPlatformPlugin is the struct implementing the plugin.Handler interface.
type TrustedPlatformPlugin struct {
	Next plugin.Handler
}

// ServeDNS handles incoming DNS requests.
func (cp TrustedPlatformPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	// Only standard queries are served. An UPDATE (RFC 2136 §2), NOTIFY or
	// any other opcode gets NOTIMP (RFC 1035 §4.1.1 RCODE 4) instead of being
	// answered as if it were a query. NOTIMP is one of the rcodes for which
	// plugin.ClientWrite is false, so the CoreDNS server writes the reply.
	if r.Opcode != dns.OpcodeQuery {
		Configuration.Logger.Warn("Unsupported DNS opcode",
			slog.String("remoteAddr", w.RemoteAddr().String()),
			slog.String("opcode", dns.OpcodeToString[r.Opcode]))
		return dns.RcodeNotImplemented, nil
	}

	// A query names what it asks for in its question section (RFC 1035
	// §4.1.2). One without a question cannot be interpreted, so it gets
	// FORMERR (RFC 1035 §4.1.1 RCODE 1), which the CoreDNS server writes.
	if len(r.Question) == 0 {
		Configuration.Logger.Warn("DNS query without a question",
			slog.String("remoteAddr", w.RemoteAddr().String()))
		return dns.RcodeFormatError, nil
	}

	// Parse the port number from the local connection address
	pieces := strings.Split(w.LocalAddr().String(), ":")
	port := pieces[len(pieces)-1]

	// Parse the query name and type
	qname := dns.Fqdn(r.Question[0].Name) // Normalize the DNS name
	qtype := r.Question[0].Qtype          // Query type

	Configuration.Logger.Info("Inbound DNS query",
		slog.String("remoteAddr", w.RemoteAddr().String()),
		slog.String("port", port),
		slog.String("qname", qname),
		slog.String("qtype", dns.TypeToString[qtype]))

	// Increment the request counter metric.
	// requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	// Validate the query
	if err := validateQuery(qname); err != nil {
		Configuration.Logger.Warn("Invalid query",
			slog.String("qname", qname),
			slog.String("error", err.Error()))
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	// RFC 7050 prefix discovery. ipv4only.arpa is answered before the zone
	// lookup because it is not one of this platform's zones and never will
	// be: it exists so an IPv6-only client can learn the NAT64 prefix from
	// the AAAA this resolver synthesises for it.
	if rcode, handled, err := serveRFC7050(w, r, qname, qtype); handled {
		return rcode, err
	}

	// Locate the authoritative zone for the queried name
	zone := findZoneForQuery(ctx, qname, zoneDAO)
	if zone == nil {
		Configuration.Logger.Debug("no zone found for query", slog.String("qname", qname))
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	if port == strconv.Itoa(Configuration.PublicServer.Port) && zone.Internal {

		// Reject queries for internal zones against the public server

		// Log the violation
		Configuration.Logger.Error(ErrInternalZoneQueryViolation)
		Configuration.Logger.Security(ctx, logging.SecurityLogEntry{
			Category:        logging.CategoryNetworkSecurity,
			Description:     "Ignoring public query for internal zone",
			Details:         qname,
			OffenderAddress: w.RemoteAddr().String(),
			Source:          logging.SourceDNS,
			Severity:        logging.SeverityHigh,
			Timestamp:       time.Now(),
		})

		// Don't return any kind of error or response here that an attacker
		// could use to determine the existence of internal zones.
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)

	}

	// Serve authoritative zone transfers (AXFR/IXFR) to configured,
	// TSIG-authenticated secondaries. The platform is a PRIMARY nameserver;
	// a zone transfer is a DNS-protocol operation (TCP), not one of the
	// platform's API protocols, so it is answered here on the wire rather
	// than through REST/gRPC/QUIC/MCP/Unix.
	if isTransferQuery(qtype) {
		return cp.handleZoneTransfer(ctx, w, r, zone, qname)
	}

	// Parse the queried records from the zone file
	rrs, err := parseQueriedRecord(qtype, qname, zone)
	if err != nil {
		Configuration.Logger.Error(err)
		return plugin.NextOrFailure(cp.Name(), cp.Next, ctx, w, r)
	}

	// Send the response to the client
	msg := buildResponse(r, qtype, qname, zone, rrs)
	if err := w.WriteMsg(msg); err != nil {
		Configuration.Logger.Error(err)
		return dns.RcodeServerFailure, err
	}

	Configuration.Logger.Info("Query response",
		slog.String("qname", qname),
		slog.String("qtype", dns.TypeToString[qtype]),
		slog.String("rcode", dns.RcodeToString[msg.Rcode]),
		slog.Any("reply", rrs))

	return msg.Rcode, nil
}

// buildResponse constructs the authoritative reply for a query answered out of
// a local zone. Records that matched are the answer; a query that matched none
// is a negative answer, and RFC 2308 §2 distinguishes two kinds of those:
// NXDOMAIN (RCODE 3) when the queried name exists nowhere in the zone, and
// NODATA (NOERROR with an empty answer section) when the name exists but holds
// no record of the queried type.
//
// Both kinds carry the zone SOA in the authority section so a resolver can
// cache the denial, with the TTL RFC 2308 §3 and §5 prescribe for it: the
// lesser of the SOA record's own TTL and its MINIMUM field.
func buildResponse(req *dns.Msg, qtype uint16, qname string, zone *entities.Zone, rrs []dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	// A name at or below a delegation point is not ours to answer OR to deny:
	// the parent zone holds the child's NS records but is not authoritative
	// for the names beneath them. RFC 1034 §4.3.2 step 3(b) finds the cut
	// while walking DOWN to the name, before any data at or below it is
	// considered — so this precedes the answer below. Whatever the parent
	// stores under a cut is glue for the additional section, never an answer,
	// and the delegating NS RRset belongs in the authority section with the
	// AA bit clear.
	//
	// Parent-side types at the cut are the exception — see
	// parentSideTypesAtCut.
	if owner, ns := delegationFor(zone, qname); len(ns) > 0 &&
		!isParentSideQuery(qtype, qname, owner) {
		msg.Authoritative = false
		msg.Ns = append(msg.Ns, ns...)
		msg.Extra = append(msg.Extra, glueFor(zone, owner, ns)...)
		return msg
	}

	if len(rrs) > 0 {
		msg.Answer = append(msg.Answer, rrs...)
		return msg
	}

	// A name that owns a CNAME owns nothing else (RFC 1034 §3.6.2), so a query
	// for any other type is answered with the alias and then restarted at its
	// target — §4.3.2 step 3(a). A negative answer here would have resolvers
	// cache "this name has no address" for an alias that resolves to one.
	if qtype != dns.TypeCNAME {
		if chain, nodata := cnameChain(zone, qname, qtype); len(chain) > 0 {
			msg.Answer = append(msg.Answer, chain...)
			if nodata {
				if soa := negativeSOA(zone); soa != nil {
					msg.Ns = append(msg.Ns, soa)
				}
			}
			return msg
		}
	}

	if !zoneHasName(zone, qname) {
		msg.Rcode = dns.RcodeNameError
	}
	if soa := negativeSOA(zone); soa != nil {
		msg.Ns = append(msg.Ns, soa)
	}
	return msg
}

// parentSideTypesAtCut are the record types a delegation point owns on the
// PARENT side of the cut, which this zone answers rather than refers: the DS
// that secures the child (RFC 4035 §3.1.4.1), including the NODATA that tells
// a validator the delegation is insecure, and the NSEC that proves the
// delegation exists or that its DS does not. Referring these would leave every
// insecure delegation unvalidatable and put an RRset the zone stores out of
// reach.
var parentSideTypesAtCut = map[uint16]struct{}{
	dns.TypeDS:   {},
	dns.TypeNSEC: {},
}

// isParentSideQuery reports whether a query is for parent-side data AT a
// delegation point. Below the cut nothing is parent-side.
func isParentSideQuery(qtype uint16, qname, owner string) bool {
	if !equalNames(qname, owner) {
		return false
	}
	_, ok := parentSideTypesAtCut[qtype]
	return ok
}

// maxCNAMEDepth bounds how far a CNAME chain is followed inside one zone.
// Zone data can point an alias at itself or around a cycle, and a query must
// terminate regardless.
const maxCNAMEDepth = 8

// cnameChain follows the alias at qname through this zone and returns the
// answer section for a query of qtype: the CNAME records traversed, followed
// by the target's own records when the chain ends at a name this zone holds.
// It returns no records when qname owns no CNAME.
//
// nodata reports that the chain ended INSIDE this zone at a name owning no
// record of the queried type, which is a negative answer the resolver may
// cache against the zone SOA. A chain leaving the zone is not nodata: the
// resolver continues from the target on its own.
func cnameChain(zone *entities.Zone, qname string, qtype uint16) (chain []dns.RR, nodata bool) {
	name := qname
	seen := make(map[string]struct{}, maxCNAMEDepth)

	for depth := 0; depth < maxCNAMEDepth; depth++ {
		if _, loop := seen[dns.CanonicalName(name)]; loop {
			return chain, false
		}
		seen[dns.CanonicalName(name)] = struct{}{}

		cnames, err := parseQueriedRecord(dns.TypeCNAME, name, zone)
		if err != nil || len(cnames) == 0 {
			// The chain ends here. It is a cacheable negative answer only
			// when this zone is the one that would hold the missing records.
			return chain, len(chain) > 0 && nameInZone(zone, name)
		}
		cname, ok := cnames[0].(*dns.CNAME)
		if !ok {
			return chain, false
		}
		chain = append(chain, cname)
		name = dns.Fqdn(cname.Target)

		// The target may sit in a delegated child zone. The parent cannot
		// answer inside it — what it holds there is glue, not data — so the
		// chain stops and the resolver follows the alias itself.
		if _, ns := delegationFor(zone, name); len(ns) > 0 {
			return chain, false
		}

		targets, err := parseQueriedRecord(qtype, name, zone)
		if err == nil && len(targets) > 0 {
			return append(chain, targets...), false
		}
	}
	return chain, false
}

// nameInZone reports whether a name falls inside the zone, and so is this
// server's to answer for.
func nameInZone(zone *entities.Zone, name string) bool {
	apex := dns.CanonicalName(zone.Name)
	canonical := dns.CanonicalName(name)
	return canonical == apex || strings.HasSuffix(canonical, "."+apex)
}

// delegationFor returns the delegation point enclosing the queried name and
// the NS records that delegate it to a child zone, or ("", nil) when the name
// is not at or below a delegation.
//
// A delegation is an NS RRset owned by a name other than the zone apex; the
// apex NS RRset names the zone's own servers and delegates nothing. When
// several delegations are ancestors of the query, the closest one wins — that
// is the zone actually holding the name.
func delegationFor(zone *entities.Zone, qname string) (string, []dns.RR) {
	q := dns.CanonicalName(qname)
	apex := dns.CanonicalName(zone.Name)

	closest := ""
	for _, r := range zone.RecordSet.NSRecords {
		owner := dns.CanonicalName(recordOwnerFQDN(r.Name, zone.Name))
		// An NS owner outside this zone delegates nothing from here: a query
		// for a name under it is routed to whichever zone is authoritative
		// for that name. Nothing constrains the stored owner today, and a
		// misconfigured "com." would otherwise refer the whole zone away.
		if owner == apex || !strings.HasSuffix(owner, "."+apex) {
			continue
		}
		// Authoritative data and a cut cannot share an owner (RFC 2181 §6.1),
		// so an NS owner that also holds an address, alias or any other RRset
		// here delegates nothing: it is a zone's own NS RRset stored under a
		// hostname instead of the apex. Zones seeded from templates older than
		// 2026-09-02 carry exactly that, and reading it as a delegation would
		// refer a name this zone still answers.
		if ownsNonDelegationData(zone, owner) {
			continue
		}
		if q != owner && !strings.HasSuffix(q, "."+owner) {
			continue
		}
		if len(owner) > len(closest) {
			closest = owner
		}
	}
	if closest == "" {
		return "", nil
	}

	recs := make([]dns.RR, 0, len(zone.RecordSet.NSRecords))
	for _, r := range zone.RecordSet.NSRecords {
		owner := recordOwnerFQDN(r.Name, zone.Name)
		if dns.CanonicalName(owner) != closest {
			continue
		}
		recs = append(recs, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   owner,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    r.TTL,
			},
			Ns: r.Value,
		})
	}
	return closest, recs
}

// glueFor returns the address records the parent holds for the nameservers a
// referral names. Only IN-BAILIWICK targets — names at or below the delegation
// point — can have glue here; an address for anything else is not this zone's
// to give, and the resolver looks it up separately. Without glue an
// in-bailiwick referral is a circular dependency the resolver cannot break.
func glueFor(zone *entities.Zone, owner string, ns []dns.RR) []dns.RR {
	glue := make([]dns.RR, 0, len(ns)*2)
	seen := make(map[string]struct{}, len(ns))

	for _, rr := range ns {
		nsRR, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		target := dns.Fqdn(nsRR.Ns)
		canonical := dns.CanonicalName(target)
		if !equalNames(target, owner) &&
			!strings.HasSuffix(canonical, "."+dns.CanonicalName(owner)) {
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}

		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			addrs, err := parseQueriedRecord(qtype, target, zone)
			if err != nil {
				continue
			}
			glue = append(glue, addrs...)
		}
	}
	return glue
}

// negativeSOA builds the zone SOA that accompanies a negative answer in the
// authority section, bounded by the negative-caching TTL of RFC 2308 §3.
// It returns nil when the zone has no SOA to cite.
func negativeSOA(zone *entities.Zone) *dns.SOA {
	soa := zone.RecordSet.SOARecord
	ttl := soaTTL(zone)
	if soa.MinimumTTL > 0 && (ttl == 0 || soa.MinimumTTL < ttl) {
		ttl = soa.MinimumTTL
	}
	return soaRR(zone.Name, &soa, ttl)
}

// findZoneForQuery locates the authoritative zone for a DNS query name by
// walking up the label hierarchy. For a query like _8443._tcp.server.example.com.,
// this tries each suffix in order:
//
//	_8443._tcp.server.example.com.
//	_tcp.server.example.com.
//	server.example.com.
//	example.com.
//	com.
//
// The first match against the zone DAO is the authoritative zone for the query.
func findZoneForQuery(ctx context.Context, qname string, zDAO dao.ZoneDAO) *entities.Zone {
	labels := dns.SplitDomainName(qname)
	for i := range labels {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		z, err := zDAO.Get(ctx, util.NewID([]byte(candidate)))
		if err == nil {
			return z
		}
	}
	return nil
}

func setup(c *caddy.Controller) error {
	// Parse and validate configuration from CoreDNS
	for c.Next() {
		if len(c.RemainingArgs()) > 0 {
			return plugin.Error(trustedPlatformPlugin, c.ArgErr())
		}
	}

	// Initialize macro values
	if err := setupMacros(); err != nil {
		return &WrappedError{Msg: "failed to set up zone macros", Err: err}
	}

	// Use injected DatastoreFactory if available (shared with main platform),
	// otherwise create a new one (standalone DNS server mode)
	if DatastoreFactory != nil {
		log.Infof("Using injected datastore factory for DNS zone storage")
		datastoreFactory = DatastoreFactory

		// Get ZoneDAO from injected factory
		var err error
		zoneDAO, err = datastoreFactory.ZoneDAO()
		if err != nil {
			return &WrappedError{Msg: "failed to get ZoneDAO from injected factory", Err: err}
		}
	} else {
		log.Infof("Creating standalone QuicBaaS factory for DNS zone storage")

		// Create QuicBaaS factory from configuration
		factory, err := quicbaas.NewFactory(Configuration.QuicBaaS, Configuration.Logger, nil)
		if err != nil {
			return &WrappedError{Msg: "failed to create QuicBaaS factory", Err: err}
		}
		datastoreFactory = factory

		// Start the QuicBaaS factory - required before any DAO operations.
		//
		// The budget is the configured startup budget, not an arbitrary 30s
		// (#270). The embedded server's Start takes no context: it runs first
		// boot -- barrier construction, a TPM open, the system tenant and five
		// roles -- synchronously, and the context is consulted only afterwards.
		// So a deadline shorter than that work cannot interrupt it; it can only
		// report a startup that already succeeded as a failure.
		ctx, cancel := context.WithTimeout(context.Background(), Configuration.QuicBaaS.EffectiveStartupTimeout())
		defer cancel()
		if err := datastoreFactory.Start(ctx); err != nil {
			return &WrappedError{Msg: "failed to start QuicBaaS factory", Err: err}
		}

		// Initialize global ZoneDAO defined at the top of the file and used in ServeDNS
		// to retrieve zone information
		zoneDAO, err = datastoreFactory.ZoneDAO()
		if err != nil {
			return &WrappedError{Msg: "failed to initialize ZoneDAO", Err: err}
		}
	}

	// Process internal and public server zones
	if Configuration.InternalServer != nil {
		if err := processZone(Configuration.InternalServer.Zone, zoneDAO, "internal"); err != nil {
			return &WrappedError{Msg: "failed to process internal zone", Err: err}
		}
	}
	if Configuration.PublicServer != nil {
		if err := processZone(Configuration.PublicServer.Zone, zoneDAO, "public"); err != nil {
			return &WrappedError{Msg: "failed to process public zone", Err: err}
		}
	}

	// When zone_subdomains is enabled, pre-create one DNS sub-zone per network
	// zone under the internal domain. This makes names like
	// host.trusted.example.internal. resolvable immediately, before any device
	// has registered. The operation is idempotent: existing sub-zones are left
	// unchanged.
	if Configuration.ZoneSubdomains && Configuration.InternalServer != nil {
		tenantID := ""
		if Configuration.InternalServer.Zone.TenantID != "" {
			tenantID = Configuration.InternalServer.Zone.TenantID
		}
		if err := InitNetworkZoneSubdomains(
			context.Background(),
			Configuration,
			Configuration.NetworkZones,
			zoneDAO,
			tenantID,
		); err != nil {
			return &WrappedError{Msg: "failed to initialise network-zone subdomains", Err: err}
		}
		log.Infof("Network-zone subdomains initialised: %v", Configuration.NetworkZones)
	}

	// Install outbound zone-transfer TSIG secrets so the DNS server
	// validates AXFR requests signed by configured secondaries. When no
	// keys are configured the AXFR responder stays fail-closed.
	if secrets := configureTransfer(Configuration.Transfer); len(secrets) > 0 {
		cfg := dnsserver.GetConfig(c)
		if cfg.TsigSecret == nil {
			cfg.TsigSecret = make(map[string]string, len(secrets))
		}
		for name, secret := range secrets {
			cfg.TsigSecret[name] = secret
		}
		log.Infof("Outbound zone transfer enabled for %d TSIG secondary key(s)", len(secrets))
	}

	// Register the plugin in the middleware chain
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return TrustedPlatformPlugin{
			Next: next,
		}
	})

	return nil
}

// isNotFoundError checks if an error is a not-found error from QuicBaaS.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Check for QuicBaaS error types
	var notFoundErr quicbaas.ErrNotFound
	if errors.As(err, &notFoundErr) {
		return true
	}
	var notFoundByIndexErr quicbaas.ErrNotFoundByIndex
	if errors.As(err, &notFoundByIndexErr) {
		return true
	}
	// Fallback: check error message for "not found"
	errMsg := err.Error()
	return strings.Contains(errMsg, "not found")
}

// processZone handles loading and saving a zone from the configuration
func processZone(zone entities.Zone, zoneDAO dao.ZoneDAO, serverType string) error {

	if zone.Name == "" {
		return &DetailError{Err: ErrServerZoneUndefined, Detail: " (" + serverType + " server)"}
	}

	ctx := context.Background()

	// Check if the zone already exists in the datastore
	existingZone, err := zoneDAO.GetByName(ctx, zone.Name)
	if err != nil && !isNotFoundError(err) {
		return &ZoneError{Op: "look up", Zone: zone.Name, Err: err}
	}

	// Save the zone to the datastore if it doesn't already exist
	if existingZone == nil {
		log.Infof("Zone %s (%s server) not found in datastore, saving...", zone.Name, serverType)
		if zone.ID == 0 {
			zone.ID = util.NewID([]byte(zone.Name))
		}

		// Expand config file macros
		if err := Expand(&zone); err != nil {
			return &ZoneError{Op: "expand", Zone: zone.Name, Err: err}
		}

		// Sign the zone with DNSSEC if enabled
		if err := signZoneIfEnabled(&zone); err != nil {
			return &ZoneError{Op: "sign", Zone: zone.Name, Err: err}
		}

		// Save the zone to the datastore
		if err := zoneDAO.Save(ctx, &zone); err != nil {
			return &ZoneError{Op: "save", Zone: zone.Name, Err: err}
		}
		log.Infof("Zone %s (%s server) saved to datastore", zone.Name, serverType)
	} else if needsDNSSECSigning(existingZone) {
		// The zone already exists, so the only outstanding work is signing it.
		log.Infof("Zone %s (%s server) needs DNSSEC signing, signing...", zone.Name, serverType)

		// Sign the existing zone
		if err := signZoneIfEnabled(existingZone); err != nil {
			return &ZoneError{Op: "sign", Zone: zone.Name, Err: err}
		}

		// Update the zone in the datastore
		if err := zoneDAO.Save(ctx, existingZone); err != nil {
			return &ZoneError{Op: "update", Zone: zone.Name, Err: err}
		}
		log.Infof("Zone %s (%s server) DNSSEC signed and saved", zone.Name, serverType)
	}

	return nil
}

// needsDNSSECSigning checks if a zone needs DNSSEC signing.
// Returns true if DNSSEC is enabled but the zone has no DNSSEC records.
func needsDNSSECSigning(zone *entities.Zone) bool {
	// Check if DNSSEC is enabled
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return false
	}

	// Check if zone already has DNSSEC records
	if len(zone.RecordSet.DNSKEYRecords) > 0 {
		// Zone already has DNSKEY records, check for RRSIG records too
		if len(zone.RecordSet.RRSIGRecords) > 0 {
			return false // Zone is already signed
		}
	}

	return true
}

// signZoneIfEnabled signs a zone with DNSSEC. DNSSEC must be configured with
// a working key backend (KeyStore or XKMSAdapter) before this is called — a
// missing backend is a hard failure, not a silent skip.
//
// Previous behaviour silently logged "skipping signing (will sign when
// available)" and returned nil, which let the caller log "Zone X DNSSEC
// signed and saved" even though the zone was NOT signed. That allowed
// zones to be persisted unsigned into the datastore with no error path,
// and the rest of the application carried on as if everything was fine.
// Removed 2026-04-08 on operator demand: no silent fallbacks, surface the
// real failure so the caller aborts.
func signZoneIfEnabled(zone *entities.Zone) error {
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return nil
	}

	var dnssecSvc *DNSSECService
	var err error

	switch {
	case KeyStore != nil:
		log.Infof("Using DNSSEC key store for key management")
		dnssecSvc, err = NewDNSSECServiceWithKeyStore(Configuration.DNSSEC, Configuration.Logger, KeyStore)
		if err != nil {
			return &WrappedError{Msg: "dns: failed to create DNSSEC service with key store", Err: err}
		}
	case XKMSAdapter != nil:
		log.Infof("Using XKMS adapter for DNSSEC key management")
		dnssecSvc, err = NewDNSSECServiceWithXKMS(Configuration.DNSSEC, Configuration.Logger, XKMSAdapter)
		if err != nil {
			return &WrappedError{Msg: "dns: failed to create DNSSEC service with XKMS adapter", Err: err}
		}
	default:
		// HARD FAIL: DNSSEC is enabled but no key backend is wired up.
		// The caller MUST NOT persist this zone as "signed" — the data is
		// unsigned and the validator will reject it downstream.
		return ErrNoDNSSECSigner
	}

	log.Infof("Signing zone %s with DNSSEC", zone.Name)
	if err := dnssecSvc.SignZone(zone); err != nil {
		return &WrappedError{Msg: "dns: DNSSEC signing failed", Err: err}
	}
	log.Infof("Zone %s signed with DNSSEC successfully", zone.Name)

	return nil
}

// SetXKMSAdapter sets the global XKMS adapter for DNSSEC key management
// and signs any zones that were loaded before the adapter was available.
func SetXKMSAdapter(adapter *xkmsadapter.Adapter) error {
	XKMSAdapter = adapter
	return SignUnsignedZones()
}

// SetDNSSECKeyStore sets the global DNSSEC key store and signs any zones
// that were loaded before the key store was available.
func SetDNSSECKeyStore(ks DNSSECKeyStore) error {
	KeyStore = ks
	return SignUnsignedZones()
}

// SignUnsignedZones signs all zones that need DNSSEC signing.
// This is called after the XKMS adapter or key store becomes available
// to handle deferred signing from initial zone loading.
func SignUnsignedZones() error {
	if Configuration == nil || Configuration.DNSSEC == nil || !Configuration.DNSSEC.Enabled {
		return nil
	}

	if KeyStore == nil && XKMSAdapter == nil {
		return nil
	}

	if zoneDAO == nil {
		return nil
	}

	ctx := context.Background()

	// Collect zones that need signing from the configured servers
	type zoneRef struct {
		name       string
		serverType string
	}
	var zones []zoneRef

	if Configuration.InternalServer != nil && Configuration.InternalServer.Zone.Name != "" {
		zones = append(zones, zoneRef{
			name:       Configuration.InternalServer.Zone.Name,
			serverType: "internal",
		})
	}
	if Configuration.PublicServer != nil && Configuration.PublicServer.Zone.Name != "" {
		zones = append(zones, zoneRef{
			name:       Configuration.PublicServer.Zone.Name,
			serverType: "public",
		})
	}

	for _, zr := range zones {
		zone, err := zoneDAO.GetByName(ctx, zr.name)
		if err != nil {
			log.Warningf("Failed to retrieve zone %s for deferred DNSSEC signing: %v", zr.name, err)
			continue
		}
		if zone == nil {
			continue
		}

		if !needsDNSSECSigning(zone) {
			continue
		}

		log.Infof("Deferred DNSSEC signing for zone %s (%s server)", zr.name, zr.serverType)

		if err := signZoneIfEnabled(zone); err != nil {
			log.Warningf("Failed deferred DNSSEC signing for zone %s: %v", zr.name, err)
			continue
		}

		if err := zoneDAO.Save(ctx, zone); err != nil {
			log.Warningf("Failed to save zone %s after deferred DNSSEC signing: %v", zr.name, err)
			continue
		}

		log.Infof("Zone %s (%s server) DNSSEC signed via deferred signing", zr.name, zr.serverType)
	}

	return nil
}

// Saves a new zone file to the datastore. If DNSSEC is enabled, the zone
// is signed before saving. This function uses the global zoneDAO that's
// initialized during plugin setup.
func Save(ctx context.Context, zone *entities.Zone) error {
	if zoneDAO == nil {
		return &MessageError{Msg: "zone DAO not initialized - plugin setup may not have completed"}
	}

	if zone.ID == 0 {
		zone.ID = util.NewID([]byte(zone.Name))
	}

	// Sign the zone with DNSSEC if enabled
	if err := signZoneIfEnabled(zone); err != nil {
		return &WrappedError{Msg: "failed to sign zone", Err: err}
	}

	if err := zoneDAO.Save(ctx, zone); err != nil {
		return &WrappedError{Msg: "failed to save zone", Err: err}
	}

	return nil
}

// Helper functions to handle pointer fields
func uint16Ptr(i uint16) *uint16 { return &i }
func uint32Ptr(i uint32) *uint32 { return &i }
