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
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// tsigFudge is the permitted clock skew (seconds) between the platform and
// a secondary when validating/signing TSIG timestamps (RFC 8945 §5.2).
const tsigFudge = 300

// transferKeys maps the canonical TSIG key name to its base64 secret for
// every secondary authorized to pull zone transfers. It is populated during
// CoreDNS plugin setup from Config.Transfer and mirrors the dnsserver TSIG
// secrets so the AXFR responder can reject requests signed with an unknown
// key. A nil or empty map means outbound AXFR is disabled (fail closed).
var transferKeys map[string]string

// configureTransfer copies the configured TSIG keys into the package-level
// transferKeys map and returns the same map for installation into the
// dnsserver TSIG secret table. The returned map is nil when transfers are
// disabled so callers can leave the server TSIG table untouched.
func configureTransfer(cfg *TransferConfig) map[string]string {
	if cfg == nil || !cfg.Enabled || len(cfg.TSIGKeys) == 0 {
		transferKeys = nil
		return nil
	}
	keys := make(map[string]string, len(cfg.TSIGKeys))
	for _, k := range cfg.TSIGKeys {
		if k.Name == "" || k.Secret == "" {
			continue
		}
		keys[dns.CanonicalName(k.Name)] = k.Secret
	}
	if len(keys) == 0 {
		transferKeys = nil
		return nil
	}
	transferKeys = keys
	return keys
}

// canonicalTSIGAlgorithm normalises a configured TSIG algorithm to the
// miekg/dns canonical form, defaulting to HMAC-SHA256 when unset.
func canonicalTSIGAlgorithm(alg string) string {
	if alg == "" {
		return dns.HmacSHA256
	}
	return dns.CanonicalName(alg)
}

// handleZoneTransfer answers an AXFR (or IXFR, served as a full AXFR) request
// for the located zone. The platform is a PRIMARY nameserver: it streams the
// full zone — SOA, all records, closing SOA per RFC 5936 — to secondaries
// that authenticate with a configured TSIG key over DNS TCP. Every failure
// path refuses the transfer with a typed security-logged rejection; no zone
// data is emitted to an unauthenticated or unauthorized peer.
func (cp TrustedPlatformPlugin) handleZoneTransfer(
	ctx context.Context,
	w dns.ResponseWriter,
	r *dns.Msg,
	zone *entities.Zone,
	qname string,
) (int, error) {

	// Fail closed: no configured, keyed secondaries means no transfers.
	if len(transferKeys) == 0 {
		return cp.refuseTransfer(ctx, w, r, qname, "outbound zone transfer is not configured")
	}

	// AXFR/IXFR are TCP-only operations (RFC 5936 §4.2). Refuse datagram
	// transports outright — a UDP AXFR cannot carry a full zone and is a
	// common reconnaissance probe.
	if addr := w.RemoteAddr(); addr == nil || !strings.HasPrefix(addr.Network(), "tcp") {
		return cp.refuseTransfer(ctx, w, r, qname, "zone transfer requires TCP")
	}

	// A TSIG record is mandatory.
	tsig := r.IsTsig()
	if tsig == nil {
		return cp.refuseTransfer(ctx, w, r, qname, "zone transfer requires TSIG authentication")
	}

	// The presented key must be one of the configured secondaries.
	keyName := dns.CanonicalName(tsig.Hdr.Name)
	if _, ok := transferKeys[keyName]; !ok {
		return cp.refuseTransfer(ctx, w, r, qname, "TSIG key not authorized for zone transfer: "+keyName)
	}

	// The server-side TSIG verification result must be clean. This is set
	// by the miekg server when the request was signed with the matching
	// secret installed during plugin setup.
	if err := w.TsigStatus(); err != nil {
		return cp.refuseTransfer(ctx, w, r, qname, "TSIG verification failed: "+err.Error())
	}

	// Build the full-zone answer in RFC 5936 order and sign the reply with
	// the request's key so the secondary can authenticate the response.
	records := BuildZoneTransfer(zone)

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.Answer = records
	msg.SetTsig(tsig.Hdr.Name, canonicalTSIGAlgorithm(tsig.Algorithm), tsigFudge, time.Now().Unix())

	if err := w.WriteMsg(msg); err != nil {
		Configuration.Logger.Error(&WrappedError{Msg: "failed to write AXFR response", Err: err})
		return dns.RcodeServerFailure, err
	}

	Configuration.Logger.Info("Served zone transfer",
		slog.String("zone", zone.Name),
		slog.String("qname", qname),
		slog.String("key", keyName),
		slog.String("remote", w.RemoteAddr().String()),
		slog.Int("records", len(records)))

	return dns.RcodeSuccess, nil
}

// refuseTransfer emits a security log entry and replies REFUSED without
// leaking any zone data.
func (cp TrustedPlatformPlugin) refuseTransfer(
	ctx context.Context,
	w dns.ResponseWriter,
	r *dns.Msg,
	qname, reason string,
) (int, error) {

	remote := ""
	if w.RemoteAddr() != nil {
		remote = w.RemoteAddr().String()
	}

	Configuration.Logger.Warn("Refusing zone transfer",
		slog.String("qname", qname),
		slog.String("reason", reason),
		slog.String("remote", remote))

	Configuration.Logger.Security(ctx, logging.SecurityLogEntry{
		Category:        logging.CategoryNetworkSecurity,
		Description:     "Refused DNS zone transfer",
		Details:         qname + ": " + reason,
		OffenderAddress: remote,
		Source:          logging.SourceDNS,
		Severity:        logging.SeverityMedium,
		Timestamp:       time.Now(),
	})

	msg := new(dns.Msg)
	msg.SetRcode(r, dns.RcodeRefused)
	if err := w.WriteMsg(msg); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeRefused, nil
}

// BuildZoneTransfer projects a zone's stored record set into an ordered slice
// of resource records suitable for an AXFR response: the apex SOA first, then
// every record in the zone (including any DNSSEC records), then the apex SOA
// again to terminate the transfer per RFC 5936 §2.2. Record owner names are
// resolved to fully qualified names within the zone; malformed address
// records are skipped rather than emitted in an invalid wire form.
func BuildZoneTransfer(zone *entities.Zone) []dns.RR {
	if zone == nil {
		return nil
	}

	rs := &zone.RecordSet
	soa := buildTransferSOA(zone)

	records := make([]dns.RR, 0, 2+zoneRecordCount(rs))
	if soa != nil {
		records = append(records, soa)
	}

	// NS records at the apex delegate authority and conventionally lead the
	// body of an AXFR.
	for _, r := range rs.NSRecords {
		records = append(records, &dns.NS{
			Hdr: transferHeader(r.Name, zone.Name, dns.TypeNS, r.TTL, zone.TTL),
			Ns:  dns.Fqdn(r.Value),
		})
	}
	for _, r := range rs.ARecords {
		ip := net.ParseIP(r.Value).To4()
		if ip == nil {
			continue
		}
		records = append(records, &dns.A{
			Hdr: transferHeader(r.Name, zone.Name, dns.TypeA, r.TTL, zone.TTL),
			A:   ip,
		})
	}
	for _, r := range rs.AAAARecords {
		ip := net.ParseIP(r.Value).To16()
		if ip == nil {
			continue
		}
		records = append(records, &dns.AAAA{
			Hdr:  transferHeader(r.Name, zone.Name, dns.TypeAAAA, r.TTL, zone.TTL),
			AAAA: ip,
		})
	}
	for _, r := range rs.CNAMERecords {
		records = append(records, &dns.CNAME{
			Hdr:    transferHeader(r.Name, zone.Name, dns.TypeCNAME, r.TTL, zone.TTL),
			Target: dns.Fqdn(r.Value),
		})
	}
	for _, r := range rs.MXRecords {
		records = append(records, &dns.MX{
			Hdr:        transferHeader(r.Name, zone.Name, dns.TypeMX, r.TTL, zone.TTL),
			Preference: r.Priority,
			Mx:         dns.Fqdn(r.Value),
		})
	}
	for _, r := range rs.TXTRecords {
		records = append(records, &dns.TXT{
			Hdr: transferHeader(r.Name, zone.Name, dns.TypeTXT, r.TTL, zone.TTL),
			Txt: []string{r.Value},
		})
	}
	for _, r := range rs.SRVRecords {
		records = append(records, &dns.SRV{
			Hdr:      transferHeader(r.Name, zone.Name, dns.TypeSRV, r.TTL, zone.TTL),
			Priority: r.Priority,
			Weight:   r.Weight,
			Port:     r.Port,
			Target:   dns.Fqdn(r.Target),
		})
	}
	for _, r := range rs.CAARecords {
		records = append(records, &dns.CAA{
			Hdr:   transferHeader(r.Name, zone.Name, dns.TypeCAA, r.TTL, zone.TTL),
			Flag:  r.Flags,
			Tag:   r.Tag,
			Value: r.Value,
		})
	}
	for _, r := range rs.TLSARecords {
		records = append(records, &dns.TLSA{
			Hdr:          transferHeader(r.Name, zone.Name, dns.TypeTLSA, r.TTL, zone.TTL),
			Usage:        r.Usage,
			Selector:     r.Selector,
			MatchingType: r.MatchingType,
			Certificate:  r.Data,
		})
	}
	for _, r := range rs.DNSKEYRecords {
		records = append(records, &dns.DNSKEY{
			Hdr:       transferHeader(r.Name, zone.Name, dns.TypeDNSKEY, r.TTL, zone.TTL),
			Flags:     r.Flags,
			Protocol:  r.Protocol,
			Algorithm: r.Algorithm,
			PublicKey: r.Key,
		})
	}
	for _, r := range rs.DSRecords {
		records = append(records, &dns.DS{
			Hdr:        transferHeader(r.Name, zone.Name, dns.TypeDS, r.TTL, zone.TTL),
			KeyTag:     r.KeyTag,
			Algorithm:  r.Algorithm,
			DigestType: r.DigestType,
			Digest:     r.Digest,
		})
	}
	for _, r := range rs.RRSIGRecords {
		records = append(records, &dns.RRSIG{
			Hdr:         transferHeader(zone.Name, zone.Name, dns.TypeRRSIG, r.OriginalTTL, zone.TTL),
			TypeCovered: dns.StringToType[strings.ToUpper(r.TypeCovered)],
			Algorithm:   r.Algorithm,
			Labels:      r.Labels,
			OrigTtl:     r.OriginalTTL,
			Expiration:  parseRRSIGTimestamp(r.Expiration),
			Inception:   parseRRSIGTimestamp(r.Inception),
			KeyTag:      r.KeyTag,
			SignerName:  dns.Fqdn(r.SignerName),
			Signature:   r.Signature,
		})
	}
	for _, r := range rs.NSECRecords {
		records = append(records, &dns.NSEC{
			Hdr:        transferHeader(r.Name, zone.Name, dns.TypeNSEC, r.TTL, zone.TTL),
			NextDomain: dns.Fqdn(r.NextDomain),
			TypeBitMap: r.TypeBitMap,
		})
	}
	for _, r := range rs.NSEC3Records {
		records = append(records, &dns.NSEC3{
			Hdr:        transferHeader(r.Name, zone.Name, dns.TypeNSEC3, r.TTL, zone.TTL),
			Hash:       r.Algorithm,
			Flags:      r.Flags,
			Iterations: r.Iterations,
			SaltLength: uint8(len(r.Salt) / 2),
			Salt:       r.Salt,
			HashLength: uint8(len(r.NextHashed)),
			NextDomain: r.NextHashed,
			TypeBitMap: r.TypeBitMap,
		})
	}
	for _, r := range rs.NSEC3PARAMRecords {
		records = append(records, &dns.NSEC3PARAM{
			Hdr:        transferHeader(r.Name, zone.Name, dns.TypeNSEC3PARAM, r.TTL, zone.TTL),
			Hash:       r.Algorithm,
			Flags:      r.Flags,
			Iterations: r.Iterations,
			SaltLength: uint8(len(r.Salt) / 2),
			Salt:       r.Salt,
		})
	}

	// Closing SOA terminates the transfer.
	if soa != nil {
		records = append(records, soa)
	}

	return records
}

// buildTransferSOA constructs the apex SOA record for the zone, or nil when
// the zone has no SOA configured (an AXFR without an SOA is invalid, so the
// caller emits nothing and the transfer is refused upstream).
func buildTransferSOA(zone *entities.Zone) *dns.SOA {
	soa := zone.RecordSet.SOARecord
	if soa.MName == "" {
		return nil
	}
	ttl := soa.TTL
	if ttl == 0 {
		ttl = zone.TTL
	}
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone.Name),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      dns.Fqdn(soa.MName),
		Mbox:    dns.Fqdn(soa.RName),
		Serial:  soa.Serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minttl:  soa.MinimumTTL,
	}
}

// transferHeader builds an RR header with the record's owner resolved to a
// fully qualified name within the zone and a TTL that falls back to the zone
// default when the record TTL is unset.
func transferHeader(name, zoneName string, rrtype uint16, ttl, zoneTTL uint32) dns.RR_Header {
	if ttl == 0 {
		ttl = zoneTTL
	}
	return dns.RR_Header{
		Name:   recordOwnerFQDN(name, zoneName),
		Rrtype: rrtype,
		Class:  dns.ClassINET,
		Ttl:    ttl,
	}
}

// recordOwnerFQDN resolves a stored record owner name to a fully qualified
// name within the zone. An empty name or "@" maps to the zone apex; a name
// that is already fully qualified is returned unchanged; a relative label is
// joined to the zone apex.
func recordOwnerFQDN(name, zoneName string) string {
	zoneFQDN := dns.Fqdn(zoneName)
	if name == "" || name == "@" {
		return zoneFQDN
	}
	if dns.IsFqdn(name) {
		return name
	}
	return dns.Fqdn(name + "." + strings.TrimSuffix(zoneFQDN, "."))
}

// zoneRecordCount returns the number of non-SOA records in the set, used to
// pre-size the AXFR answer slice.
func zoneRecordCount(rs *entities.RecordSet) int {
	return len(rs.ARecords) + len(rs.AAAARecords) + len(rs.CNAMERecords) +
		len(rs.MXRecords) + len(rs.NSRecords) + len(rs.TXTRecords) +
		len(rs.SRVRecords) + len(rs.CAARecords) + len(rs.TLSARecords) +
		len(rs.DNSKEYRecords) + len(rs.DSRecords) + len(rs.RRSIGRecords) +
		len(rs.NSECRecords) + len(rs.NSEC3Records) + len(rs.NSEC3PARAMRecords)
}

// isTransferQuery reports whether a query type is a zone-transfer request.
func isTransferQuery(qtype uint16) bool {
	return qtype == dns.TypeAXFR || qtype == dns.TypeIXFR
}
