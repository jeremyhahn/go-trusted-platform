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
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// labelRegexp validates DNS labels per RFC 1035 with underscore support per
// RFC 8552. Underscore-prefixed labels are required for TLSA (_8443._tcp),
// SRV (_sip._tcp), DKIM (_dkim), and other scoped DNS record types.
var labelRegexp = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?$`)

// Error for unsupported record types
var ErrRecordTypeNotSupported = errors.New("dns: record type not supported")

// RecordParserFunc defines a function type for parsing DNS records
type RecordParserFunc func(qname string, zone *entities.Zone) []dns.RR

// Record parser functions for each supported record type in a zone
var recordParserFuncs = map[uint16]RecordParserFunc{
	dns.TypeA: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.ARecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			// net.ParseIP returns a 16-byte IPv6-mapped form for
			// IPv4 inputs. miekg/dns serialises dns.A records with
			// rdlen=len(A) — passing the 16-byte form produces a
			// rdlen=0 wire response and strict resolvers (e.g.
			// systemd-resolved) reject the answer as malformed.
			// .To4() coerces the 4-byte form, dropping bad inputs.
			ip := net.ParseIP(r.Value).To4()
			if ip == nil {
				continue
			}
			recs = append(recs, &dns.A{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				A: ip,
			})
		}
		return recs
	},
	dns.TypeAAAA: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.AAAARecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			// .To16() guarantees the 16-byte AAAA wire form. Also
			// fix the Rrtype which was previously set to dns.TypeA
			// (copy-paste from the IPv4 branch) — strict resolvers
			// rejected AAAA answers because the header type didn't
			// match the rdata format.
			ip := net.ParseIP(r.Value).To16()
			if ip == nil {
				continue
			}
			recs = append(recs, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				AAAA: ip,
			})
		}
		return recs
	},
	dns.TypeMX: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.MXRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.MX{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeMX,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Preference: r.Priority,
				Mx:         r.Value,
			})
		}
		return recs
	},
	dns.TypeCNAME: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.CNAMERecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Target: r.Value,
			})
		}
		return recs
	},
	dns.TypeNS: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.NSRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.NS{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Ns: r.Value,
			})
		}
		return recs
	},
	// A zone has exactly one SOA and it sits at the apex (RFC 1034 §4.2), so
	// the SOA answers for the zone name and for no other name within it.
	dns.TypeSOA: func(qname string, zone *entities.Zone) []dns.RR {
		if !isZoneApex(qname, zone.Name) {
			return nil
		}
		soa := soaRR(qname, &zone.RecordSet.SOARecord, soaTTL(zone))
		if soa == nil {
			return nil
		}
		return []dns.RR{soa}
	},
	dns.TypeTXT: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.TXTRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Txt: []string{r.Value},
			})
		}
		return recs
	},
	dns.TypeCAA: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.CAARecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.CAA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeCAA,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Flag:  r.Flags,
				Tag:   r.Tag,
				Value: r.Value,
			})
		}
		return recs
	},
	dns.TypeTLSA: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.TLSARecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Usage:        r.Usage,
				Selector:     r.Selector,
				MatchingType: r.MatchingType,
				Certificate:  r.Data,
			})
		}
		return recs
	},
	dns.TypeSRV: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.SRVRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.SRV{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Priority: r.Priority,
				Weight:   r.Weight,
				Port:     r.Port,
				Target:   r.Target,
			})
		}
		return recs
	},
	dns.TypeDNSKEY: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.DNSKEYRecords == nil {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.DNSKEYRecords))
		for _, r := range zone.RecordSet.DNSKEYRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Flags:     r.Flags,
				Protocol:  r.Protocol,
				Algorithm: r.Algorithm,
				PublicKey: r.Key,
			})
		}
		return recs
	},
	dns.TypeDS: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.DSRecords == nil {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.DSRecords))
		for _, r := range zone.RecordSet.DSRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.DS{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				KeyTag:     r.KeyTag,
				Algorithm:  r.Algorithm,
				DigestType: r.DigestType,
				Digest:     r.Digest,
			})
		}
		return recs
	},
	// RRSIGRecord carries no owner name, so the zone's signatures are owned
	// by the apex — the same assumption BuildZoneTransfer makes when it emits
	// them for an AXFR. Answering them at every name in the zone leaked the
	// whole signature set to any query.
	dns.TypeRRSIG: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.RRSIGRecords == nil || !isZoneApex(qname, zone.Name) {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.RRSIGRecords))
		for _, r := range zone.RecordSet.RRSIGRecords {
			typeCovered := dns.StringToType[strings.ToUpper(r.TypeCovered)]
			expiration := parseRRSIGTimestamp(r.Expiration)
			inception := parseRRSIGTimestamp(r.Inception)
			recs = append(recs, &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    r.OriginalTTL,
				},
				TypeCovered: typeCovered,
				Algorithm:   r.Algorithm,
				Labels:      r.Labels,
				OrigTtl:     r.OriginalTTL,
				Expiration:  expiration,
				Inception:   inception,
				KeyTag:      r.KeyTag,
				SignerName:  r.SignerName,
				Signature:   r.Signature,
			})
		}
		return recs
	},
	dns.TypeNSEC: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.NSECRecords == nil {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.NSECRecords))
		for _, r := range zone.RecordSet.NSECRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.NSEC{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeNSEC,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				NextDomain: r.NextDomain,
				TypeBitMap: r.TypeBitMap,
			})
		}
		return recs
	},
	dns.TypeNSEC3: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.NSEC3Records == nil {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.NSEC3Records))
		for _, r := range zone.RecordSet.NSEC3Records {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.NSEC3{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeNSEC3,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
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
		return recs
	},
	dns.TypeNSEC3PARAM: func(qname string, zone *entities.Zone) []dns.RR {
		if zone.RecordSet.NSEC3PARAMRecords == nil {
			return nil
		}
		recs := make([]dns.RR, 0, len(zone.RecordSet.NSEC3PARAMRecords))
		for _, r := range zone.RecordSet.NSEC3PARAMRecords {
			if !ownerMatchesQuery(r.Name, qname, zone.Name) {
				continue
			}
			recs = append(recs, &dns.NSEC3PARAM{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeNSEC3PARAM,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Hash:       r.Algorithm,
				Flags:      r.Flags,
				Iterations: r.Iterations,
				SaltLength: uint8(len(r.Salt) / 2),
				Salt:       r.Salt,
			})
		}
		return recs
	},
}

// soaTTL returns the effective TTL of a zone's SOA: the record's own TTL, or
// the zone default when it has none. Zones that set only the top-level ttl
// would otherwise serve, and have resolvers cache, an SOA with TTL 0.
func soaTTL(zone *entities.Zone) uint32 {
	if ttl := zone.RecordSet.SOARecord.TTL; ttl != 0 {
		return ttl
	}
	return zone.TTL
}

// soaRR builds a zone's SOA resource record from its stored entity, owned by
// the supplied name and carrying the supplied TTL. It returns nil when the
// zone has no SOA configured: a record with no MNAME names no primary server
// and is not an answer.
func soaRR(owner string, r *entities.SOARecord, ttl uint32) *dns.SOA {
	if r.MName == "" {
		return nil
	}
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      dns.Fqdn(r.MName),
		Mbox:    dns.Fqdn(r.RName),
		Serial:  r.Serial,
		Refresh: r.Refresh,
		Retry:   r.Retry,
		Expire:  r.Expire,
		Minttl:  r.MinimumTTL,
	}
}

// parseRRSIGTimestamp converts an RRSIG timestamp string to uint32.
// Supports both Unix timestamp format and DNSSEC timestamp format (YYYYMMDDHHmmss).
func parseRRSIGTimestamp(ts string) uint32 {
	if ts == "" {
		return 0
	}
	if val, err := strconv.ParseUint(ts, 10, 32); err == nil {
		if len(ts) <= 10 {
			return uint32(val)
		}
	}
	t, err := time.Parse("20060102150405", ts)
	if err != nil {
		return 0
	}
	return uint32(t.Unix())
}

// Parses a zone entity for the requested record type and query name (ie: www.domain.com)
func parseQueriedRecord(
	rr uint16,
	qname string,
	zone *entities.Zone) ([]dns.RR, error) {

	parserFunc, ok := recordParserFuncs[rr]
	if !ok {
		return nil, ErrRecordTypeNotSupported
	}
	return parserFunc(qname, zone), nil
}

// ParseDomainName parses a fully qualified domain name (FQDN) into
// its hostname, subdomains, root domain, and TLD. Any trailing dot
// in the FQDN is removed and each of the domain components are returned
// in their normalized form (ie: no trailing dots).
func ParseDomainName(fqdn string) (hostname, subdomains, rootDomain, tld string, err error) {

	// Normalize input (remove trailing dot if present)
	fqdn = strings.TrimSuffix(fqdn, ".")

	// Split the FQDN into labels
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", "", "", "", &MessageError{Msg: "invalid FQDN: must have at least a domain and TLD"}
	}

	// Get the root domain and TLD using the publicsuffix package
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return "", "", "", "", &WrappedError{Msg: "failed to parse domain", Err: err}
	}

	// Extract the TLD from the root domain
	tld, _ = publicsuffix.PublicSuffix(eTLDPlusOne)

	// Find the root domain
	rootDomain = eTLDPlusOne

	// Remove the root domain from the FQDN to extract subdomains and hostname
	// If fqdn and rootDomain are the same, remaining will be empty.
	if len(fqdn) == len(rootDomain) {
		return "", "", rootDomain, tld, nil
	}
	remaining := fqdn[:len(fqdn)-len(rootDomain)-1]

	// Split remaining into hostname and subdomains
	if idx := strings.LastIndex(remaining, "."); idx != -1 {
		hostname = remaining[:idx]
		subdomains = remaining[idx+1:]
	} else {
		hostname = remaining
		subdomains = ""
	}

	return hostname, subdomains, rootDomain, tld, nil
}

// Validates a DNS query string to ensure it's a RFC compliant domain name.
// Guards against injection attacks, invalid characters, and malformed inputs.
func validateQuery(query string) error {

	// Maximum domain name length per RFC 1035
	const maxDomainLength = 253

	// Normalize query: trim spaces and remove trailing dots (common in fully qualified domain names)
	query = strings.TrimSpace(strings.TrimSuffix(query, "."))

	// Check overall domain length
	if len(query) == 0 {
		return errors.New("DNS query is empty")
	}
	if len(query) > maxDomainLength {
		return errors.New("DNS query exceeds maximum domain length (253 characters)")
	}

	// Split the query into labels and validate each
	labels := strings.Split(query, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return errors.New("DNS query contains an empty label")
		}
		if len(label) > 63 {
			return errors.New("DNS query contains a label exceeding 63 characters")
		}
		matched := labelRegexp.MatchString(label)
		if !matched {
			return errors.New("DNS query contains an invalid label: " + label)
		}
	}

	// Ensure the query is not an IP address - not yet supported
	if isIPAddress(query) {
		return errors.New("DNS query must not be an IP address")
	}

	return nil
}

// isIPAddress checks if a given query is an IPv4 or IPv6 address.
func isIPAddress(query string) bool {
	// Simple check for IPv4 and IPv6 formats
	ipv4Regex := `^(\d{1,3}\.){3}\d{1,3}$`
	ipv6Regex := `^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`

	isIPv4, _ := regexp.MatchString(ipv4Regex, query)
	isIPv6, _ := regexp.MatchString(ipv6Regex, query)

	return isIPv4 || isIPv6
}
