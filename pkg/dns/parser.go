package dns

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Error for unsupported record types
var ErrRecordTypeNotSupported = errors.New("dns: record type not supported")

// RecordParserFunc defines a function type for parsing DNS records
type RecordParserFunc func(qname string, zone *entities.Zone) []dns.RR

// Record parser functions for each supported record type in a zone
var recordParserFuncs = map[uint16]RecordParserFunc{
	dns.TypeA: func(qname string, zone *entities.Zone) []dns.RR {
		parts := strings.Split(qname, ".")
		hostname := parts[0]
		if qname == zone.Name {
			hostname = "@"
		}
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.ARecords {
			if r.Name == hostname {
				recs = append(recs, &dns.A{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    r.TTL,
					},
					A: net.ParseIP(r.Value),
				})
			}
		}
		return recs
	},
	dns.TypeAAAA: func(qname string, zone *entities.Zone) []dns.RR {
		parts := strings.Split(qname, ".")
		hostname := parts[0]
		if qname == zone.Name {
			hostname = "@"
		}
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.AAAARecords {
			if r.Name == hostname {
				recs = append(recs, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    r.TTL,
					},
					AAAA: net.ParseIP(r.Value),
				})
			}
		}
		return recs
	},
	dns.TypeMX: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.MXRecords {
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
	dns.TypeSOA: func(qname string, zone *entities.Zone) []dns.RR {
		r := zone.RecordSet.SOARecord
		return []dns.RR{
			&dns.SOA{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    r.TTL,
				},
				Ns:      r.MName,
				Mbox:    r.RName,
				Serial:  r.Serial,
				Refresh: r.Refresh,
				Retry:   r.Retry,
				Expire:  r.Expire,
				Minttl:  r.MinimumTTL,
			},
		}
	},
	dns.TypeTXT: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.TXTRecords {
			if r.Name == qname {
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
		}
		return recs
	},
	dns.TypeSRV: func(qname string, zone *entities.Zone) []dns.RR {
		recs := make([]dns.RR, 0)
		for _, r := range zone.RecordSet.SRVRecords {
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
		return "", "", "", "", fmt.Errorf("invalid FQDN: must have at least a domain and TLD")
	}

	// Get the root domain and TLD using the publicsuffix package
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to parse domain: %w", err)
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

	// Domain label regex per RFC 1035: 1-63 characters, alphanumeric or hyphen, no leading or trailing hyphens
	const labelRegex = `^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`

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
		matched, err := regexp.MatchString(labelRegex, label)
		if err != nil || !matched {
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
