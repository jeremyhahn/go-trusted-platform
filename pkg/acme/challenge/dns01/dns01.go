package dns01

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
)

var (
	DNSService *dns.Service

	ErrChallengeFailed          = errors.New("dns-01: challenge failed")
	ErrDNSServiceNotInitialized = errors.New("dns-01: DNS service not initialized")
)

// Verify checks if the dns-01 challenge is valid by querying the local DNS
// resolver for the expected key authorization in the _acme-challenge.<domain>
// TXT record.
// Implements acme.ChallengeVerifierFunc
func Verify(
	resolver *net.Resolver,
	ca ca.CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	if DNSService == nil {
		return ErrDNSServiceNotInitialized
	}

	sha := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(sha[:])

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	txtRecords, err := resolver.LookupTXT(ctx, fmt.Sprintf("_acme-challenge.%s", domain))
	if err != nil {
		return fmt.Errorf("failed to query DNS TXT records: %v", err)
	}

	for _, txt := range txtRecords {

		if txt == expected {

			// Retrieve the zone from the DNS service
			zone, err := DNSService.Zone(domain)
			if err != nil {
				return err
			}

			// Define the ACME TXT record for removeal
			name := fmt.Sprintf("_acme-challenge.%s", domain)

			// Remove the record from the zone
			zone.RemoveTXTRecord(name)

			// Save the zone to the datastore
			if err := DNSService.Save(zone); err != nil {
				return err
			}

			return nil
		}
	}

	return ErrChallengeFailed
}

// Setup adds the ACME DNS-01 challenge record to the provided
// DNS domain hosted by the embedded platform DNS server.
func Setup(challengeToken, authzValue string) error {

	if DNSService == nil {
		return ErrDNSServiceNotInitialized
	}

	// hostname, subdomain, domain, tld, err
	_, _, domain, _, err := dns.ParseDomainName(authzValue)
	if err != nil {
		return err
	}

	// Ensure authzValue ends with a dot
	if !strings.HasSuffix(authzValue, ".") {
		authzValue += "."
	}

	// Define the ACME TXT record
	name := fmt.Sprintf("_acme-challenge.%s", authzValue)
	ttl := 300
	txt := dns.NewTXTRecord(name, challengeToken, uint32(ttl))

	// Retrieve the zone from the DNS service
	zone, err := DNSService.Zone(domain)
	if err != nil {
		return err
	}

	// Add the record to the zone
	zone.AddTXTRecord(txt)

	// Save the zone to the datastore making the record
	// immediately available for resolution
	if err := DNSService.Save(zone); err != nil {
		return err
	}

	return nil
}
