package dns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"

	_ "github.com/coredns/coredns/plugin/chaos"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/log"
)

var (
	ErrZoneAlreadyExists            = errors.New("zone already exists")
	ErrParsingDomainName            = errors.New("failed to parse FQDN or domain name")
	ErrInvalidIPAddress             = errors.New("invalid IP address")
	ErrZoneNotFound                 = errors.New("zone not found")
	ErrInvalidPrivateIP             = errors.New("invalid private IP address")
	ErrInvalidPublicIP              = errors.New("invalid public IP address")
	ErrInvalidPrivateTLD            = errors.New("invalid private TLD")
	ErrInvalidPublicTLD             = errors.New("invalid public TLD")
	ErrRegistrationDisabled         = errors.New("zone registration is disallowed")
	ErrExternalRegistrationDisabled = errors.New("external zone registration disallowed")
	ErrInternalRegistrationDisabled = errors.New("internal zone registration disallowed")
)

type Params struct {
	AppName     string
	AppVersion  string
	Config      *Config
	PublicIPv4  net.IP
	PrivateIPv4 net.IP
	PublicIPv6  net.IP
	PrivateIPv6 net.IP
	Datastore   *Datastore
}

// DNSService handles zone and record operations.
type Service struct {
	consistencyLevel datastore.ConsistencyLevel
	params           *Params
	zoneDAO          dao.ZoneDAO
}

// NewService creates a new DNSService instance.
func NewService(params *Params) (*Service, error) {
	zoneDAO, err := params.Datastore.ZoneDAO()
	if err != nil {
		return nil, fmt.Errorf("failed to get zone DAO: %w", err)
	}
	return &Service{
		consistencyLevel: datastore.ParseConsistentLevel(params.Config.Datastore.ConsistencyLevel),
		params:           params,
		zoneDAO:          zoneDAO,
	}, nil
}

// Save saves a zone to the datastore.
func (s *Service) Save(zone *entities.Zone) error {
	if err := s.zoneDAO.Save(zone); err != nil {
		return fmt.Errorf("failed to save zone: %w", err)
	}
	return nil
}

// Delete deletes a zone from the datastore.
func (s *Service) Delete(zone *entities.Zone) error {
	if err := s.zoneDAO.Delete(zone); err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}
	return nil
}

// Zone retrieves a zone from the datastore.
func (s *Service) Zone(zoneName string) (*entities.Zone, error) {

	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	id := util.NewID([]byte(zoneName))
	consistencyLevel := datastore.ParseConsistentLevel(s.params.Config.Datastore.ConsistencyLevel)

	zone, err := s.zoneDAO.Get(id, consistencyLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone: %w", err)
	}
	return zone, nil
}

func (s *Service) InternalDomain() string {
	return s.params.Config.InternalServer.Zone.Name
}

func (s *Service) PublicDomain() string {
	return s.params.Config.PublicServer.Zone.Name
}

func (s *Service) InternalZone() (*entities.Zone, error) {
	return s.Zone(s.params.Config.InternalServer.Zone.Name)
}

func (s *Service) PublicZone() (*entities.Zone, error) {
	return s.Zone(s.params.Config.PublicServer.Zone.Name)
}

// Returns a new net.Resolver instance that uses the internal DNS server. The
// internal DNS service allows queries for both internal and public zones and
// forwards unknown queries to the forwarders specified in the platform
// configuration.
func (s *Service) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dnsServer := fmt.Sprintf(":%d", s.params.Config.InternalServer.Port)
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, network, dnsServer)
		},
	}
}

// Register creates a new DNS record or zone based on the provided FQDN
// and platform configuration. If the the FQDN does not match the DNS
// server's public or private zone, and the platform configuration permits,
// a new zone will be created with an initial A record so the host is
// resolvable. If the FQDN matches the DNS server's public or private
// zone, a new A record will be added to the existing zone for the host.
// If the provided IP address belongs to a private subnet, the record will
// be created as an internal zone, otherwise it will be created as a public
// zone.
func (s *Service) Register(fqdn, ip string) (*entities.Zone, error) {

	// Ensure DNS registrations are allowed
	if !s.params.Config.AllowRegistration {
		return nil, ErrRegistrationDisabled
	}

	// Normalize the FQDN
	fqdn = strings.ToLower(fqdn)

	// Ensure the IP address is valid
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, ErrInvalidIPAddress
	}

	// Parse the domain name into it's components
	hostname, subdomains, rootDomain, tld, err := ParseDomainName(fqdn)
	if err != nil {
		s.params.Config.Logger.Error(err)
		return nil, ErrParsingDomainName
	}

	var regDomain string
	if subdomains != "" {
		regDomain = fmt.Sprintf("%s.%s", subdomains, rootDomain)
	} else {
		regDomain = rootDomain
	}

	// Build a "zone name" which is the FQDN with a dot suffix
	if !strings.HasSuffix(regDomain, ".") {
		regDomain = fmt.Sprintf("%s.", strings.ToLower(regDomain))
	}

	// Ensure internal FQDNs meet criteria for an internal zone
	if regDomain == s.params.Config.InternalServer.Zone.Name {
		if !util.IsPrivateSubnet(parsedIP) {
			return nil, ErrInvalidPrivateIP
		}
		if IsTLD(tld) {
			return nil, ErrInvalidPrivateTLD
		}
		return s.register(hostname, subdomains, rootDomain, tld, parsedIP.String())
	}

	// Ensure public FQDNs meet criteria for a public zone
	if regDomain == s.params.Config.PublicServer.Zone.Name {
		if util.IsPrivateSubnet(parsedIP) {
			return nil, ErrInvalidPublicIP
		}
		if !IsTLD(tld) {
			return nil, ErrInvalidPublicTLD
		}
		return s.register(hostname, subdomains, rootDomain, tld, parsedIP.String())
	}

	// This FQDN doesn't match any of the server's zones.

	// Ensure registrations are enabled for the request type
	if IsTLD(tld) {
		if !s.params.Config.AllowExternalRegistration {
			return nil, ErrExternalRegistrationDisabled
		}
	} else {
		if !s.params.Config.AllowInternalRegistration {
			return nil, ErrInternalRegistrationDisabled
		}
	}

	// Ensure the zone doesn't already exist
	id := util.NewID([]byte(rootDomain))
	if _, err = s.zoneDAO.Get(id, s.consistencyLevel); err == nil {
		return nil, ErrZoneAlreadyExists
	}

	// Meets all checks - perform registration
	return s.register(hostname, subdomains, rootDomain, tld, parsedIP.String())
}

// Registers a new DNS record or zone based on the provided domain components
// with the platform DNS service.
func (s *Service) register(
	hostname, subdomains, rootDomain, tld, ip string) (*entities.Zone, error) {

	var zone *entities.Zone
	var zoneName string
	var err error

	if subdomains == "" {
		zoneName = fmt.Sprintf("%s.", rootDomain)
	} else {
		zoneName = fmt.Sprintf("%s.%s.", subdomains, rootDomain)
	}
	id := util.NewID([]byte(zoneName))

	if zoneName == s.params.Config.InternalServer.Zone.Name ||
		zoneName == s.params.Config.PublicServer.Zone.Name {

		// Zone matches the internal or public server zone -
		// add a new record to the existing zone
		zone, err = s.zoneDAO.Get(id, s.consistencyLevel)
		if err != nil {
			return nil, ErrZoneNotFound
		}

		zone.AddARecord(&entities.ARecord{
			Name:  hostname,
			Value: ip,
			TTL:   3600})

	} else {

		// No way to check if a user owns a previous domain at this point
		// in the project's maturity. TODO ...
		zone, err := s.zoneDAO.Get(id, s.consistencyLevel)
		if err == nil && zone != nil {
			return nil, ErrZoneAlreadyExists
		}

		// Create new zone file with a minimal set of records
		zone = &entities.Zone{
			ID:          id,
			Name:        zoneName,
			TTL:         3600,
			Internal:    true,
			Description: fmt.Sprintf("Registered device %s.%s", hostname, zoneName),
			RecordSet: entities.RecordSet{
				SOARecord: entities.SOARecord{
					Name:       zoneName,
					MName:      fmt.Sprintf("ns1.%s", zoneName),
					RName:      fmt.Sprintf("hostmaster.%s", zoneName),
					Serial:     1,
					Refresh:    86400,
					Retry:      7200,
					Expire:     86400,
					MinimumTTL: 3600,
					TTL:        3600,
				},
				ARecords: []*entities.ARecord{
					{
						Name:  "@",
						Value: ip,
						TTL:   3600,
					},
					{
						Name:  "ns1",
						Value: ip,
						TTL:   3600,
					},
					{
						Name:  hostname,
						Value: ip,
						TTL:   3600,
					},
				},
				NSRecords: []*entities.NSRecord{
					{
						Name:  "ns1",
						Value: fmt.Sprintf("ns1.%s", zoneName),
						TTL:   3600,
					},
				},
			},
		}
	}

	// Save the zone to the datastore
	if err := s.zoneDAO.Save(zone); err != nil {
		return nil, fmt.Errorf("failed to save zone: %w", err)
	}

	return nil, nil
}

func Run(
	appName, appVersion string,
	logger *logging.Logger,
	config *Config) {

	// Set the global DNS configuration, needed by the
	// CoreDNS plugin
	Configuration = config

	// Stores the dynamically created CoreDNS Corefile
	var corefile string

	if config.InternalServer != nil {
		// Create internal DNS server using values specified in
		// the platform configuration file
		corefile = fmt.Sprintf(`
.:%d {
	trustedPlatform
	log
	chaos
	forward . %s
}
`, config.InternalServer.Port,
			strings.Join(config.InternalServer.Forwarders, " "))
	}

	if config.PublicServer.Port > 0 {
		// Create public DNS server using values specified in
		// the platform configuration file
		corefile += fmt.Sprintf(`
.:%d {
	trustedPlatform
	log
	chaos
	forward . %s
}`, config.PublicServer.Port,
			strings.Join(config.PublicServer.Forwarders, " "))
	}

	logger.Debug("DNS server configuration",
		slog.String("corefile", corefile))

	os.Args = []string{"coredns"}

	// Define the CHAOS name and version directives
	name := appName
	version := appVersion
	if name == "" {
		name = "TrustedPlatform"
	}
	if version == "" {
		version = "debug"
	}
	caddy.AppName = name
	caddy.AppVersion = version

	// Register the dynamic Caddyfile loader
	caddy.RegisterCaddyfileLoader("dynamic", caddy.LoaderFunc(func(serverType string) (caddy.Input, error) {
		return &caddy.CaddyfileInput{
			Contents:       []byte(corefile),
			Filepath:       "dynamic",
			ServerTypeName: serverType,
		}, nil
	}))

	// Register CoreDNS plugins
	dnsserver.Directives = []string{
		"trustedPlatform",
		"log",
		"chaos",
		"forward",
	}

	// Start your engines
	go coremain.Run()
}

// NewARecord creates a new A record.
func NewARecord(
	name, value string, ttl uint32) *entities.ARecord {

	return &entities.ARecord{
		Name:  name,
		Value: value,
		TTL:   ttl,
	}
}

// NewAAAARecord creates a new AAAA record.
func NewAAAARecord(
	name, value string, ttl uint32) *entities.AAAARecord {

	return &entities.AAAARecord{
		Name:  name,
		Value: value,
		TTL:   ttl,
	}
}

// NewCNAMERecord creates a new CNAME record.
func NewCNAMERecord(
	name, target string, ttl uint32) *entities.CNAMERecord {

	return &entities.CNAMERecord{
		Name:  name,
		Value: target,
		TTL:   ttl,
	}
}

// NewDNSKEYRecord creates a new DNSKEY record.
func NewDNSKEYRecord(
	name, key string,
	flags uint16,
	protocol, algorithm uint8,
	ttl uint32) *entities.DNSKEYRecord {

	return &entities.DNSKEYRecord{
		Name:      name,
		Key:       key,
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		TTL:       ttl,
	}
}

// NewDSRecord creates a new DS record.
func NewDSRecord(
	name string,
	keyTag uint16,
	algorithm, digestType uint8,
	digest string, ttl uint32) *entities.DSRecord {

	return &entities.DSRecord{
		Name:       name,
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     digest,
		TTL:        ttl,
	}
}

// NewMXRecord creates a new MX record.
func NewMXRecord(
	name, value string,
	priority uint16,
	ttl uint32) *entities.MXRecord {

	return &entities.MXRecord{
		Name:     name,
		Value:    value,
		Priority: priority,
		TTL:      ttl,
	}
}

// NewNSRecord creates a new NS record.
func NewNSRecord(
	name, value string,
	ttl uint32) *entities.NSRecord {

	return &entities.NSRecord{
		Name:  name,
		Value: value,
		TTL:   ttl,
	}
}

// NewRRSIGRecord creates a new signed RRset
func NewRRSIGRecord(
	name, typeCovered string,
	algorithm, labels uint8,
	originalTTL uint32,
	expiration, inception string,
	keyTag uint16, signerName,
	signature string) *entities.RRSIGRecord {

	return &entities.RRSIGRecord{
		SignerName:  signerName,
		Signature:   signature,
		Labels:      labels,
		Algorithm:   algorithm,
		OriginalTTL: originalTTL,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		TypeCovered: typeCovered}
}

// NewSOARecord creates a new SOA record.
func NewSOARecord(
	name, mname, rname string,
	serial, refresh, retry, expire, minimumTTL, ttl uint32) *entities.SOARecord {

	return &entities.SOARecord{
		Name:       name,
		MName:      mname,
		RName:      rname,
		Serial:     serial,
		Refresh:    refresh,
		Retry:      retry,
		Expire:     expire,
		MinimumTTL: minimumTTL,
		TTL:        ttl,
	}
}

// NewSRVRecord creates a new SRV record.
func NewSRVRecord(
	name, target string,
	port, priority, weight uint16,
	ttl uint32) *entities.SRVRecord {

	return &entities.SRVRecord{
		Name:     name,
		Target:   target,
		Port:     port,
		Priority: priority,
		Weight:   weight,
		TTL:      ttl,
	}
}

// NewTXTRecord creates a new TXT record.
func NewTXTRecord(
	name, value string, ttl uint32) *entities.TXTRecord {

	return &entities.TXTRecord{
		Name:  name,
		Value: value,
		TTL:   ttl,
	}
}
