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
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/miekg/dns"

	_ "github.com/coredns/coredns/plugin/chaos"
	_ "github.com/coredns/coredns/plugin/dns64"
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
	ErrDNSSECNotEnabled             = errors.New("DNSSEC is not enabled")
	ErrDNSNotRunning                = errors.New("DNS server is not running")
	ErrMissingTenantContext         = errors.New("missing tenant context")
	ErrUnauthorizedZoneAccess       = errors.New("unauthorized: caller tenant does not own this zone")
	ErrInvalidRecordValue           = errors.New("dns: invalid record value")
	ErrRecordNotFound               = errors.New("dns: record not found")
	ErrInvalidTTL                   = errors.New("dns: TTL must be 0 to 2147483647 (RFC 2181 §8)")
	ErrCNOutsideZones               = errors.New("dns: CN does not match any configured zone")

	// caddyInstance holds the running Caddy/CoreDNS instance for shutdown
	caddyInstance *caddy.Instance
)

// Params holds all dependencies required to create a DNS Service.
type Params struct {
	AppName        string
	AppVersion     string
	Config         *Config
	TenantID       string // Platform's tenant ID for zone authorization
	PublicIPv4     net.IP
	PrivateIPv4    net.IP
	PublicIPv6     net.IP
	PrivateIPv6    net.IP
	Datastore      *Datastore
	XKMSAdapter    *xkmsadapter.Adapter // Deprecated: Use DNSSECKeyStore instead
	DNSSECKeyStore DNSSECKeyStore       // DNSSEC key store (XKMS or QuicBaaS KMS)
	// NetworkZones is the resolved list of network zone names sourced from
	// sdn.Config.ResolvedZones(). When Config.ZoneSubdomains is true, the
	// service uses this list to pre-create per-zone sub-zones under the
	// internal domain at startup. Must not be nil when ZoneSubdomains is true;
	// ignored otherwise.
	NetworkZones []string
}

// DNSService handles zone and record operations.
type Service struct {
	params    *Params
	zoneDAO   dao.ZoneDAO
	dnssecSvc *DNSSECService
}

// NewService creates a new DNSService instance.
// If DNSSEC is enabled, XKMS adapter is required for key management.
func NewService(params *Params) (*Service, error) {
	zoneDAO, err := params.Datastore.ZoneDAO()
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get zone DAO", Err: err}
	}

	svc := &Service{
		params:  params,
		zoneDAO: zoneDAO,
	}

	// Initialize DNSSEC service if enabled
	if params.Config.DNSSEC != nil && params.Config.DNSSEC.Enabled {
		var keyStore DNSSECKeyStore

		// Prefer DNSSECKeyStore if set, otherwise fall back to XKMSAdapter for backward compatibility
		switch {
		case params.DNSSECKeyStore != nil:
			keyStore = params.DNSSECKeyStore
		case params.XKMSAdapter != nil:
			// Backward compatibility: wrap XKMSAdapter in XKMSKeyStore
			var err error
			keyStore, err = NewXKMSKeyStore(params.XKMSAdapter)
			if err != nil {
				return nil, &WrappedError{Msg: "failed to create XKMS key store", Err: err}
			}
		default:
			return nil, &WrappedError{Msg: "DNSSEC is enabled but no key store is configured (DNSSECKeyStore or XKMSAdapter required)", Err: ErrKeyStoreNil}
		}

		dnssecSvc, err := NewDNSSECServiceWithKeyStore(params.Config.DNSSEC, params.Config.Logger, keyStore)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create DNSSEC service", Err: err}
		}
		svc.dnssecSvc = dnssecSvc

		// CRITICAL: also publish the keystore into the plugin-level
		// global so signZoneIfEnabled (which runs during CoreDNS
		// zone loading, before any Service method is called) can
		// see it. Without this, zone loading fails with
		// "DNSSEC enabled ... but no key store and no XKMS adapter
		// are configured" even though the service has one.
		//
		// Observed on node-02 2026-04-08: DNSSEC service was
		// created correctly here, but the plugin's package-level
		// KeyStore var remained nil, so every example.com/
		// example.internal zone load hard-failed and the DNS
		// server never started.
		//
		// SetDNSSECKeyStore also calls SignUnsignedZones for any
		// previously-loaded zones; at this point there are none
		// so that path is a no-op.
		if err := SetDNSSECKeyStore(keyStore); err != nil {
			// Deliberately non-fatal: SignUnsignedZones may
			// report errors for unrelated pre-existing zones,
			// but the global is set regardless. Log and continue.
			if params.Config.Logger != nil {
				params.Config.Logger.Warn("SetDNSSECKeyStore returned an error on startup",
					"error", err)
			}
		}
	}

	return svc, nil
}

// TenantID returns the service's tenant ID for zone authorization.
func (s *Service) TenantID() string {
	return s.params.TenantID
}

// authorizeZoneAccess checks if the caller's tenant owns the zone.
// Returns nil if authorized, ErrMissingTenantContext if no tenant context,
// or ErrUnauthorizedZoneAccess if the caller doesn't own the zone.
func (s *Service) authorizeZoneAccess(zone *entities.Zone, action string) error {
	if s.params.TenantID == "" {
		return ErrMissingTenantContext
	}
	if !zone.IsOwnedBy(s.params.TenantID) {
		s.params.Config.Logger.Warn("unauthorized zone access",
			slog.String("caller_tenant", s.params.TenantID),
			slog.String("zone_tenant", zone.TenantID),
			slog.String("zone", zone.Name),
			slog.String("action", action))
		return ErrUnauthorizedZoneAccess
	}
	return nil
}

// ensureZoneTenantID ensures the zone has a TenantID set.
// If the zone's TenantID is empty, it is set to the service's TenantID.
func (s *Service) ensureZoneTenantID(zone *entities.Zone) error {
	if zone.TenantID == "" {
		if s.params.TenantID == "" {
			return ErrMissingTenantContext
		}
		zone.TenantID = s.params.TenantID
	}
	return nil
}

// Save saves a zone to the datastore. If DNSSEC is enabled, the zone is
// automatically signed before saving. Authorization is checked to ensure
// the caller owns the zone.
func (s *Service) Save(ctx context.Context, zone *entities.Zone) error {
	// Ensure zone has TenantID
	if err := s.ensureZoneTenantID(zone); err != nil {
		return err
	}

	// Authorize access to the zone
	if err := s.authorizeZoneAccess(zone, "save"); err != nil {
		return err
	}

	// Stamp a deterministic, name-derived ID so subsequent
	// `Zone(ctx, name)` lookups can find the zone by hash. Without this
	// the DAO assigned an auto-incrementing/timestamp ID at save time
	// and `util.NewID(name)`-based reads always 404'd.
	if zone.ID == 0 {
		name := zone.Name
		if !strings.HasSuffix(name, ".") {
			name += "."
		}
		zone.ID = util.NewID([]byte(name))
	}

	// Sign the zone if DNSSEC is enabled
	if s.dnssecSvc != nil && s.dnssecSvc.IsEnabled() {
		if err := s.dnssecSvc.SignZone(zone); err != nil {
			return &WrappedError{Msg: "failed to sign zone", Err: err}
		}
	}

	if err := s.zoneDAO.Save(ctx, zone); err != nil {
		return &WrappedError{Msg: "failed to save zone", Err: err}
	}
	return nil
}

// SaveAndSign saves a zone to the datastore after signing it with DNSSEC if enabled.
// If DNSSEC is not enabled, the zone is saved without signing. Authorization is
// checked to ensure the caller owns the zone.
func (s *Service) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	// Ensure zone has TenantID
	if err := s.ensureZoneTenantID(zone); err != nil {
		return err
	}

	// Authorize access to the zone
	if err := s.authorizeZoneAccess(zone, "save_and_sign"); err != nil {
		return err
	}

	// Sign the zone if DNSSEC is enabled
	if s.dnssecSvc != nil && s.dnssecSvc.IsEnabled() {
		if err := s.dnssecSvc.SignZone(zone); err != nil {
			return &WrappedError{Msg: "failed to sign zone", Err: err}
		}
	}

	if err := s.zoneDAO.Save(ctx, zone); err != nil {
		return &WrappedError{Msg: "failed to save zone", Err: err}
	}
	return nil
}

// SignZone signs a zone with DNSSEC. Returns an error if DNSSEC is not enabled.
// Authorization is checked to ensure the caller owns the zone.
func (s *Service) SignZone(zone *entities.Zone) error {
	if s.dnssecSvc == nil {
		return ErrDNSSECNotEnabled
	}

	// Authorize access to the zone - must be owner to sign
	if err := s.authorizeZoneAccess(zone, "sign"); err != nil {
		return err
	}

	return s.dnssecSvc.SignZone(zone)
}

// DNSSECService returns the DNSSEC service if configured, nil otherwise.
func (s *Service) DNSSECService() *DNSSECService {
	return s.dnssecSvc
}

// Delete deletes a zone from the datastore. Authorization is checked to ensure
// the caller owns the zone.
func (s *Service) Delete(ctx context.Context, zone *entities.Zone) error {
	// Authorize access to the zone - must be owner to delete
	if err := s.authorizeZoneAccess(zone, "delete"); err != nil {
		return err
	}

	if err := s.zoneDAO.Delete(ctx, zone); err != nil {
		return &WrappedError{Msg: "failed to delete zone", Err: err}
	}
	return nil
}

// Zone retrieves a zone from the datastore.
// Authorization is checked to ensure the caller owns the zone.
func (s *Service) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {

	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	id := util.NewID([]byte(zoneName))

	zone, err := s.zoneDAO.Get(ctx, id)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to get zone", Err: err}
	}

	// Check authorization - caller must own the zone
	if err := s.authorizeZoneAccess(zone, "get"); err != nil {
		return nil, err
	}

	return zone, nil
}

// InternalDomain returns the internal server's zone name, or "" when no
// internal server is configured.
func (s *Service) InternalDomain() string {
	if s.params.Config.InternalServer == nil {
		return ""
	}
	return s.params.Config.InternalServer.Zone.Name
}

// PublicDomain returns the public server's zone name, or "" when no public
// server is configured.
func (s *Service) PublicDomain() string {
	if s.params.Config.PublicServer == nil {
		return ""
	}
	return s.params.Config.PublicServer.Zone.Name
}

func (s *Service) InternalZone(ctx context.Context) (*entities.Zone, error) {
	return s.Zone(ctx, s.params.Config.InternalServer.Zone.Name)
}

func (s *Service) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return s.Zone(ctx, s.params.Config.PublicServer.Zone.Name)
}

// Resolver returns a net.Resolver that queries the platform DNS infrastructure.
// Resolver prefers the unified dns.resolver config when available, falling back
// to the internal DNS server port for backward compatibility.
func (s *Service) Resolver() *net.Resolver {
	// Prefer unified resolver config
	if s.params.Config.Resolver != nil {
		if resolver := s.params.Config.Resolver.NetResolver(); resolver != nil {
			return resolver
		}
	}
	// Fall back to internal server port (existing behavior)
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
func (s *Service) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {

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

	// Normalize FQDN for suffix matching (ensure trailing dot)
	normalizedFQDN := strings.ToLower(fqdn)
	if !strings.HasSuffix(normalizedFQDN, ".") {
		normalizedFQDN += "."
	}

	// Check if FQDN belongs to internal zone using suffix matching.
	// This handles private TLDs like .internal, .local, .home.arpa which
	// publicsuffix doesn't recognize as multi-part suffixes.
	if s.params.Config.InternalServer != nil &&
		strings.HasSuffix(normalizedFQDN, s.params.Config.InternalServer.Zone.Name) {
		if !util.IsPrivateSubnet(parsedIP) {
			return nil, ErrInvalidPrivateIP
		}
		if IsTLD(tld) {
			return nil, ErrInvalidPrivateTLD
		}
		return s.register(ctx, hostname, subdomains, rootDomain, tld, parsedIP.String())
	}

	// Check if FQDN belongs to public zone using suffix matching
	if s.params.Config.PublicServer != nil &&
		strings.HasSuffix(normalizedFQDN, s.params.Config.PublicServer.Zone.Name) {
		if util.IsPrivateSubnet(parsedIP) {
			return nil, ErrInvalidPublicIP
		}
		if !IsTLD(tld) {
			return nil, ErrInvalidPublicTLD
		}
		return s.register(ctx, hostname, subdomains, rootDomain, tld, parsedIP.String())
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
	if _, err = s.zoneDAO.Get(ctx, id); err == nil {
		return nil, ErrZoneAlreadyExists
	}

	// Meets all checks - perform registration
	return s.register(ctx, hostname, subdomains, rootDomain, tld, parsedIP.String())
}

// Registers a new DNS record or zone based on the provided domain components
// with the platform DNS service.
func (s *Service) register(
	ctx context.Context, hostname, subdomains, rootDomain, tld, ip string) (*entities.Zone, error) {

	var zone *entities.Zone
	var zoneName string
	var err error

	if subdomains == "" {
		zoneName = fmt.Sprintf("%s.", rootDomain)
	} else {
		zoneName = fmt.Sprintf("%s.%s.", subdomains, rootDomain)
	}
	id := util.NewID([]byte(zoneName))

	// Check if zoneName matches one of the server's configured zones
	matchesInternalZone := s.params.Config.InternalServer != nil &&
		zoneName == s.params.Config.InternalServer.Zone.Name
	matchesPublicZone := s.params.Config.PublicServer != nil &&
		zoneName == s.params.Config.PublicServer.Zone.Name

	if matchesInternalZone || matchesPublicZone {

		// Zone matches the internal or public server zone -
		// add a new record to the existing zone
		zone, err = s.zoneDAO.Get(ctx, id)
		if err != nil {
			return nil, ErrZoneNotFound
		}

		zone.AddARecord(&entities.ARecord{
			Name:  hostname,
			Value: ip,
			TTL:   s.params.Config.RecordTTL()})

	} else {

		// DEFERRED: Domain ownership verification not yet implemented. Blocked by: IAM domain ownership model.
		existingZone, err := s.zoneDAO.Get(ctx, id)
		if err == nil && existingZone != nil {
			return nil, ErrZoneAlreadyExists
		}

		// Create new zone file with a minimal set of records
		zone = &entities.Zone{
			ID:          id,
			Name:        zoneName,
			TenantID:    s.params.TenantID,
			TTL:         s.params.Config.RecordTTL(),
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
					TTL:        s.params.Config.RecordTTL(),
				},
				ARecords: []*entities.ARecord{
					{
						Name:  "@",
						Value: ip,
						TTL:   s.params.Config.RecordTTL(),
					},
					{
						Name:  "ns1",
						Value: ip,
						TTL:   s.params.Config.RecordTTL(),
					},
					{
						Name:  hostname,
						Value: ip,
						TTL:   s.params.Config.RecordTTL(),
					},
				},
				NSRecords: []*entities.NSRecord{
					{
						Name:  "ns1",
						Value: fmt.Sprintf("ns1.%s", zoneName),
						TTL:   s.params.Config.RecordTTL(),
					},
				},
			},
		}
	}

	// Save the zone to the datastore
	if err := s.zoneDAO.Save(ctx, zone); err != nil {
		return nil, &WrappedError{Msg: "failed to save zone", Err: err}
	}

	return nil, nil
}

// RegisterWithNetworkZone registers a device hostname under its network zone
// subdomain when zone_subdomains is enabled. The zone-qualified FQDN is
// <host>.<networkZone>.<domain> and is registered IN ADDITION to the standard
// <host>.<domain> registration. When zone_subdomains is disabled or networkZone
// is empty the method returns nil without registering any extra record.
//
// BMC names (host labels ending in "-bmc") are never zone-qualified; this
// method returns nil immediately for such hosts regardless of other flags.
//
// The sub-zone <networkZone>.<domain> must have been pre-created by
// InitNetworkZoneSubdomains before this method is called; if the sub-zone does
// not exist, the registration is skipped and nil is returned (best-effort).
func (s *Service) RegisterWithNetworkZone(
	ctx context.Context,
	host, networkZone, ip string,
) error {
	if !s.params.Config.ZoneSubdomains {
		return nil
	}
	if networkZone == "" {
		return nil
	}
	if IsBMCName(host) {
		return nil
	}
	if s.params.Config.InternalServer == nil {
		return nil
	}

	internalDomain := strings.TrimSuffix(s.params.Config.InternalServer.Zone.Name, ".")
	subZoneName := fmt.Sprintf("%s.%s.", networkZone, internalDomain)
	id := util.NewID([]byte(subZoneName))

	subZone, err := s.zoneDAO.Get(ctx, id)
	if isNotFoundError(err) {
		// Sub-zone not pre-created: skip best-effort.
		return nil
	}
	if err != nil {
		return &ZoneError{Op: "get", Zone: subZoneName, Err: err}
	}

	// Ensure TenantID so Save does not reject the zone.
	if subZone.TenantID == "" {
		subZone.TenantID = s.params.TenantID
	}

	// Idempotent: skip if the A record already exists with the same value.
	for _, r := range subZone.RecordSet.ARecords {
		if r.Name == host && r.Value == ip {
			return nil
		}
	}

	subZone.AddARecord(&entities.ARecord{
		Name:  host,
		Value: ip,
		TTL:   s.params.Config.RecordTTL(),
	})

	if err := s.zoneDAO.Save(ctx, subZone); err != nil {
		return &RecordError{Op: "save", Type: "A", Name: host + "." + subZoneName, Err: err}
	}

	return nil
}

func Run(
	appName, appVersion string,
	logger *logging.Logger,
	config *Config) error {

	// Refuse a configuration this process cannot honour BEFORE anything is
	// started or registered. Under FIPS activation NSEC3 cannot be produced at
	// all, and a daemon that comes up with zones it will silently fail to sign
	// is the outcome this prevents (#249). Likewise a DNS64 prefix no RFC 6052
	// translator can reverse synthesises addresses that route to nothing, and
	// a resolver section with no usable server leaves every lookup failing.
	if err := config.Validate(); err != nil {
		return err
	}

	// Set the logger on the config before setting the global Configuration
	// so that the CoreDNS plugin has access to it for DNSSEC signing
	config.Logger = logger

	// Set the global DNS configuration, needed by the
	// CoreDNS plugin
	Configuration = config

	// Stores the dynamically created CoreDNS Corefile
	var corefile string

	// Create internal Corefile
	if config.InternalServer != nil {
		corefile = NewCorefileForServer(DNS64ServerInternal,
			config.InternalServer.Port, config.InternalServer.Forwarders, config.DNS64)
	}

	// Create public Corefile
	if config.PublicServer != nil && config.PublicServer.Port > 0 {
		corefile += NewCorefileForServer(DNS64ServerPublic,
			config.PublicServer.Port, config.PublicServer.Forwarders, config.DNS64)
	}

	logger.Debug("DNS server configuration",
		slog.String("corefile", corefile))

	fmt.Println(corefile)

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
	// dns64 is ordered ahead of trustedPlatform, not after it. The plugin
	// works by letting the rest of the chain answer an AAAA question and
	// synthesising only when that answer carried no AAAA, so it has to wrap
	// the authoritative plugin rather than sit behind it. Ordering it after
	// trustedPlatform would leave it nothing to intercept for the platform's
	// own zones — and would break RFC 7050 discovery outright, since the
	// ipv4only.arpa answer it synthesises from is served by trustedPlatform.
	// Everything that is not an AAAA question passes straight through.
	dnsserver.Directives = []string{
		"dns64",
		"trustedPlatform",
		"log",
		"chaos",
		"forward",
	}

	// Build Caddy input from the corefile
	caddyInput := caddy.CaddyfileInput{
		Contents:       []byte(corefile),
		Filepath:       "dynamic",
		ServerTypeName: "dns",
	}

	// Start the DNS server and capture the instance for later shutdown
	go func() {
		instance, err := caddy.Start(caddyInput)
		if err != nil {
			logger.Error(&WrappedError{Msg: "failed to start DNS server", Err: err})
			return
		}
		caddyInstance = instance
		// Wait for the instance to finish (blocks until Stop() is called)
		instance.Wait()
	}()

	return nil
}

// Stop gracefully shuts down the DNS server
func Stop() error {
	if caddyInstance == nil {
		return ErrDNSNotRunning
	}
	err := caddyInstance.Stop()
	caddyInstance = nil
	return err
}

// IsRunning returns true if the DNS server is running
func IsRunning() bool {
	return caddyInstance != nil
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
		Name:        name,
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

// NewCAARecord creates a new CAA record for certificate authority authorization.
// The flags parameter is typically 0 (non-critical) or 128 (critical).
// The tag parameter is one of: "issue", "issuewild", or "iodef".
// The value parameter is the CA domain name or reporting URI.
func NewCAARecord(
	name string, flags uint8, tag, value string, ttl uint32) *entities.CAARecord {

	return &entities.CAARecord{
		Name:  name,
		Flags: flags,
		Tag:   tag,
		Value: value,
		TTL:   ttl,
	}
}

// NewTLSARecord creates a new TLSA record for DANE certificate pinning.
// Usage: 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE (recommended)
// Selector: 0=Full certificate, 1=SubjectPublicKeyInfo (recommended)
// MatchingType: 0=Full, 1=SHA-256 (recommended), 2=SHA-512
// Data: The certificate association data (hash or full certificate).
func NewTLSARecord(
	name string, usage, selector, matchingType uint8, data string, ttl uint32) *entities.TLSARecord {

	return &entities.TLSARecord{
		Name:         name,
		Usage:        usage,
		Selector:     selector,
		MatchingType: matchingType,
		Data:         data,
		TTL:          ttl,
	}
}

// AddTLSARecord adds a TLSA record to the specified DNS zone. The zone is
// retrieved, the record is added, and the zone is saved with DNSSEC signing.
// This method is used by the DANE auto-generation hook during certificate
// issuance to create TLSA records for DANE certificate pinning.
// Zones with empty tenant IDs are automatically claimed by the caller's tenant.
func (s *Service) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	if !strings.HasSuffix(zoneName, ".") {
		zoneName += "."
	}

	id := util.NewID([]byte(zoneName))

	zone, err := s.zoneDAO.Get(ctx, id)
	if err != nil {
		return &ZoneError{Op: "get", Zone: zoneName, Err: err}
	}

	// Ensure zone has a tenant ID — zones created during initial DNS startup
	// may have empty tenant IDs that need to be claimed by the platform tenant.
	if err := s.ensureZoneTenantID(zone); err != nil {
		return &ZoneError{Op: "set the tenant of", Zone: zoneName, Err: err}
	}

	zone.AddTLSARecord(record)

	if err := s.SaveAndSign(ctx, zone); err != nil {
		return &RecordError{Op: "save", Type: "TLSA", Name: record.Name, Err: err}
	}

	return nil
}

// ListZones retrieves all zones owned by the caller's tenant from the datastore.
// Multi-tenancy: Only zones where TenantID matches the caller's tenant are returned.
func (s *Service) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if s.params.TenantID == "" {
		return nil, ErrMissingTenantContext
	}

	var zones []*entities.Zone

	query := datastore.PageQuery{
		PageSize:  100,
		SortOrder: datastore.SortAscending,
	}

	err := s.zoneDAO.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
		// Filter zones by tenant - only include zones owned by caller's tenant
		for _, zone := range result.Entities {
			if zone.IsOwnedBy(s.params.TenantID) {
				zones = append(zones, zone)
			}
		}
		return nil
	})
	if err != nil {
		return nil, &WrappedError{Msg: "failed to list zones", Err: err}
	}
	return zones, nil
}

// IsDNSSECEnabled returns true if DNSSEC is enabled for the service.
// ZoneTransfer returns the named zone's resource records in RFC 5936 AXFR
// order (apex SOA, all records, closing SOA). It reuses the same projection
// the on-the-wire AXFR responder emits, so the REST zone-export surface and
// the DNS server stay byte-for-byte consistent. It is the read side of the
// platform-as-primary transfer model; the authenticated wire transfer itself
// is served by the CoreDNS plugin over TCP, not through this method.
func (s *Service) ZoneTransfer(ctx context.Context, zoneName string) ([]dns.RR, error) {
	zone, err := s.Zone(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	return BuildZoneTransfer(zone), nil
}

// TransferSecondaries returns the canonical TSIG key names authorized to pull
// zone transfers, or nil when outbound transfer is disabled. It backs the
// REST secondary-management view; it never exposes key secrets.
func (s *Service) TransferSecondaries() []string {
	cfg := s.params.Config.Transfer
	if cfg == nil || !cfg.Enabled || len(cfg.TSIGKeys) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.TSIGKeys))
	for _, k := range cfg.TSIGKeys {
		if k.Name == "" || k.Secret == "" {
			continue
		}
		names = append(names, dns.CanonicalName(k.Name))
	}
	return names
}

func (s *Service) IsDNSSECEnabled() bool {
	return s.dnssecSvc != nil && s.dnssecSvc.IsEnabled()
}

// RegisterWebservice registers DNS A records for a webservice based on its
// certificate CN. The CN should be a fully qualified domain name (e.g.,
// "server.example.internal" or "api.example.com"). The method determines
// whether to use the public or internal zone based on whether the CN suffix
// matches the configured zone names.
func (s *Service) RegisterWebservice(ctx context.Context, cn string) error {
	if cn == "" {
		return &MessageError{Msg: "certificate CN is required"}
	}

	// Normalize the CN
	cn = strings.ToLower(cn)
	if !strings.HasSuffix(cn, ".") {
		cn += "."
	}

	// Determine which zone this CN belongs to
	var zone *entities.Zone
	var ip string
	var err error

	internalZoneName := ""
	publicZoneName := ""

	if s.params.Config.InternalServer != nil {
		internalZoneName = s.params.Config.InternalServer.Zone.Name
	}
	if s.params.Config.PublicServer != nil {
		publicZoneName = s.params.Config.PublicServer.Zone.Name
	}

	switch {
	// Check if CN matches internal zone
	case internalZoneName != "" && strings.HasSuffix(cn, internalZoneName):
		zone, err = s.InternalZone(ctx)
		if err != nil {
			return &WrappedError{Msg: "failed to get internal zone", Err: err}
		}
		ip = configuredOrDetected(s.params.Config.PrivateIPv4, s.params.PrivateIPv4)
	// Check if CN matches public zone
	case publicZoneName != "" && strings.HasSuffix(cn, publicZoneName):
		zone, err = s.PublicZone(ctx)
		if err != nil {
			return &WrappedError{Msg: "failed to get public zone", Err: err}
		}
		ip = configuredOrDetected(s.params.Config.PublicIPv4, s.params.PublicIPv4)
	default:
		return &DetailError{Err: ErrCNOutsideZones, Detail: ": " + cn + " (internal: " + internalZoneName + ", public: " + publicZoneName + ")"}
	}

	if ip == "" {
		return &MessageError{Msg: "no IP address available for zone"}
	}

	// Extract hostname from CN (e.g., "server" from "server.example.internal.")
	hostname := extractHostnameFromCN(cn, zone.Name)

	// Check if record already exists
	for _, rec := range zone.RecordSet.ARecords {
		if rec.Name == hostname && rec.Value == ip {
			// Record already exists with same value, nothing to do
			return nil
		}
	}

	// Add the A record
	zone.AddARecord(&entities.ARecord{
		Name:  hostname,
		Value: ip,
		TTL:   s.params.Config.RecordTTL(),
	})

	// Save the zone
	if err := s.Save(ctx, zone); err != nil {
		return &WrappedError{Msg: "failed to save zone with new A record", Err: err}
	}

	return nil
}

// configuredOrDetected is the address a webservice record points at: the
// dns.private-ipv4 / dns.public-ipv4 the operator configured, else the
// address the host detected. The configured address wins because it is the
// one the zone's static records carry; a host with several interfaces (a
// boot node serving one VLAN) would otherwise register its default-route
// address beside them, and a client could be handed an unreachable record.
func configuredOrDetected(configured string, detected net.IP) string {
	if configured != "" {
		return configured
	}
	if detected != nil {
		return detected.String()
	}
	return ""
}

// extractHostnameFromCN extracts the hostname portion from a CN.
// For example, "server.example.internal." with zone "example.internal." returns "server"
func extractHostnameFromCN(cn, zoneName string) string {
	// Remove the zone suffix from the CN
	hostname := strings.TrimSuffix(cn, zoneName)
	// Remove trailing dot if present
	hostname = strings.TrimSuffix(hostname, ".")
	return hostname
}

// =============================================================================
// Convenience methods for API handlers
// =============================================================================

// CreateZone creates a new zone with the specified name. The zone is automatically
// assigned the service's TenantID.
func (s *Service) CreateZone(ctx context.Context, zoneName string) error {
	zone := &entities.Zone{
		Name:     zoneName,
		TenantID: s.params.TenantID,
		TTL:      s.params.Config.RecordTTL(),
	}
	return s.Save(ctx, zone)
}

// DeleteZone deletes a zone by name.
func (s *Service) DeleteZone(ctx context.Context, zoneName string) error {
	zone, err := s.Zone(ctx, zoneName)
	if err != nil {
		return err
	}
	return s.Delete(ctx, zone)
}

// AddRecord adds a DNS record to the longest stored zone that holds name. The
// types and the form of each value are recordKinds'; any other type is
// ErrRecordTypeNotSupported, and a value that does not parse is
// ErrInvalidRecordValue. A ttl of 0 means the record has none and takes the
// configured default-ttl; a ttl outside RFC 2181 §8's range is ErrInvalidTTL.
func (s *Service) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	kind, err := lookupRecordKind(recordType)
	if err != nil {
		return err
	}

	recordTTL, err := s.addRecordTTL(ttl)
	if err != nil {
		return &RecordError{Op: "add", Type: recordType, Name: name, Err: err}
	}

	zone, err := s.zoneForName(ctx, name)
	if err != nil {
		return &RecordError{Op: "find the zone of", Type: recordType, Name: name, Err: err}
	}

	if err := kind.add(zone, name, value, recordTTL); err != nil {
		return &RecordError{Op: "add", Type: recordType, Name: name, Err: err}
	}

	return s.Save(ctx, zone)
}

// addRecordTTL returns the TTL AddRecord stores: ttl itself, or the
// configured default-ttl when ttl is 0. A negative ttl, or one above 2^31-1
// (RFC 2181 §8), is ErrInvalidTTL.
func (s *Service) addRecordTTL(ttl int) (uint32, error) {
	if ttl < 0 || ttl > maxTTL {
		return 0, &DetailError{Err: ErrInvalidTTL, Detail: ": ttl " + strconv.Itoa(ttl)}
	}
	if ttl == 0 {
		return s.params.Config.RecordTTL(), nil
	}
	return uint32(ttl), nil
}

// DeleteRecord deletes a DNS record from the appropriate zone.
func (s *Service) DeleteRecord(ctx context.Context, name string, recordType string) error {
	kind, err := lookupRecordKind(recordType)
	if err != nil {
		return err
	}

	zone, err := s.zoneForName(ctx, name)
	if err != nil {
		return &RecordError{Op: "find the zone of", Type: recordType, Name: name, Err: err}
	}

	kind.remove(zone, name)

	return s.Save(ctx, zone)
}

// GetRecord retrieves a DNS record by name and type.
func (s *Service) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	kind, err := lookupRecordKind(recordType)
	if err != nil {
		return nil, err
	}

	zone, err := s.zoneForName(ctx, name)
	if err != nil {
		return nil, &RecordError{Op: "find the zone of", Type: recordType, Name: name, Err: err}
	}

	for _, rec := range kind.records(&zone.RecordSet) {
		if rec.name == name {
			return rec.record, nil
		}
	}

	return nil, &RecordError{Op: "find", Type: recordType, Name: name, Err: ErrRecordNotFound}
}

// ListRecords lists all records in a zone.
func (s *Service) ListRecords(ctx context.Context, zoneName string) ([]interface{}, error) {
	zone, err := s.Zone(ctx, zoneName)
	if err != nil {
		return nil, &ZoneError{Op: "get", Zone: zoneName, Err: err}
	}

	var records []interface{}
	for _, recordType := range recordKindOrder {
		for _, rec := range recordKinds[recordType].records(&zone.RecordSet) {
			records = append(records, rec.record)
		}
	}

	return records, nil
}

// Resolve resolves a DNS name to its values using the local zone data.
func (s *Service) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	values, ok := resolvedValues[strings.ToUpper(recordType)]
	if !ok {
		return nil, &DetailError{Err: ErrRecordTypeNotSupported, Detail: ": " + recordType}
	}

	resolution, err := ResolveName(ctx, s, name, recordType)
	if err != nil {
		return nil, err
	}

	results := values(&resolution.Records)
	if len(results) == 0 {
		return nil, &RecordError{Op: "resolve", Type: recordType, Name: name, Err: ErrRecordNotFound}
	}

	return results, nil
}

// zoneForName returns the stored zone that holds name: the longest zone name
// that is a suffix of it, so www.internal.example.com. is filed under
// internal.example.com. when that zone exists and under example.com.
// otherwise. A lookup that fails for any reason other than "not found" is
// returned rather than skipped.
func (s *Service) zoneForName(ctx context.Context, name string) (*entities.Zone, error) {
	labels := dns.SplitDomainName(name)
	for i := range labels {
		zone, err := s.Zone(ctx, strings.Join(labels[i:], "."))
		if err == nil {
			return zone, nil
		}
		if !isNotFoundError(err) {
			return nil, err
		}
	}
	return nil, &DetailError{Err: ErrZoneNotFound, Detail: ": no zone contains " + name}
}
