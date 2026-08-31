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
	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

var (
	DatastorePartition = "dns/zones"

	Configuration *Config

	// DatastoreFactory is the global QuicBaaS factory for DNS zone storage.
	// This is set by the app when initializing DNS services to share
	// the platform's QuicBaaS instance instead of creating a separate one.
	DatastoreFactory *quicbaas.Factory

	// XKMSAdapter is the global XKMS adapter for DNSSEC key management.
	// This is set by the app when initializing DNS services.
	XKMSAdapter *xkmsadapter.Adapter

	// KeyStore is the global DNSSEC key store for zone signing.
	// When set, this is used by signZoneIfEnabled instead of XKMSAdapter.
	// This enables DNSSEC signing when the xkms SDK is initialized but
	// the full Adapter is not yet available.
	KeyStore DNSSECKeyStore

	DefaultConfig = Config{
		QuicBaaS: &quicbaas.Config{
			StorageBackend: "pebble",
			DataDir:        "trusted-data/quicbaas",
			WALDir:         "trusted-data/quicbaas/wal",
			// Dev placeholder identity, consistent with the example.*
			// convention; deployments set the real internal domain.
			SPIFFETrustDomain: "example.internal",
			NodeID:            1,
			CacheSize:         64 * 1024 * 1024, // 64MB
			LogLevel:          "warn",
			ConsistencyLevel:  quicbaas.ConsistencyLinearizable,
		},
		PublicServer: &PublicServer{
			Port:       8053,
			Forwarders: []string{"4.4.4.4", "8.8.8.8"},
			Zone: entities.Zone{
				ID:          1,
				Name:        "trusted-platform.io.",
				TTL:         3600,
				Description: "Public zone for trusted-platform.io",
				Internal:    false,
				RecordSet: entities.RecordSet{
					SOARecord: entities.SOARecord{
						Name:       "trusted-platform.io.",
						MName:      "ns1.trusted-platform.io.",
						RName:      "hostmaster.trusted-platform.io.",
						Serial:     1,
						Refresh:    86400,
						Retry:      7200,
						Expire:     86400,
						MinimumTTL: 3600,
						TTL:        3600,
					},
					NSRecords: []*entities.NSRecord{
						{Name: "trusted-platform.io.", Value: "ns1.trusted-platform.io.", TTL: 3600},
						{Name: "trusted-platform.io.", Value: "ns2.trusted-platform.io.", TTL: 3600},
						{Name: "trusted-platform.io.", Value: "ns3.trusted-platform.io.", TTL: 3600},
					},
					ARecords: []*entities.ARecord{
						{Name: "ns1", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "ns2", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "ns3", Value: "${PUBLIC_IPv4}", TTL: 3600},
						{Name: "www", Value: "${PUBLIC_IPv4}", TTL: 3600},
					},
					CNAMERecords: []*entities.CNAMERecord{},
					MXRecords: []*entities.MXRecord{
						{Name: "trusted-platform.io.", Value: "mail.trusted-platform.io.", Priority: 10, TTL: 3600},
					},
					TXTRecords: []*entities.TXTRecord{
						{Name: "trusted-platform.io.", Value: "v=spf1 include:_spf.google.com ~all", TTL: 3600},
					},
				},
			},
		},
		InternalServer: &InternalServer{
			Port:       9053,
			Forwarders: []string{"192.168.1.1", "192.168.2.1", "192.168.3.1"},
			Zone: entities.Zone{
				ID:          2,
				Name:        "trusted-platform.internal.",
				TTL:         3600,
				Description: "Internal zone for trusted-platform.internal",
				Internal:    true,
				RecordSet: entities.RecordSet{
					SOARecord: entities.SOARecord{
						Name:       "trusted-platform.internal.",
						MName:      "ns1.trusted-platform.internal.",
						RName:      "hostmaster.trusted-platform.internal.",
						Serial:     1,
						Refresh:    86400,
						Retry:      7200,
						Expire:     86400,
						MinimumTTL: 3600,
						TTL:        3600,
					},
					NSRecords: []*entities.NSRecord{
						{Name: "trusted-platform.internal.", Value: "ns1.trusted-platform.internal.", TTL: 3600},
						{Name: "trusted-platform.internal.", Value: "ns2.trusted-platform.internal.", TTL: 3600},
						{Name: "trusted-platform.internal.", Value: "ns3.trusted-platform.internal.", TTL: 3600},
					},
					ARecords: []*entities.ARecord{
						{Name: "ns1", Value: "${PRIVATE_IPv4}", TTL: 3600},
						{Name: "ns2", Value: "192.168.2.1", TTL: 3600},
						{Name: "ns3", Value: "192.168.3.1", TTL: 3600},
						{Name: "${HOSTNAME}", Value: "${PRIVATE_IPv4}", TTL: 3600},
					},
					CNAMERecords: []*entities.CNAMERecord{
						{Name: "www", Value: "trusted-platform.internal.", TTL: 3600},
					},
				},
			},
		},
		Resolver: &ResolverConfig{
			Servers:  []ResolverServer{{Address: "127.0.0.1", Port: 8053}},
			Fallback: []string{"1.1.1.1:53", "8.8.8.8:53"},
			LocalForwarder: &LocalForwarderConfig{
				Listen:    "127.0.0.1:53",
				CacheSize: 1000,
			},
		},
	}
)

// Config holds the DNS subsystem configuration including server settings,
// resolver defaults, DNSSEC, DANE, and attestation-gated updates.
type Config struct {
	AllowRegistration         bool               `yaml:"allow-registration" json:"allow_registration" mapstructure:"allow-registration"`
	AllowExternalRegistration bool               `yaml:"allow-external-registration" json:"allow_external_registration" mapstructure:"allow-external-registration"`
	AllowInternalRegistration bool               `yaml:"allow-internal-registration" json:"allow_internal_registration" mapstructure:"allow-internal-registration"`
	Attestation               *AttestationConfig `yaml:"attestation" json:"attestation" mapstructure:"attestation"`
	DANE                      *DANEConfig        `yaml:"dane" json:"dane" mapstructure:"dane"`
	QuicBaaS                  *quicbaas.Config   `yaml:"quicbaas" json:"quicbaas" mapstructure:"quicbaas"`
	DefaultTTL                int                `yaml:"default-ttl" json:"default_ttl" mapstructure:"default-ttl"`
	DNSSEC                    *DNSSECConfig      `yaml:"dnssec" json:"dnssec" mapstructure:"dnssec"`
	InternalServer            *InternalServer    `yaml:"internal" json:"internal" mapstructure:"internal"`
	Logger                    *logging.Logger    `yaml:"-" json:"-" mapstructure:"-"`
	PublicServer              *PublicServer      `yaml:"public" json:"public" mapstructure:"public"`
	PrivateIPv4               string             `yaml:"private-ipv4" json:"private_ipv4" mapstructure:"private-ipv4"`
	PrivateIPv6               string             `yaml:"private-ipv6" json:"private_ipv6" mapstructure:"private-ipv6"`
	PublicIPv4                string             `yaml:"public-ipv4" json:"public_ipv4" mapstructure:"public-ipv4"`
	PublicIPv6                string             `yaml:"public-ipv6" json:"public_ipv6" mapstructure:"public-ipv6"`
	Resolver                  *ResolverConfig    `yaml:"resolver" json:"resolver" mapstructure:"resolver"`
	// Transfer configures outbound authoritative zone transfers (AXFR).
	// The platform is a PRIMARY nameserver: it serves full zone transfers
	// to explicitly configured, TSIG-authenticated secondaries over DNS
	// TCP. When nil or without keys, the AXFR responder refuses every
	// transfer request (fail closed).
	Transfer *TransferConfig `yaml:"transfer" json:"transfer" mapstructure:"transfer"`
	// ZoneSubdomains, when true, enables per-network-zone subdomain support in
	// the internal DNS server. At startup the server pre-creates one DNS
	// sub-zone per declared network zone under the internal domain
	// (<networkzone>.<domain>). During device enrollment, hosts are registered
	// as <host>.<networkzone>.<domain> in addition to the standard
	// <host>.<domain> A record. BMC names (<host>-bmc.<domain>) are never
	// zone-qualified. Defaults to false (off).
	ZoneSubdomains bool `yaml:"zone-subdomains" json:"zone_subdomains" mapstructure:"zone-subdomains"`
	// NetworkZones is the runtime-injected list of network zone names sourced
	// from sdn.Config.ResolvedZones(). Not read from YAML; populated by the
	// app wiring before dns.Run is called. Used by the CoreDNS plugin setup
	// to pre-create per-zone sub-zones when ZoneSubdomains is true.
	NetworkZones []string `yaml:"-" json:"-" mapstructure:"-"`
}

// AttestationConfig contains attestation-gated DNS update settings.
type AttestationConfig struct {
	// Enabled enables attestation-gated DNS updates globally.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// Required makes attestation required by default for all zones.
	Required bool `yaml:"required" json:"required" mapstructure:"required"`
	// MaxAge is the maximum age of attestation evidence (default: 5m).
	MaxAge string `yaml:"max-age" json:"max_age" mapstructure:"max-age"`
	// DefaultPCRPolicy is the default PCR policy name for verification.
	DefaultPCRPolicy string `yaml:"default-pcr-policy" json:"default_pcr_policy" mapstructure:"default-pcr-policy"`
	// Fallback defines behavior when attestation service unavailable.
	// Options: "deny", "allow-with-warning", "cached-quote"
	Fallback string `yaml:"fallback" json:"fallback" mapstructure:"fallback"`
	// PCRPolicies defines named PCR policies for attestation verification.
	PCRPolicies map[string]*PCRPolicy `yaml:"pcr-policies" json:"pcr_policies" mapstructure:"pcr-policies"`
}

// PCRPolicy defines expected PCR values for attestation verification.
type PCRPolicy struct {
	// Description of the policy.
	Description string `yaml:"description" json:"description" mapstructure:"description"`
	// PCRs defines the expected PCR values.
	PCRs []PCRExpectation `yaml:"pcrs" json:"pcrs" mapstructure:"pcrs"`
}

// PCRExpectation defines an expected PCR value.
type PCRExpectation struct {
	// Index is the PCR index (0-23).
	Index int `yaml:"index" json:"index" mapstructure:"index"`
	// Description of what this PCR measures.
	Description string `yaml:"description" json:"description" mapstructure:"description"`
	// Any allows any value for this PCR (useful for volatile PCRs).
	Any bool `yaml:"any" json:"any" mapstructure:"any"`
	// Expected is the expected SHA-256 hash value (if Any is false).
	Expected string `yaml:"expected" json:"expected" mapstructure:"expected"`
}

// DANEConfig contains DANE/TLSA auto-generation settings.
type DANEConfig struct {
	// Enabled enables DANE/TLSA record auto-generation.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// AutoGenerate enables automatic TLSA record generation on certificate issuance.
	AutoGenerate bool `yaml:"auto-generate" json:"auto_generate" mapstructure:"auto-generate"`
	// DefaultPort is the default port for TLSA record names (e.g., 443 for HTTPS).
	DefaultPort uint16 `yaml:"default-port" json:"default_port" mapstructure:"default-port"`
	// DefaultTTL is the TTL for generated TLSA records.
	DefaultTTL uint32 `yaml:"ttl" json:"ttl" mapstructure:"ttl"`
	// DefaultUsage is the default TLSA usage field (0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE).
	DefaultUsage uint8 `yaml:"default-usage" json:"default_usage" mapstructure:"default-usage"`
	// DefaultSelector is the default TLSA selector field (0=Full cert, 1=SPKI).
	DefaultSelector uint8 `yaml:"default-selector" json:"default_selector" mapstructure:"default-selector"`
	// DefaultMatchingType is the default TLSA matching type (0=Full, 1=SHA-256, 2=SHA-512).
	DefaultMatchingType uint8 `yaml:"default-matching-type" json:"default_matching_type" mapstructure:"default-matching-type"`
	// PublishDANEEE enables publishing DANE-EE (Usage=3) TLSA records in addition to DANE-TA.
	PublishDANEEE bool `yaml:"publish-dane-ee" json:"publish_dane_ee" mapstructure:"publish-dane-ee"`
	// KeyReuse reuses the private key during certificate renewal, keeping the SPKI hash
	// unchanged (Selector=1). This eliminates the need for DANE-EE TLSA rollover delays.
	KeyReuse bool `yaml:"key-reuse" json:"key_reuse" mapstructure:"key-reuse"`
	// RolloverTTL is the TTL for pre-published TLSA records during DANE-EE rollover.
	// Must be >= 2x the normal TTL for DNS cache expiry. 0 means auto (2x DefaultTTL).
	RolloverTTL uint32 `yaml:"rollover-ttl" json:"rollover_ttl" mapstructure:"rollover-ttl"`
}

// TransferConfig configures outbound authoritative zone transfers (AXFR).
// The platform acts as a PRIMARY nameserver per RFC 5936: it serves full
// zone transfers to explicitly configured, TSIG-authenticated secondary
// nameservers over DNS TCP. Inbound/secondary mode is intentionally not
// supported. When Enabled is false or no keys are configured, the AXFR
// responder refuses every transfer request (fail closed).
type TransferConfig struct {
	// Enabled turns on the outbound AXFR responder. Even when true, a
	// transfer is only served to a request bearing a valid TSIG signed
	// with one of the configured keys.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// TSIGKeys are the shared TSIG keys authorized to pull zone transfers.
	// Each configured secondary must present a TSIG signed with one of
	// these keys. An empty list refuses all transfers.
	TSIGKeys []TSIGKey `yaml:"tsig-keys" json:"tsig_keys" mapstructure:"tsig-keys"`
}

// TSIGKey is a shared TSIG key authorizing a secondary nameserver to pull
// zone transfers per RFC 8945.
type TSIGKey struct {
	// Name is the TSIG key name (e.g. "secondary1."). It is canonicalized
	// (lowercased, fully qualified) before use.
	Name string `yaml:"name" json:"name" mapstructure:"name"`
	// Algorithm is the TSIG HMAC algorithm (e.g. "hmac-sha256."). Defaults
	// to hmac-sha256 when empty.
	Algorithm string `yaml:"algorithm" json:"algorithm" mapstructure:"algorithm"`
	// Secret is the base64-encoded shared HMAC secret.
	Secret string `yaml:"secret" json:"secret" mapstructure:"secret"`
}

// DNSSECConfig configures DNSSEC zone signing.
// DNSSEC key management is handled by the XKMS SDK.
type DNSSECConfig struct {
	// Enabled enables DNSSEC zone signing.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// DefaultKey provides default key configuration used when KSK or ZSK don't specify their own key.
	// This allows specifying algorithm, curve/keysize, hash, store, etc. once for all DNSSEC keys.
	DefaultKey *common.KeyConfig `yaml:"default-key,omitempty" json:"default_key,omitempty" mapstructure:"default-key"`
	// SignatureExpiry specifies the signature validity period (e.g., "30d").
	SignatureExpiry string `yaml:"signature-expiry" json:"signature_expiry" mapstructure:"signature-expiry"`
	// NSECMode specifies the authenticated denial mode ("nsec" or "nsec3").
	NSECMode string `yaml:"nsec-mode" json:"nsec_mode" mapstructure:"nsec-mode"`
	// NSEC3Iterations specifies the number of NSEC3 hash iterations.
	NSEC3Iterations uint16 `yaml:"nsec3-iterations" json:"nsec3_iterations" mapstructure:"nsec3-iterations"`
	// NSEC3Salt specifies the NSEC3 salt value.
	NSEC3Salt string `yaml:"nsec3-salt" json:"nsec3_salt" mapstructure:"nsec3-salt"`
	// KSK is the Key Signing Key configuration.
	KSK *DNSSECKeyConfig `yaml:"ksk" json:"ksk" mapstructure:"ksk"`
	// ZSK is the Zone Signing Key configuration.
	ZSK *DNSSECKeyConfig `yaml:"zsk" json:"zsk" mapstructure:"zsk"`
}

// DNSSECKeyConfig configures a DNSSEC key (KSK or ZSK).
type DNSSECKeyConfig struct {
	// Key specifies the cryptographic key configuration.
	// This uses the standard KeyConfig pattern for algorithm, curve/keysize, hash, store, etc.
	// If not specified, the DNSSECConfig.DefaultKey is used.
	Key *common.KeyConfig `yaml:"key,omitempty" json:"key,omitempty" mapstructure:"key"`
	// Lifetime specifies the key lifetime before rollover (e.g., "365d" for KSK, "30d" for ZSK).
	Lifetime string `yaml:"lifetime" json:"lifetime" mapstructure:"lifetime"`
	// TTL specifies the DNSKEY record TTL in seconds.
	TTL uint32 `yaml:"ttl" json:"ttl" mapstructure:"ttl"`
}

type PublicServer struct {
	Port       int           `yaml:"port" json:"port" mapstructure:"port"`
	Forwarders []string      `yaml:"forwarders" json:"forwarders" mapstructure:"forwarders"`
	Zone       entities.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`
}

type InternalServer struct {
	Port       int           `yaml:"port" json:"port" mapstructure:"port"`
	Forwarders []string      `yaml:"forwarders" json:"forwarders" mapstructure:"forwarders"`
	Zone       entities.Zone `yaml:"zone" json:"zone" mapstructure:"zone"`
}

// HasServer returns true if a PublicServer or InternalServer is configured.
// A Config with only a Resolver does not run a DNS server; the resolver
// is passive configuration consumed by bootstrap DANE lookups and other
// clients that need to know which nameserver to query.
func (c *Config) HasServer() bool {
	return c.PublicServer != nil || c.InternalServer != nil
}
