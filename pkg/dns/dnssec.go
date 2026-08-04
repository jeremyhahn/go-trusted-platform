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
	"crypto"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	xkmsadapter "github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/miekg/dns"
)

// DNSSECService provides DNSSEC zone signing operations.
// DNSSEC key management is handled by the XKMS SDK.
type DNSSECService struct {
	config   *DNSSECConfig
	logger   *logging.Logger
	keyStore DNSSECKeyStore
}

// DNSSECKeyPair holds a DNSKEY record and its corresponding private key.
type DNSSECKeyPair struct {
	DNSKEY     *dns.DNSKEY
	PrivateKey crypto.PrivateKey
}

// NewDNSSECServiceWithXKMS creates a new DNSSECService instance with XKMS backend.
// This is the primary constructor for DNSSEC operations using the go-xkms SDK.
func NewDNSSECServiceWithXKMS(config *DNSSECConfig, logger *logging.Logger, adapter *xkmsadapter.Adapter) (*DNSSECService, error) {
	if config == nil {
		return nil, ErrDNSSECConfigNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}
	if adapter == nil {
		return nil, ErrKeyStoreNil
	}

	keyStore, err := NewXKMSKeyStore(adapter)
	if err != nil {
		return nil, &DNSSECError{
			Op:  "NewDNSSECServiceWithXKMS",
			Err: &WrappedError{Msg: "failed to create xkms key store", Err: err},
		}
	}

	return &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: keyStore,
	}, nil
}

// NewDNSSECServiceWithXKMSAndBackend creates a new DNSSECService instance with XKMS backend
// and a specific backend (e.g., "software", "tpm", "pkcs11").
func NewDNSSECServiceWithXKMSAndBackend(config *DNSSECConfig, logger *logging.Logger, adapter *xkmsadapter.Adapter, backend string) (*DNSSECService, error) {
	if config == nil {
		return nil, ErrDNSSECConfigNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}
	if adapter == nil {
		return nil, ErrKeyStoreNil
	}

	keyStore, err := NewXKMSKeyStoreWithBackend(adapter, backend)
	if err != nil {
		return nil, &DNSSECError{
			Op:  "NewDNSSECServiceWithXKMSAndBackend",
			Err: &WrappedError{Msg: "failed to create xkms key store", Err: err},
		}
	}

	return &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: keyStore,
	}, nil
}

// NewDNSSECServiceWithKeyStore creates a new DNSSECService instance with a custom key store.
// This allows for custom key store implementations including testing with mock stores.
func NewDNSSECServiceWithKeyStore(config *DNSSECConfig, logger *logging.Logger, keyStore DNSSECKeyStore) (*DNSSECService, error) {
	if config == nil {
		return nil, ErrDNSSECConfigNil
	}
	if logger == nil {
		return nil, ErrLoggerNil
	}
	if keyStore == nil {
		return nil, ErrKeyStoreNil
	}

	return &DNSSECService{
		config:   config,
		logger:   logger,
		keyStore: keyStore,
	}, nil
}

// GenerateKeys generates a KSK (Key Signing Key) and ZSK (Zone Signing Key)
// for the specified zone using the configured key store. Returns the DNSKEY records for both keys.
// The tenantID is used to scope keys to specific tenants for multi-tenant isolation.
func (s *DNSSECService) GenerateKeys(tenantID, zoneName string) (*dns.DNSKEY, *dns.DNSKEY, error) {
	if zoneName == "" {
		return nil, nil, ErrZoneNameEmpty
	}
	if tenantID == "" {
		return nil, nil, ErrMissingTenantContext
	}

	// Normalize zone name
	zoneName = dns.Fqdn(zoneName)

	// Get algorithm from KeyConfig pattern
	algorithm := s.getAlgorithm()

	s.logger.Info("Generating DNSSEC keys via xkms",
		slog.String("tenant", tenantID),
		slog.String("zone", zoneName),
		slog.Uint64("algorithm", uint64(algorithm)))

	return s.generateKeysXKMS(tenantID, zoneName, algorithm)
}

// generateKeysXKMS generates keys using the XKMS backend.
func (s *DNSSECService) generateKeysXKMS(tenantID, zoneName string, algorithm uint8) (*dns.DNSKEY, *dns.DNSKEY, error) {
	ctx := context.Background()

	// Generate KSK
	ksk, err := s.keyStore.GenerateKSK(ctx, tenantID, zoneName, algorithm)
	if err != nil {
		return nil, nil, err
	}

	// Generate ZSK
	zsk, err := s.keyStore.GenerateZSK(ctx, tenantID, zoneName, algorithm)
	if err != nil {
		return nil, nil, err
	}

	s.logger.Info("DNSSEC keys generated via xkms",
		slog.String("tenant", tenantID),
		slog.String("zone", zoneName),
		slog.Uint64("ksk_keytag", uint64(ksk.KeyTag())),
		slog.Uint64("zsk_keytag", uint64(zsk.KeyTag())))

	return ksk, zsk, nil
}

// LoadKeys loads existing keys for a zone from the xkms.
// Returns the KSK, ZSK, and their signers.
// The tenantID is used to scope key retrieval to the correct tenant.
func (s *DNSSECService) LoadKeys(tenantID, zoneName string) (*DNSSECKeyPair, *DNSSECKeyPair, error) {
	zoneName = dns.Fqdn(zoneName)
	return s.loadKeysXKMS(tenantID, zoneName)
}

// loadKeysXKMS loads keys from the XKMS backend.
func (s *DNSSECService) loadKeysXKMS(tenantID, zoneName string) (*DNSSECKeyPair, *DNSSECKeyPair, error) {
	ctx := context.Background()

	// Load KSK
	kskDNSKEY, err := s.keyStore.GetDNSKEY(ctx, tenantID, zoneName, KeyTypeKSK)
	if err != nil {
		return nil, nil, &DNSSECError{
			Op:   "LoadKeys",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to load KSK", Err: err},
		}
	}

	kskSigner, err := s.keyStore.GetSigner(ctx, tenantID, zoneName, KeyTypeKSK)
	if err != nil {
		return nil, nil, &DNSSECError{
			Op:   "LoadKeys",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to get KSK signer", Err: err},
		}
	}

	// Load ZSK
	zskDNSKEY, err := s.keyStore.GetDNSKEY(ctx, tenantID, zoneName, KeyTypeZSK)
	if err != nil {
		return nil, nil, &DNSSECError{
			Op:   "LoadKeys",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to load ZSK", Err: err},
		}
	}

	zskSigner, err := s.keyStore.GetSigner(ctx, tenantID, zoneName, KeyTypeZSK)
	if err != nil {
		return nil, nil, &DNSSECError{
			Op:   "LoadKeys",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to get ZSK signer", Err: err},
		}
	}

	return &DNSSECKeyPair{
			DNSKEY:     kskDNSKEY,
			PrivateKey: kskSigner,
		}, &DNSSECKeyPair{
			DNSKEY:     zskDNSKEY,
			PrivateKey: zskSigner,
		}, nil
}

// validateKeyPair verifies that a DNSSEC key pair's DNSKEY and private key
// correspond to each other by performing a test signature.
func (s *DNSSECService) validateKeyPair(pair *DNSSECKeyPair) error {
	if pair == nil || pair.DNSKEY == nil || pair.PrivateKey == nil {
		return &MessageError{Msg: "dnssec: nil key pair"}
	}

	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return &MessageError{Msg: "dnssec: private key does not implement crypto.Signer"}
	}

	// Create a dummy RR and try to sign it
	testRR := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   "test.validation.",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{"key-validation"},
	}

	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeTXT,
		Algorithm:   pair.DNSKEY.Algorithm,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(time.Hour).Unix()),
		Inception:   uint32(time.Now().Unix()),
		KeyTag:      pair.DNSKEY.KeyTag(),
		SignerName:  "test.validation.",
	}

	return rrsig.Sign(signer, []dns.RR{testRR})
}

// KeysExist checks if keys exist for the specified zone in the xkms.
// The tenantID is used to scope the key lookup to the correct tenant.
func (s *DNSSECService) KeysExist(tenantID, zoneName string) bool {
	zoneName = dns.Fqdn(zoneName)
	ctx := context.Background()
	return s.keyStore.KeyExists(ctx, tenantID, zoneName, KeyTypeKSK) &&
		s.keyStore.KeyExists(ctx, tenantID, zoneName, KeyTypeZSK)
}

// SignZone signs all records in the zone with DNSSEC signatures.
// This method:
// - Loads or generates keys for the zone (scoped by zone.TenantID)
// - Creates RRSIG records for each RRset using the ZSK
// - Signs the DNSKEY RRset with the KSK
// - Generates NSEC or NSEC3 chain based on configuration
// - Updates the zone with signed records
func (s *DNSSECService) SignZone(zone *entities.Zone) error {
	if zone == nil {
		return ErrZoneNil
	}
	if zone.TenantID == "" {
		return ErrMissingTenantContext
	}

	zoneName := dns.Fqdn(zone.Name)
	tenantID := zone.TenantID

	s.logger.Info("Signing zone",
		slog.String("tenant", tenantID),
		slog.String("zone", zoneName))

	// Determine algorithm: per-zone KeyConfig takes precedence over global config
	algorithm := s.getAlgorithmForZone(zone)

	// Load or generate keys (scoped by tenant)
	kskPair, zskPair, err := s.LoadKeys(tenantID, zoneName)
	if err != nil {
		// Keys don't exist, generate them
		s.logger.Info("No existing keys found, generating new keys",
			slog.String("tenant", tenantID),
			slog.String("zone", zoneName),
			slog.Uint64("algorithm", uint64(algorithm)))

		ksk, zsk, genErr := s.generateKeysXKMS(tenantID, zoneName, algorithm)
		if genErr != nil {
			return genErr
		}

		// Load the private keys we just saved
		kskPair, zskPair, err = s.LoadKeys(tenantID, zoneName)
		if err != nil {
			return err
		}
		kskPair.DNSKEY = ksk
		zskPair.DNSKEY = zsk
	} else {
		// Keys loaded — validate they can sign. Stale keys from a previous
		// install that wasn't properly cleaned will fail validation.
		if err := s.validateKeyPair(kskPair); err != nil {
			return &DNSSECError{
				Op:   "SignZone",
				Zone: zoneName,
				Err:  &WrappedError{Msg: "KSK validation failed (stale keys from previous install? clean data directory and retry)", Err: err},
			}
		}
		if err := s.validateKeyPair(zskPair); err != nil {
			return &DNSSECError{
				Op:   "SignZone",
				Zone: zoneName,
				Err:  &WrappedError{Msg: "ZSK validation failed (stale keys from previous install? clean data directory and retry)", Err: err},
			}
		}
	}

	// Clear existing DNSSEC records
	zone.RecordSet.DNSKEYRecords = nil
	zone.RecordSet.RRSIGRecords = nil
	zone.RecordSet.NSECRecords = nil
	zone.RecordSet.NSEC3Records = nil
	zone.RecordSet.NSEC3PARAMRecords = nil
	zone.RecordSet.DSRecords = nil

	// Add DNSKEY records to zone
	zone.AddDNSKEYRecord(s.dnsKeyToEntity(kskPair.DNSKEY))
	zone.AddDNSKEYRecord(s.dnsKeyToEntity(zskPair.DNSKEY))

	// Calculate signature validity
	inception := time.Now().UTC()
	expiration := s.calculateExpiration(inception)

	// Collect all RRsets and sign them
	rrsets := s.collectRRsets(zone)

	for _, rrset := range rrsets {
		if len(rrset) == 0 {
			continue
		}

		rrtype := rrset[0].Header().Rrtype

		// DNSKEY RRset is signed with KSK
		if rrtype == dns.TypeDNSKEY {
			rrsig, err := s.signRRset(rrset, kskPair.DNSKEY, kskPair.PrivateKey, zoneName, inception, expiration)
			if err != nil {
				return &DNSSECError{
					Op:   "SignZone",
					Zone: zoneName,
					Err:  &WrappedError{Msg: "failed to sign DNSKEY RRset", Err: err},
				}
			}
			zone.AddRRSIGRecord(s.rrsigToEntity(rrsig))
		} else {
			// All other RRsets are signed with ZSK
			rrsig, err := s.signRRset(rrset, zskPair.DNSKEY, zskPair.PrivateKey, zoneName, inception, expiration)
			if err != nil {
				return &DNSSECError{
					Op:   "SignZone",
					Zone: zoneName,
					Err:  &WrappedError{Msg: fmt.Sprintf("failed to sign RRset type %s", dns.TypeToString[rrtype]), Err: err},
				}
			}
			zone.AddRRSIGRecord(s.rrsigToEntity(rrsig))
		}
	}

	// Generate NSEC or NSEC3 chain based on configuration
	if s.config.NSECMode == "nsec3" {
		if err := s.generateNSEC3Chain(zone, zskPair, inception, expiration); err != nil {
			return err
		}
	} else {
		if err := s.generateNSECChain(zone, zskPair, inception, expiration); err != nil {
			return err
		}
	}

	// Generate DS record for the KSK
	ds := s.GenerateDS(kskPair.DNSKEY)
	zone.AddDSRecord(s.dsToEntity(ds))

	s.logger.Info("Zone signed successfully",
		slog.String("zone", zoneName),
		slog.Int("rrsig_count", len(zone.RecordSet.RRSIGRecords)))

	return nil
}

// GenerateDS generates a DS (Delegation Signer) record from a DNSKEY.
func (s *DNSSECService) GenerateDS(dnskey *dns.DNSKEY) *dns.DS {
	return dnskey.ToDS(dns.SHA256) // Digest type 2 (SHA-256)
}

// GenerateNSECChain generates an NSEC chain for authenticated denial of existence.
func (s *DNSSECService) GenerateNSECChain(zone *entities.Zone) []*dns.NSEC {
	zoneName := dns.Fqdn(zone.Name)

	// Collect all owner names in the zone
	ownerNames := s.collectOwnerNames(zone)

	// Sort canonically
	sort.Slice(ownerNames, func(i, j int) bool {
		return dns.CanonicalName(ownerNames[i]) < dns.CanonicalName(ownerNames[j])
	})

	nsecRecords := make([]*dns.NSEC, 0, len(ownerNames))

	for i, name := range ownerNames {
		// Next domain wraps around to first for the last entry
		nextIdx := (i + 1) % len(ownerNames)
		nextDomain := ownerNames[nextIdx]

		// Get type bitmap for this name
		typeBitMap := s.getTypeBitMapForName(zone, name)

		// Include NSEC and RRSIG in type bitmap
		typeBitMap = append(typeBitMap, dns.TypeNSEC, dns.TypeRRSIG)
		sort.Slice(typeBitMap, func(i, j int) bool {
			return typeBitMap[i] < typeBitMap[j]
		})

		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    zone.TTL,
			},
			NextDomain: nextDomain,
			TypeBitMap: typeBitMap,
		}

		nsecRecords = append(nsecRecords, nsec)
	}

	s.logger.Debug("Generated NSEC chain",
		slog.String("zone", zoneName),
		slog.Int("count", len(nsecRecords)))

	return nsecRecords
}

// signRRset creates an RRSIG for an RRset.
func (s *DNSSECService) signRRset(
	rrset []dns.RR,
	key *dns.DNSKEY,
	privKey crypto.PrivateKey,
	signerName string,
	inception, expiration time.Time,
) (*dns.RRSIG, error) {
	if len(rrset) == 0 {
		return nil, ErrEmptyRRSet
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  signerName,
	}

	// Cast private key to crypto.Signer for signing
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &MessageError{Msg: "private key does not implement crypto.Signer"}
	}

	if err := rrsig.Sign(signer, rrset); err != nil {
		return nil, &WrappedError{Msg: "signing failed", Err: err}
	}

	return rrsig, nil
}

// collectRRsets collects all RRsets from a zone for signing.
func (s *DNSSECService) collectRRsets(zone *entities.Zone) map[string][]dns.RR {
	rrsets := make(map[string][]dns.RR)
	zoneName := dns.Fqdn(zone.Name)

	// Helper to add RRs to the map
	addRR := func(rr dns.RR) {
		key := fmt.Sprintf("%s_%d", rr.Header().Name, rr.Header().Rrtype)
		rrsets[key] = append(rrsets[key], rr)
	}

	// SOA record
	soa := s.soaToRR(zone.Name, &zone.RecordSet.SOARecord)
	addRR(soa)

	// NS records
	for _, r := range zone.RecordSet.NSRecords {
		addRR(s.nsToRR(zoneName, r))
	}

	// A records
	for _, r := range zone.RecordSet.ARecords {
		addRR(s.aToRR(zoneName, r))
	}

	// AAAA records
	for _, r := range zone.RecordSet.AAAARecords {
		addRR(s.aaaaToRR(zoneName, r))
	}

	// CNAME records
	for _, r := range zone.RecordSet.CNAMERecords {
		addRR(s.cnameToRR(zoneName, r))
	}

	// MX records
	for _, r := range zone.RecordSet.MXRecords {
		addRR(s.mxToRR(zoneName, r))
	}

	// TXT records
	for _, r := range zone.RecordSet.TXTRecords {
		addRR(s.txtToRR(zoneName, r))
	}

	// SRV records
	for _, r := range zone.RecordSet.SRVRecords {
		addRR(s.srvToRR(zoneName, r))
	}

	// CAA records
	for _, r := range zone.RecordSet.CAARecords {
		addRR(s.caaToRR(zoneName, r))
	}

	// TLSA records
	for _, r := range zone.RecordSet.TLSARecords {
		addRR(s.tlsaToRR(zoneName, r))
	}

	// DNSKEY records
	for _, r := range zone.RecordSet.DNSKEYRecords {
		addRR(s.dnskeyToRR(zoneName, r))
	}

	return rrsets
}

// collectOwnerNames collects all unique owner names in a zone.
func (s *DNSSECService) collectOwnerNames(zone *entities.Zone) []string {
	namesMap := make(map[string]struct{})
	zoneName := dns.Fqdn(zone.Name)

	// Add zone apex
	namesMap[zoneName] = struct{}{}

	// Helper to add a name
	addName := func(name string) {
		if name == "@" || name == "" {
			namesMap[zoneName] = struct{}{}
		} else if strings.HasSuffix(name, ".") {
			namesMap[name] = struct{}{}
		} else {
			namesMap[fmt.Sprintf("%s.%s", name, zoneName)] = struct{}{}
		}
	}

	// Collect from all record types
	for _, r := range zone.RecordSet.ARecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.AAAARecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.CNAMERecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.MXRecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.NSRecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.TXTRecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.SRVRecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.CAARecords {
		addName(r.Name)
	}
	for _, r := range zone.RecordSet.TLSARecords {
		addName(r.Name)
	}

	// Convert to slice
	names := make([]string, 0, len(namesMap))
	for name := range namesMap {
		names = append(names, name)
	}

	return names
}

// getTypeBitMapForName returns the types present at a given name.
func (s *DNSSECService) getTypeBitMapForName(zone *entities.Zone, name string) []uint16 {
	typesMap := make(map[uint16]struct{})
	zoneName := dns.Fqdn(zone.Name)

	// Normalize name for comparison
	normName := name
	if !strings.HasSuffix(normName, ".") {
		normName = normName + "."
	}

	// Helper to check if record name matches
	matchesName := func(recordName string) bool {
		var fullName string
		if recordName == "@" || recordName == "" {
			fullName = zoneName
		} else if strings.HasSuffix(recordName, ".") {
			fullName = recordName
		} else {
			fullName = fmt.Sprintf("%s.%s", recordName, zoneName)
		}
		return fullName == normName
	}

	// Check each record type
	if matchesName(zone.RecordSet.SOARecord.Name) || normName == zoneName {
		typesMap[dns.TypeSOA] = struct{}{}
	}

	for _, r := range zone.RecordSet.ARecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeA] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.AAAARecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeAAAA] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.CNAMERecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeCNAME] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.MXRecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeMX] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.NSRecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeNS] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.TXTRecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeTXT] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.SRVRecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeSRV] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.CAARecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeCAA] = struct{}{}
		}
	}
	for _, r := range zone.RecordSet.TLSARecords {
		if matchesName(r.Name) {
			typesMap[dns.TypeTLSA] = struct{}{}
		}
	}

	// DNSKEY only at zone apex
	if normName == zoneName && len(zone.RecordSet.DNSKEYRecords) > 0 {
		typesMap[dns.TypeDNSKEY] = struct{}{}
	}

	types := make([]uint16, 0, len(typesMap))
	for t := range typesMap {
		types = append(types, t)
	}

	return types
}

// generateNSECChain generates and signs NSEC records for the zone.
func (s *DNSSECService) generateNSECChain(zone *entities.Zone, zskPair *DNSSECKeyPair, inception, expiration time.Time) error {
	nsecRecords := s.GenerateNSECChain(zone)
	zoneName := dns.Fqdn(zone.Name)

	// Add NSEC records to zone and sign them
	for _, nsec := range nsecRecords {
		zone.AddNSECRecord(s.nsecToEntity(nsec))

		// Sign the NSEC record
		rrsig, err := s.signRRset([]dns.RR{nsec}, zskPair.DNSKEY, zskPair.PrivateKey, zoneName, inception, expiration)
		if err != nil {
			return &DNSSECError{
				Op:   "generateNSECChain",
				Zone: zoneName,
				Err:  &WrappedError{Msg: "failed to sign NSEC record", Err: err},
			}
		}
		zone.AddRRSIGRecord(s.rrsigToEntity(rrsig))
	}

	return nil
}

// generateNSEC3Chain generates and signs NSEC3 records for the zone.
func (s *DNSSECService) generateNSEC3Chain(zone *entities.Zone, zskPair *DNSSECKeyPair, inception, expiration time.Time) error {
	zoneName := dns.Fqdn(zone.Name)

	// NSEC3PARAM record
	iterations := s.config.NSEC3Iterations
	if iterations == 0 {
		iterations = 0 // RFC 9276 recommends 0 iterations
	}

	salt := s.config.NSEC3Salt
	saltBytes := []byte(salt)

	nsec3param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   zoneName,
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    zone.TTL,
		},
		Hash:       dns.SHA1, // Only SHA-1 is defined for NSEC3
		Flags:      0,
		Iterations: iterations,
		SaltLength: uint8(len(saltBytes)),
		Salt:       salt,
	}

	zone.AddNSEC3PARAMRecord(s.nsec3paramToEntity(nsec3param))

	// Collect owner names and generate NSEC3 records
	ownerNames := s.collectOwnerNames(zone)

	// Generate hashes for each name
	type hashedName struct {
		original  string
		hashed    string
		typeBits  []uint16
		nsec3Name string
	}

	hashedNames := make([]hashedName, 0, len(ownerNames))

	for _, name := range ownerNames {
		hash := dns.HashName(name, dns.SHA1, iterations, salt)
		nsec3Name := fmt.Sprintf("%s.%s", hash, zoneName)
		typeBits := s.getTypeBitMapForName(zone, name)
		typeBits = append(typeBits, dns.TypeRRSIG)

		// Sort type bitmap in ascending order (required by DNS)
		sort.Slice(typeBits, func(i, j int) bool {
			return typeBits[i] < typeBits[j]
		})

		hashedNames = append(hashedNames, hashedName{
			original:  name,
			hashed:    hash,
			typeBits:  typeBits,
			nsec3Name: nsec3Name,
		})
	}

	// Sort by hash
	sort.Slice(hashedNames, func(i, j int) bool {
		return hashedNames[i].hashed < hashedNames[j].hashed
	})

	// Create NSEC3 chain
	for i, hn := range hashedNames {
		nextIdx := (i + 1) % len(hashedNames)
		nextHash := hashedNames[nextIdx].hashed

		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hn.nsec3Name,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    zone.TTL,
			},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: iterations,
			SaltLength: uint8(len(saltBytes)),
			Salt:       salt,
			HashLength: uint8(len(nextHash)),
			NextDomain: nextHash,
			TypeBitMap: hn.typeBits,
		}

		zone.AddNSEC3Record(s.nsec3ToEntity(nsec3))

		// Sign the NSEC3 record
		rrsig, err := s.signRRset([]dns.RR{nsec3}, zskPair.DNSKEY, zskPair.PrivateKey, zoneName, inception, expiration)
		if err != nil {
			return &DNSSECError{
				Op:   "generateNSEC3Chain",
				Zone: zoneName,
				Err:  &WrappedError{Msg: "failed to sign NSEC3 record", Err: err},
			}
		}
		zone.AddRRSIGRecord(s.rrsigToEntity(rrsig))
	}

	// Sign NSEC3PARAM
	rrsig, err := s.signRRset([]dns.RR{nsec3param}, zskPair.DNSKEY, zskPair.PrivateKey, zoneName, inception, expiration)
	if err != nil {
		return &DNSSECError{
			Op:   "generateNSEC3Chain",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to sign NSEC3PARAM record", Err: err},
		}
	}
	zone.AddRRSIGRecord(s.rrsigToEntity(rrsig))

	return nil
}

// calculateExpiration calculates signature expiration based on config.
func (s *DNSSECService) calculateExpiration(inception time.Time) time.Time {
	expiry := s.config.SignatureExpiry
	if expiry == "" {
		expiry = "30d" // Default 30 days
	}

	duration, err := parseDuration(expiry)
	if err != nil {
		duration = 30 * 24 * time.Hour // Fallback to 30 days
	}

	return inception.Add(duration)
}

// Helper function to parse duration strings like "30d", "24h", etc.
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, &MessageError{Msg: fmt.Sprintf("invalid duration: %s", s)}
	}

	unit := s[len(s)-1]
	value := s[:len(s)-1]

	var multiplier time.Duration
	switch unit {
	case 'd', 'D':
		multiplier = 24 * time.Hour
	case 'h', 'H':
		multiplier = time.Hour
	case 'm', 'M':
		multiplier = time.Minute
	case 's', 'S':
		multiplier = time.Second
	default:
		return time.ParseDuration(s)
	}

	var numValue int
	_, err := fmt.Sscanf(value, "%d", &numValue)
	if err != nil {
		return 0, err
	}

	return time.Duration(numValue) * multiplier, nil
}

// keyBitsForAlgorithm returns the appropriate key size for a given algorithm.
func keyBitsForAlgorithm(alg uint8) int {
	switch alg {
	case dns.RSASHA256, dns.RSASHA512:
		return 2048
	case dns.ECDSAP256SHA256:
		return 256
	case dns.ECDSAP384SHA384:
		return 384
	case dns.ED25519:
		return 256
	default:
		return 256
	}
}

// keyConfigToDNSSECAlgorithm converts a KeyConfig to a DNSSEC algorithm number.
// This supports the same key algorithm strings used throughout the platform configuration.
func keyConfigToDNSSECAlgorithm(keyConfig *common.KeyConfig) uint8 {
	if keyConfig == nil {
		return dns.ECDSAP256SHA256 // Default
	}

	// Normalize algorithm string to uppercase
	alg := strings.ToUpper(keyConfig.KeyAlgorithm)

	switch alg {
	case "RSA":
		// Check signature algorithm for RSA variant
		sigAlg := strings.ToUpper(keyConfig.SignatureAlgorithm)
		switch {
		case strings.Contains(sigAlg, "SHA512"), strings.Contains(sigAlg, "SHA-512"):
			return dns.RSASHA512
		default:
			return dns.RSASHA256
		}
	case "ECDSA":
		// Check curve for ECDSA variant
		if keyConfig.ECCConfig != nil {
			curve := strings.ToUpper(keyConfig.ECCConfig.Curve)
			switch curve {
			case "P-384", "P384", "SECP384R1":
				return dns.ECDSAP384SHA384
			default:
				return dns.ECDSAP256SHA256
			}
		}
		return dns.ECDSAP256SHA256
	case "ED25519":
		return dns.ED25519
	default:
		return dns.ECDSAP256SHA256 // Default to ECDSA P-256
	}
}

// getEffectiveKeyConfig returns the key configuration to use for a DNSSEC key.
// It checks the key-specific config first, then falls back to the default key config.
func (s *DNSSECService) getEffectiveKeyConfig(keyConfig *DNSSECKeyConfig) *common.KeyConfig {
	// First, check if the key config has its own key specification
	if keyConfig != nil && keyConfig.Key != nil {
		return keyConfig.Key
	}

	// Fall back to the default key config
	if s.config.DefaultKey != nil {
		return s.config.DefaultKey
	}

	// Return nil to indicate default algorithm should be used
	return nil
}

// getAlgorithm returns the DNSSEC algorithm based on configuration.
// It derives the algorithm from the KeyConfig pattern rather than a numeric value.
func (s *DNSSECService) getAlgorithm() uint8 {
	// Try KSK config first (they should match, but KSK takes precedence)
	if s.config.KSK != nil && s.config.KSK.Key != nil {
		return keyConfigToDNSSECAlgorithm(s.config.KSK.Key)
	}

	// Try ZSK config
	if s.config.ZSK != nil && s.config.ZSK.Key != nil {
		return keyConfigToDNSSECAlgorithm(s.config.ZSK.Key)
	}

	// Try default key config
	if s.config.DefaultKey != nil {
		return keyConfigToDNSSECAlgorithm(s.config.DefaultKey)
	}

	// Default to ECDSA P-256
	return dns.ECDSAP256SHA256
}

// getAlgorithmForZone returns the DNSSEC algorithm for a specific zone.
// Per-zone KeyConfig takes precedence over the global DNSSECConfig.
func (s *DNSSECService) getAlgorithmForZone(zone *entities.Zone) uint8 {
	// Per-zone KSK config takes precedence
	if zone.KSK != nil {
		return keyConfigToDNSSECAlgorithm(zone.KSK)
	}

	// Per-zone ZSK config
	if zone.ZSK != nil {
		return keyConfigToDNSSECAlgorithm(zone.ZSK)
	}

	// Fall back to global config
	return s.getAlgorithm()
}

// Conversion functions from entity types to dns.RR types

func (s *DNSSECService) soaToRR(zoneName string, r *entities.SOARecord) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zoneName),
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
	}
}

func (s *DNSSECService) nsToRR(zoneName string, r *entities.NSRecord) *dns.NS {
	name := s.resolveName(r.Name, zoneName)
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Ns: r.Value,
	}
}

func (s *DNSSECService) aToRR(zoneName string, r *entities.ARecord) *dns.A {
	name := s.resolveName(r.Name, zoneName)
	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		A: net.ParseIP(r.Value),
	}
}

func (s *DNSSECService) aaaaToRR(zoneName string, r *entities.AAAARecord) *dns.AAAA {
	name := s.resolveName(r.Name, zoneName)
	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		AAAA: net.ParseIP(r.Value),
	}
}

func (s *DNSSECService) cnameToRR(zoneName string, r *entities.CNAMERecord) *dns.CNAME {
	name := s.resolveName(r.Name, zoneName)
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Target: r.Value,
	}
}

func (s *DNSSECService) mxToRR(zoneName string, r *entities.MXRecord) *dns.MX {
	name := s.resolveName(r.Name, zoneName)
	return &dns.MX{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeMX,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Preference: r.Priority,
		Mx:         r.Value,
	}
}

func (s *DNSSECService) txtToRR(zoneName string, r *entities.TXTRecord) *dns.TXT {
	name := s.resolveName(r.Name, zoneName)
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Txt: []string{r.Value},
	}
}

func (s *DNSSECService) srvToRR(zoneName string, r *entities.SRVRecord) *dns.SRV {
	name := s.resolveName(r.Name, zoneName)
	return &dns.SRV{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeSRV,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Priority: r.Priority,
		Weight:   r.Weight,
		Port:     r.Port,
		Target:   r.Target,
	}
}

func (s *DNSSECService) caaToRR(zoneName string, r *entities.CAARecord) *dns.CAA {
	name := s.resolveName(r.Name, zoneName)
	return &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Flag:  r.Flags,
		Tag:   r.Tag,
		Value: r.Value,
	}
}

func (s *DNSSECService) tlsaToRR(zoneName string, r *entities.TLSARecord) *dns.TLSA {
	name := s.resolveName(r.Name, zoneName)
	return &dns.TLSA{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTLSA,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Usage:        r.Usage,
		Selector:     r.Selector,
		MatchingType: r.MatchingType,
		Certificate:  r.Data,
	}
}

func (s *DNSSECService) dnskeyToRR(zoneName string, r *entities.DNSKEYRecord) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zoneName),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		Flags:     r.Flags,
		Protocol:  r.Protocol,
		Algorithm: r.Algorithm,
		PublicKey: r.Key,
	}
}

// resolveName resolves a record name to an FQDN.
func (s *DNSSECService) resolveName(name, zoneName string) string {
	if name == "@" || name == "" {
		return dns.Fqdn(zoneName)
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return fmt.Sprintf("%s.%s", name, dns.Fqdn(zoneName))
}

// Conversion functions from dns types to entity types

func (s *DNSSECService) dnsKeyToEntity(key *dns.DNSKEY) *entities.DNSKEYRecord {
	return &entities.DNSKEYRecord{
		Name:      key.Hdr.Name,
		TTL:       key.Hdr.Ttl,
		Flags:     key.Flags,
		Protocol:  key.Protocol,
		Algorithm: key.Algorithm,
		Key:       key.PublicKey,
	}
}

func (s *DNSSECService) dsToEntity(ds *dns.DS) *entities.DSRecord {
	return &entities.DSRecord{
		Name:       ds.Hdr.Name,
		TTL:        ds.Hdr.Ttl,
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
		Digest:     ds.Digest,
	}
}

func (s *DNSSECService) rrsigToEntity(rrsig *dns.RRSIG) *entities.RRSIGRecord {
	return &entities.RRSIGRecord{
		TypeCovered: dns.TypeToString[rrsig.TypeCovered],
		Algorithm:   rrsig.Algorithm,
		Labels:      rrsig.Labels,
		OriginalTTL: rrsig.OrigTtl,
		Expiration:  fmt.Sprintf("%d", rrsig.Expiration),
		Inception:   fmt.Sprintf("%d", rrsig.Inception),
		KeyTag:      rrsig.KeyTag,
		SignerName:  rrsig.SignerName,
		Signature:   base64.StdEncoding.EncodeToString([]byte(rrsig.Signature)),
	}
}

func (s *DNSSECService) nsecToEntity(nsec *dns.NSEC) *entities.NSECRecord {
	return &entities.NSECRecord{
		Name:       nsec.Hdr.Name,
		TTL:        nsec.Hdr.Ttl,
		NextDomain: nsec.NextDomain,
		TypeBitMap: nsec.TypeBitMap,
	}
}

func (s *DNSSECService) nsec3ToEntity(nsec3 *dns.NSEC3) *entities.NSEC3Record {
	return &entities.NSEC3Record{
		Name:       nsec3.Hdr.Name,
		TTL:        nsec3.Hdr.Ttl,
		Algorithm:  nsec3.Hash,
		Flags:      nsec3.Flags,
		Iterations: nsec3.Iterations,
		Salt:       nsec3.Salt,
		NextHashed: nsec3.NextDomain,
		TypeBitMap: nsec3.TypeBitMap,
	}
}

func (s *DNSSECService) nsec3paramToEntity(nsec3param *dns.NSEC3PARAM) *entities.NSEC3PARAMRecord {
	return &entities.NSEC3PARAMRecord{
		Name:       nsec3param.Hdr.Name,
		TTL:        nsec3param.Hdr.Ttl,
		Algorithm:  nsec3param.Hash,
		Flags:      nsec3param.Flags,
		Iterations: nsec3param.Iterations,
		Salt:       nsec3param.Salt,
	}
}

// PrepareKeyRollover generates a new key pair for key rollover preparation via xkms.
// The new key is generated but not activated, allowing for pre-publication.
// The tenantID is used to scope keys to specific tenants.
// Note: Key rollover with XKMS requires deleting the old key and creating a new one,
// or using XKMS-specific versioning capabilities.
func (s *DNSSECService) PrepareKeyRollover(tenantID, zoneName string, keyType string) (*dns.DNSKEY, error) {
	zoneName = dns.Fqdn(zoneName)
	if tenantID == "" {
		return nil, ErrMissingTenantContext
	}

	// Get algorithm from KeyConfig pattern
	algorithm := s.getAlgorithm()

	var kt KeyType
	switch keyType {
	case "ksk":
		kt = KeyTypeKSK
	case "zsk":
		kt = KeyTypeZSK
	default:
		return nil, &DNSSECError{
			Op:   "PrepareKeyRollover",
			Zone: zoneName,
			Err:  ErrInvalidKeyType,
		}
	}

	s.logger.Info("Preparing key rollover via xkms",
		slog.String("tenant", tenantID),
		slog.String("zone", zoneName),
		slog.String("keyType", keyType))

	ctx := context.Background()

	// Delete existing key if present
	if s.keyStore.KeyExists(ctx, tenantID, zoneName, kt) {
		if err := s.keyStore.DeleteKey(ctx, tenantID, zoneName, kt); err != nil {
			s.logger.Warn("Failed to delete existing key during rollover",
				slog.String("tenant", tenantID),
				slog.String("zone", zoneName),
				slog.String("keyType", keyType),
				slog.String("error", err.Error()))
		}
	}

	// Generate new key via xkms
	var key *dns.DNSKEY
	var err error
	if kt == KeyTypeKSK {
		key, err = s.keyStore.GenerateKSK(ctx, tenantID, zoneName, algorithm)
	} else {
		key, err = s.keyStore.GenerateZSK(ctx, tenantID, zoneName, algorithm)
	}
	if err != nil {
		return nil, &DNSSECError{
			Op:   "PrepareKeyRollover",
			Zone: zoneName,
			Err:  &WrappedError{Msg: "failed to generate new key via xkms", Err: err},
		}
	}

	s.logger.Info("Key rollover prepared via xkms",
		slog.String("zone", zoneName),
		slog.String("keyType", keyType),
		slog.Uint64("keyTag", uint64(key.KeyTag())))

	return key, nil
}

// IsEnabled returns true if DNSSEC is enabled in the configuration.
func (s *DNSSECService) IsEnabled() bool {
	return s.config.Enabled
}
