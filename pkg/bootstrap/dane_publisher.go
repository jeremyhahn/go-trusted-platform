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

package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"

	dane "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/dane"

	dnsconfig "github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// DANEDNSService is the subset of dns.DNSService that DANEPublisher requires.
// This follows the Go interface segregation principle: accept the narrowest
// interface that satisfies the caller's needs.
type DANEDNSService interface {
	AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error
	SaveAndSign(ctx context.Context, zone *entities.Zone) error
	Zone(ctx context.Context, zoneName string) (*entities.Zone, error)
}

// DANEPublisher publishes DANE TLSA records to the platform's DNS service.
// It computes TLSA record data from X.509 certificates using the stack's
// canonical DANE primitives (owned by go-xkms, reached through the QuicBaaS
// SDK) and manages record lifecycle including rollover.
type DANEPublisher struct {
	dnsService DANEDNSService
	config     *dnsconfig.DANEConfig
	logger     *logging.Logger
}

// NewDANEPublisher creates a new DANEPublisher with the given DNS service,
// DANE configuration, and logger.
func NewDANEPublisher(
	dnsService DANEDNSService,
	config *dnsconfig.DANEConfig,
	logger *logging.Logger,
) *DANEPublisher {

	return &DANEPublisher{
		dnsService: dnsService,
		config:     config,
		logger:     logger,
	}
}

// PublishForCertificate publishes DANE TLSA records for the given leaf and CA
// certificates. A DANE-TA (Usage=2) record is always published using the CA
// certificate. If PublishDANEEE is enabled in the configuration, a DANE-EE
// (Usage=3) record is also published using the leaf certificate. After adding
// all records, the zone is saved and re-signed with DNSSEC.
func (p *DANEPublisher) PublishForCertificate(
	ctx context.Context,
	leafCert, caCert *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	if caCert == nil {
		return ErrCABundleEmpty{}
	}

	name := tlsaRecordName(hostname, port)

	// Publish DANE-TA (Usage=2) using the CA certificate.
	if err := p.publishRecord(ctx, caCert, name, dane.UsageDANETA, zoneName); err != nil {
		return err
	}

	// Optionally publish DANE-EE (Usage=3) using the leaf certificate.
	if p.config.PublishDANEEE {
		if leafCert == nil {
			return ErrTLSAComputeFailed{
				CN:    hostname,
				Cause: dane.ErrInvalidCertificate,
			}
		}
		if err := p.publishRecord(ctx, leafCert, name, dane.UsageDANEEE, zoneName); err != nil {
			return err
		}
	}

	// Re-sign the DNSSEC zone after adding records.
	zone, err := p.dnsService.Zone(ctx, zoneName)
	if err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}
	if err := p.dnsService.SaveAndSign(ctx, zone); err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}

	p.logger.Info(
		"DANE TLSA records published",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
		slog.Bool("dane_ee", p.config.PublishDANEEE),
	)

	return nil
}

// RemoveForHostname removes all TLSA records matching the given hostname and
// port from the specified DNS zone. After removal, the zone is saved and
// re-signed with DNSSEC.
func (p *DANEPublisher) RemoveForHostname(
	ctx context.Context,
	hostname string,
	port uint16,
	zoneName string,
) error {

	removeAll := func(*entities.TLSARecord) bool { return true }
	return p.removeTLSA(ctx, hostname, port, zoneName, removeAll)
}

// retireForHostname removes every TLSA record for hostname:port except one
// DANE-EE record for current, the certificate now being served. It ends an
// RFC 7671 §8.1 rollover: the old records go, the pre-published one stays.
func (p *DANEPublisher) retireForHostname(
	ctx context.Context,
	current *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	keep, err := p.rolloverRecord(current, hostname, port)
	if err != nil {
		return err
	}
	kept := false
	remove := func(record *entities.TLSARecord) bool {
		if !kept && sameTLSAData(record, keep) {
			kept = true
			return false
		}
		return true
	}
	return p.removeTLSA(ctx, hostname, port, zoneName, remove)
}

// withdrawRollover removes the DANE-EE record PrePublishRollover published for
// newCert, leaving every other record for hostname:port in place. It undoes a
// rollover whose new certificate could not be activated.
func (p *DANEPublisher) withdrawRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	withdrawn, err := p.rolloverRecord(newCert, hostname, port)
	if err != nil {
		return err
	}
	remove := func(record *entities.TLSARecord) bool {
		return sameTLSAData(record, withdrawn)
	}
	return p.removeTLSA(ctx, hostname, port, zoneName, remove)
}

// removeTLSA removes the TLSA records for hostname:port for which remove
// returns true, then re-signs the zone.
func (p *DANEPublisher) removeTLSA(
	ctx context.Context,
	hostname string,
	port uint16,
	zoneName string,
	remove func(*entities.TLSARecord) bool,
) error {

	zone, err := p.dnsService.Zone(ctx, zoneName)
	if err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}

	name := tlsaRecordName(hostname, port)

	// The entity RemoveTLSARecord only removes the first match, so filter the
	// entire slice instead.
	filtered := make([]*entities.TLSARecord, 0, len(zone.RecordSet.TLSARecords))
	for _, record := range zone.RecordSet.TLSARecords {
		if record.Name != name || !remove(record) {
			filtered = append(filtered, record)
		}
	}
	zone.SetTLSARecords(filtered)

	if err := p.dnsService.SaveAndSign(ctx, zone); err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}

	p.logger.Info(
		"DANE TLSA records removed",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
	)

	return nil
}

// sameTLSAData reports whether two TLSA records carry the same association.
func sameTLSAData(a, b *entities.TLSARecord) bool {
	return a.Usage == b.Usage &&
		a.Selector == b.Selector &&
		a.MatchingType == b.MatchingType &&
		a.Data == b.Data
}

// PrePublishRollover adds a new DANE-EE TLSA record for the new certificate
// alongside any existing records. This implements the RFC 7671 pre-publication
// rollover pattern where both old and new records coexist during the transition
// period. The RolloverTTL from configuration is used if set; otherwise the TTL
// defaults to 2x DefaultTTL.
func (p *DANEPublisher) PrePublishRollover(
	ctx context.Context,
	newCert *x509.Certificate,
	hostname string,
	port uint16,
	zoneName string,
) error {

	record, err := p.rolloverRecord(newCert, hostname, port)
	if err != nil {
		return err
	}

	if err := p.addRecord(ctx, zoneName, record); err != nil {
		return err
	}

	zone, err := p.dnsService.Zone(ctx, zoneName)
	if err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}
	if err := p.dnsService.SaveAndSign(ctx, zone); err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}

	p.logger.Info(
		"DANE TLSA rollover record pre-published",
		slog.String("hostname", hostname),
		slog.Int("port", int(port)),
		slog.String("zone", zoneName),
		slog.Uint64("ttl", uint64(record.TTL)),
	)

	return nil
}

// rolloverRecord derives the DANE-EE record PrePublishRollover publishes for
// cert at hostname:port.
func (p *DANEPublisher) rolloverRecord(
	cert *x509.Certificate,
	hostname string,
	port uint16,
) (*entities.TLSARecord, error) {

	if cert == nil {
		return nil, ErrTLSAComputeFailed{
			CN:    hostname,
			Cause: dane.ErrInvalidCertificate,
		}
	}

	data, err := dane.ComputeTLSAData(
		cert, p.config.DefaultSelector, p.config.DefaultMatchingType)
	if err != nil {
		return nil, ErrTLSAComputeFailed{CN: hostname, Cause: err}
	}

	return &entities.TLSARecord{
		Name:         tlsaRecordName(hostname, port),
		Usage:        dane.UsageDANEEE,
		Selector:     p.config.DefaultSelector,
		MatchingType: p.config.DefaultMatchingType,
		Data:         hex.EncodeToString(data),
		TTL:          p.rolloverTTL(),
	}, nil
}

// publishRecord computes TLSA data for the given certificate and publishes it
// as a TLSA record with the specified usage to the DNS zone. The DNS write
// itself is delegated to addRecord so there is a single TLSA-write path
// shared with the SDK-registered publisher.
func (p *DANEPublisher) publishRecord(
	ctx context.Context,
	cert *x509.Certificate,
	name string,
	usage uint8,
	zoneName string,
) error {

	data, err := dane.ComputeTLSAData(
		cert, p.config.DefaultSelector, p.config.DefaultMatchingType)
	if err != nil {
		return ErrTLSAComputeFailed{CN: cert.Subject.CommonName, Cause: err}
	}

	record := &entities.TLSARecord{
		Name:         name,
		Usage:        usage,
		Selector:     p.config.DefaultSelector,
		MatchingType: p.config.DefaultMatchingType,
		Data:         hex.EncodeToString(data),
		TTL:          p.config.DefaultTTL,
	}

	return p.addRecord(ctx, zoneName, record)
}

// addRecord writes a single pre-derived TLSA record to the DNS zone. It is the
// single low-level TLSA write used by every publish path in this package
// (cert-deriving and SDK-registered alike).
func (p *DANEPublisher) addRecord(
	ctx context.Context,
	zoneName string,
	record *entities.TLSARecord,
) error {

	if err := p.dnsService.AddTLSARecord(ctx, zoneName, record); err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}
	return nil
}

// PublishRecords writes a set of already-derived TLSA records to the given DNS
// zone and re-signs the zone with DNSSEC. It performs NO cert→TLSA derivation:
// the records are taken as authoritative. This is the canonical write path used
// by the SDK-registered DANE publisher, whose records are derived server-side by
// go-quicbaas before the publisher is invoked. It returns ErrDANEPublishFailed
// if any record write, zone lookup, or re-sign fails.
func (p *DANEPublisher) PublishRecords(
	ctx context.Context,
	zoneName string,
	records []*entities.TLSARecord,
) error {

	if len(records) == 0 {
		return nil
	}

	for _, record := range records {
		if err := p.addRecord(ctx, zoneName, record); err != nil {
			return err
		}
	}

	zone, err := p.dnsService.Zone(ctx, zoneName)
	if err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}
	if err := p.dnsService.SaveAndSign(ctx, zone); err != nil {
		return ErrDANEPublishFailed{Zone: zoneName, Cause: err}
	}

	p.logger.Info(
		"DANE TLSA records published",
		slog.String("zone", zoneName),
		slog.Int("records", len(records)),
	)

	return nil
}

// rolloverTTL returns the TTL to use for rollover records. If RolloverTTL is
// configured and non-zero, it is used directly. Otherwise, 2x DefaultTTL is
// returned to ensure DNS caches have time to expire.
func (p *DANEPublisher) rolloverTTL() uint32 {
	if p.config.RolloverTTL > 0 {
		return p.config.RolloverTTL
	}
	return 2 * p.config.DefaultTTL
}

// tlsaRecordName returns the TLSA DNS record name for the given hostname and
// port per RFC 6698: _<port>._tcp.<hostname>.
func tlsaRecordName(hostname string, port uint16) string {
	return fmt.Sprintf("_%d._tcp.%s.", port, hostname)
}
