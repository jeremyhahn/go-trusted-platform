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

package quicbaas

import (
	"context"
	"sync/atomic"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmsdane "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/dane"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DANERecordWriter writes a set of already-derived TLSA records to a DNS zone
// and re-signs the zone with DNSSEC. It is satisfied by bootstrap.DANEPublisher
// (its PublishRecords method). The adapter depends on this narrow interface
// rather than the concrete publisher to avoid an import cycle
// (bootstrap -> dns -> storage/quicbaas).
type DANERecordWriter interface {
	PublishRecords(ctx context.Context, zoneName string, records []*entities.TLSARecord) error
}

// ErrDANEPublisherNotAvailable indicates the platform DNS-backed DANE publisher
// has not been wired yet. This happens when the embedded QuicBaaS server
// dispatches a PublishDANE call before the platform DNS service has been
// initialized (the DNS service is created lazily by the service registry).
type ErrDANEPublisherNotAvailable struct{}

// Error implements the error interface.
func (ErrDANEPublisherNotAvailable) Error() string {
	return "DANE publisher not available (platform DNS service has not been initialized yet)"
}

// ErrDANEZoneUnresolved indicates the target DNS zone for a TLSA record could
// not be resolved from the record owner name.
type ErrDANEZoneUnresolved struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e ErrDANEZoneUnresolved) Error() string {
	if e.Cause != nil {
		return "DANE zone unresolved for record " + e.Name + ": " + e.Cause.Error()
	}
	return "DANE zone unresolved for record " + e.Name
}

// Unwrap exposes the underlying cause for errors.Is/As.
func (e ErrDANEZoneUnresolved) Unwrap() error { return e.Cause }

// DANEZoneResolver resolves the authoritative DNS zone that owns the supplied
// TLSA record owner name (e.g. "_443._tcp.host.example.com."). It returns a
// typed error when no matching zone exists. The platform supplies this so the
// adapter does not have to duplicate the App's zone-matching logic.
type DANEZoneResolver func(tlsaName string) (string, error)

// DANEPublisherBackend supplies the live, DNS-backed bootstrap.DANEPublisher
// and a zone resolver. It is consulted on every PublishDANE call so the
// embedded QuicBaaS server can be wired with the adapter at construction time
// (before the platform DNS service exists) and start dispatching the moment the
// backend becomes available. A nil return value (for either the publisher or
// the resolver) signals "not yet wired".
type DANEPublisherBackend func() (DANERecordWriter, DANEZoneResolver)

// DANEPublisherAdapter satisfies the quicbaas SDK DANEPublisher contract by
// translating the SDK's pre-derived dane.Record set into platform
// entities.TLSARecord values and writing them through the platform's single
// DNS-write path (bootstrap.DANEPublisher.PublishRecords), which re-signs the
// zone with DNSSEC.
//
// It performs NO cert→TLSA derivation: go-quicbaas derives the TLSA records
// server-side via dane.BuildRecords before invoking PublishDANE. The adapter
// only writes them. This is the single SDK-registered DANE publisher; the
// cert-deriving bootstrap.DANEPublisher methods (used by the platform's own
// rollover/issuance flows) share the same underlying write path.
//
// Thread-safe: the backend is read via atomic load on every call so SetBackend
// can run concurrently with in-flight publishes.
type DANEPublisherAdapter struct {
	backend atomic.Pointer[DANEPublisherBackend]
}

// Compile-time check that the adapter satisfies the SDK interface.
var _ quicbaassdk.DANEPublisher = (*DANEPublisherAdapter)(nil)

// NewDANEPublisherAdapter constructs an adapter bound to the supplied backend.
// Passing a nil backend is allowed and yields ErrDANEPublisherNotAvailable on
// every PublishDANE call until SetBackend installs one.
func NewDANEPublisherAdapter(backend DANEPublisherBackend) *DANEPublisherAdapter {
	a := &DANEPublisherAdapter{}
	if backend != nil {
		a.backend.Store(&backend)
	}
	return a
}

// SetBackend atomically swaps the backend used to resolve the live publisher
// and zone resolver. Passing nil clears it so subsequent calls return
// ErrDANEPublisherNotAvailable.
func (a *DANEPublisherAdapter) SetBackend(backend DANEPublisherBackend) {
	if a == nil {
		return
	}
	if backend == nil {
		a.backend.Store(nil)
		return
	}
	a.backend.Store(&backend)
}

// resolve fetches the current publisher and zone resolver, returning a typed
// error when the backend is unset or not yet wired.
func (a *DANEPublisherAdapter) resolve() (DANERecordWriter, DANEZoneResolver, error) {
	if a == nil {
		return nil, nil, ErrDANEPublisherNotAvailable{}
	}
	ptr := a.backend.Load()
	if ptr == nil {
		return nil, nil, ErrDANEPublisherNotAvailable{}
	}
	backend := *ptr
	if backend == nil {
		return nil, nil, ErrDANEPublisherNotAvailable{}
	}
	publisher, resolver := backend()
	if publisher == nil || resolver == nil {
		return nil, nil, ErrDANEPublisherNotAvailable{}
	}
	return publisher, resolver, nil
}

// PublishDANE writes the supplied SDK-derived TLSA records to the platform DNS
// service, grouping them by resolved zone so each affected zone is re-signed
// exactly once. It is the implementation registered with the embedded QuicBaaS
// server via WithDANEPublisher.
func (a *DANEPublisherAdapter) PublishDANE(ctx context.Context, records []xkmsdane.Record) error {
	if len(records) == 0 {
		return nil
	}

	publisher, resolver, err := a.resolve()
	if err != nil {
		return err
	}

	// Group records by their resolved zone so PublishRecords (which re-signs
	// the zone once) runs a single DNSSEC re-sign per zone even when a single
	// PublishDANE call spans multiple records.
	byZone := make(map[string][]*entities.TLSARecord)
	order := make([]string, 0)
	for i := range records {
		rec := records[i]
		zone, zerr := resolver(rec.Name)
		if zerr != nil {
			return ErrDANEZoneUnresolved{Name: rec.Name, Cause: zerr}
		}
		if _, seen := byZone[zone]; !seen {
			order = append(order, zone)
		}
		byZone[zone] = append(byZone[zone], toTLSARecord(rec))
	}

	for _, zone := range order {
		if err := publisher.PublishRecords(ctx, zone, byZone[zone]); err != nil {
			return err
		}
	}
	return nil
}

// toTLSARecord maps a pre-derived SDK dane.Record onto the platform's native
// entities.TLSARecord. No derivation occurs: the (Usage, Selector,
// MatchingType, Data) RDATA is taken verbatim from the SDK record.
func toTLSARecord(r xkmsdane.Record) *entities.TLSARecord {
	return &entities.TLSARecord{
		Name:         r.Name,
		Usage:        r.Usage,
		Selector:     r.Selector,
		MatchingType: r.MatchingType,
		Data:         r.Data,
		TTL:          r.TTL,
	}
}
