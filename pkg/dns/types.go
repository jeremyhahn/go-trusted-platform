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

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DNSService defines the interface for DNS zone and record operations.
// All API handlers (gRPC, REST) MUST use this interface to access DNS
// functionality, ensuring proper abstraction and separation of concerns.
type DNSService interface {
	// Zone operations

	// Save saves a zone to the datastore. If DNSSEC is enabled, the zone
	// is automatically signed before saving.
	Save(ctx context.Context, zone *entities.Zone) error

	// SaveAndSign saves a zone to the datastore after signing it with DNSSEC
	// if enabled. If DNSSEC is not enabled, the zone is saved without signing.
	SaveAndSign(ctx context.Context, zone *entities.Zone) error

	// SignZone signs a zone with DNSSEC. Returns an error if DNSSEC is not enabled.
	SignZone(zone *entities.Zone) error

	// Delete deletes a zone from the datastore.
	Delete(ctx context.Context, zone *entities.Zone) error

	// Zone retrieves a zone from the datastore by name.
	Zone(ctx context.Context, zoneName string) (*entities.Zone, error)

	// ListZones retrieves all zones from the datastore.
	ListZones(ctx context.Context) ([]*entities.Zone, error)

	// Register creates a new DNS record or zone based on the provided FQDN
	// and platform configuration.
	Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error)

	// AddTLSARecord adds a TLSA record to the specified DNS zone.
	AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error

	// InternalZone returns the internal DNS zone configured for the platform.
	InternalZone(ctx context.Context) (*entities.Zone, error)

	// PublicZone returns the public DNS zone configured for the platform.
	PublicZone(ctx context.Context) (*entities.Zone, error)

	// Domain accessors

	// InternalDomain returns the internal domain name.
	InternalDomain() string

	// PublicDomain returns the public domain name.
	PublicDomain() string

	// DNSSEC operations

	// DNSSECService returns the DNSSEC service if configured, nil otherwise.
	DNSSECService() *DNSSECService

	// IsDNSSECEnabled returns true if DNSSEC is enabled for the service.
	IsDNSSECEnabled() bool

	// Convenience methods for API handlers

	// CreateZone creates a new zone with the specified name.
	CreateZone(ctx context.Context, zoneName string) error

	// DeleteZone deletes a zone by name.
	DeleteZone(ctx context.Context, zoneName string) error

	// AddRecord adds a DNS record to the appropriate zone.
	AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error

	// DeleteRecord deletes a DNS record from the appropriate zone.
	DeleteRecord(ctx context.Context, name string, recordType string) error

	// GetRecord retrieves a DNS record by name and type.
	GetRecord(ctx context.Context, name string, recordType string) (interface{}, error)

	// ListRecords lists all records in a zone.
	ListRecords(ctx context.Context, zone string) ([]interface{}, error)

	// Resolve resolves a DNS name to its values.
	Resolve(ctx context.Context, name string, recordType string) ([]string, error)

	// RegisterWithNetworkZone registers a device hostname under its network
	// zone subdomain when zone_subdomains is enabled. The zone-qualified FQDN
	// <host>.<networkZone>.<domain> is registered IN ADDITION to the standard
	// <host>.<domain> entry. BMC names are never zone-qualified. No-op when
	// zone_subdomains is false or networkZone is empty.
	RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error
}

// Ensure Service implements DNSService interface at compile time.
var _ DNSService = (*Service)(nil)
