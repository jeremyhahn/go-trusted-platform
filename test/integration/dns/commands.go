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

//go:build integration

package dns

import (
	"context"
	"time"
)

// DNSCommands defines the central command set for DNS integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Socket) implements this interface.
// Tests are written once against this interface and run against all protocols.
type DNSCommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// Zone Management Commands (platformctl dns zone ...)
	CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error)
	GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error)
	UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error)
	DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error)
	ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error)

	// Record Management Commands (platformctl dns record ...)
	AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error)
	GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error)
	UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error)
	DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error)
	ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error)

	// Resolution Commands (platformctl dns resolve ...)
	Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error)

	// TLSA/DANE Commands (platformctl dns tlsa ...)
	AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error)
}

// =============================================================================
// Zone Management Options and Results
// =============================================================================

// CreateZoneOptions contains options for creating a new DNS zone.
type CreateZoneOptions struct {
	Name        string
	TTL         uint32
	Description string
	Internal    bool
	SOA         *SOARecordOptions
}

// SOARecordOptions contains options for an SOA record.
type SOARecordOptions struct {
	MName      string
	RName      string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinimumTTL uint32
}

// CreateZoneResult contains the result of a zone creation operation.
type CreateZoneResult struct {
	Name      string
	ID        string
	TTL       uint32
	Internal  bool
	CreatedAt time.Time
}

// GetZoneResult contains the result of a zone retrieval operation.
type GetZoneResult struct {
	Name        string
	ID          string
	TTL         uint32
	Description string
	Internal    bool
	SOA         *SOARecordInfo
	RecordCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SOARecordInfo contains SOA record information.
type SOARecordInfo struct {
	Name       string
	MName      string
	RName      string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinimumTTL uint32
	TTL        uint32
}

// UpdateZoneOptions contains options for updating a zone.
type UpdateZoneOptions struct {
	TTL         uint32
	Description string
}

// UpdateZoneResult contains the result of a zone update operation.
type UpdateZoneResult struct {
	Name      string
	TTL       uint32
	UpdatedAt time.Time
}

// DeleteZoneResult contains the result of a zone deletion operation.
type DeleteZoneResult struct {
	Name    string
	Deleted bool
}

// ListZonesOptions contains options for listing zones.
type ListZonesOptions struct {
	Limit    int32
	Cursor   string
	Internal *bool
}

// ListZonesResult contains the result of a zone list operation.
type ListZonesResult struct {
	Zones      []ZoneSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// ZoneSummary contains summary information about a zone.
type ZoneSummary struct {
	Name        string
	ID          string
	TTL         uint32
	Internal    bool
	RecordCount int
	CreatedAt   time.Time
}

// =============================================================================
// Record Management Options and Results
// =============================================================================

// AddRecordOptions contains options for adding a DNS record.
type AddRecordOptions struct {
	ZoneName   string
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	Priority   uint16 // For MX records
	Weight     uint16 // For SRV records
	Port       uint16 // For SRV records
}

// AddRecordResult contains the result of a record addition operation.
type AddRecordResult struct {
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	CreatedAt  time.Time
}

// GetRecordResult contains the result of a record retrieval operation.
type GetRecordResult struct {
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	Priority   uint16
	Weight     uint16
	Port       uint16
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UpdateRecordOptions contains options for updating a DNS record.
type UpdateRecordOptions struct {
	ZoneName   string
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	Priority   uint16
	Weight     uint16
	Port       uint16
}

// UpdateRecordResult contains the result of a record update operation.
type UpdateRecordResult struct {
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	UpdatedAt  time.Time
}

// DeleteRecordResult contains the result of a record deletion operation.
type DeleteRecordResult struct {
	Name       string
	RecordType string
	Deleted    bool
}

// ListRecordsOptions contains options for listing records.
type ListRecordsOptions struct {
	RecordType string
	Limit      int32
	Cursor     string
}

// ListRecordsResult contains the result of a record list operation.
type ListRecordsResult struct {
	Records    []RecordSummary
	TotalCount int32
	HasMore    bool
	NextCursor string
}

// RecordSummary contains summary information about a record.
type RecordSummary struct {
	Name       string
	RecordType string
	Value      string
	TTL        uint32
	Priority   uint16
}

// =============================================================================
// Resolution Options and Results
// =============================================================================

// ResolveResult contains the result of a DNS resolution operation.
type ResolveResult struct {
	Name       string
	RecordType string
	Values     []string
	TTL        uint32
	Timestamp  time.Time
}

// =============================================================================
// TLSA/DANE Options and Results
// =============================================================================

// AddTLSARecordOptions contains options for adding a TLSA record.
type AddTLSARecordOptions struct {
	ZoneName     string
	Name         string
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         string
	TTL          uint32
}

// AddTLSARecordResult contains the result of a TLSA record addition.
type AddTLSARecordResult struct {
	Name         string
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Data         string
	TTL          uint32
	CreatedAt    time.Time
}
