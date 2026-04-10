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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DNSService defines the interface for DNS operations used by QUIC handlers.
// This interface allows for mocking in unit tests while maintaining full
// compatibility with the concrete dns.Service implementation.
type DNSService interface {
	// Zone operations
	Zone(ctx context.Context, zoneName string) (*entities.Zone, error)
	CreateZone(ctx context.Context, zoneName string) error
	DeleteZone(ctx context.Context, zoneName string) error
	ListZones(ctx context.Context) ([]*entities.Zone, error)

	// Record operations
	AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error
	DeleteRecord(ctx context.Context, name string, recordType string) error
	GetRecord(ctx context.Context, name string, recordType string) (interface{}, error)
	ListRecords(ctx context.Context, zoneName string) ([]interface{}, error)

	// Resolution
	Resolve(ctx context.Context, name string, recordType string) ([]string, error)

	// Configuration
	InternalDomain() string
	PublicDomain() string
	IsDNSSECEnabled() bool
}
