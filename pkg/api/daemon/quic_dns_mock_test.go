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
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// MockDNSService is a configurable mock implementation of the full
// dns.DNSService interface for testing. It allows per-method error injection
// and return value configuration.
//
// It implements the complete dns.DNSService surface (not just the narrow local
// DNSService) so the SDK-mapped QUIC handlers — which delegate to
// NewDNSServiceServer via rebuildDNSGRPC's dns.DNSService type assertion — are
// exercisable with the mock. Save captures the last-saved zone so record/zone
// mutations performed by the delegated gRPC service can be verified.
type MockDNSService struct {
	mu sync.RWMutex

	// Zone operations
	ZoneFunc         func(ctx context.Context, zoneName string) (*entities.Zone, error)
	CreateZoneFunc   func(ctx context.Context, zoneName string) error
	DeleteZoneFunc   func(ctx context.Context, zoneName string) error
	ListZonesFunc    func(ctx context.Context) ([]*entities.Zone, error)
	SaveFunc         func(ctx context.Context, zone *entities.Zone) error
	SaveAndSignFunc  func(ctx context.Context, zone *entities.Zone) error
	DeleteFunc       func(ctx context.Context, zone *entities.Zone) error
	RegisterFunc     func(ctx context.Context, fqdn, ip string) (*entities.Zone, error)
	InternalZoneFunc func(ctx context.Context) (*entities.Zone, error)
	PublicZoneFunc   func(ctx context.Context) (*entities.Zone, error)

	// Record operations
	AddRecordFunc     func(ctx context.Context, name, recordType, value string, ttl int) error
	DeleteRecordFunc  func(ctx context.Context, name, recordType string) error
	GetRecordFunc     func(ctx context.Context, name, recordType string) (interface{}, error)
	ListRecordsFunc   func(ctx context.Context, zoneName string) ([]interface{}, error)
	AddTLSARecordFunc func(ctx context.Context, zoneName string, record *entities.TLSARecord) error

	// DNSSEC
	SignZoneFunc func(zone *entities.Zone) error

	// Resolution / registration
	ResolveFunc                 func(ctx context.Context, name, recordType string) ([]string, error)
	RegisterWithNetworkZoneFunc func(ctx context.Context, host, networkZone, ip string) error

	// Configuration
	InternalDomainValue string
	PublicDomainValue   string
	DNSSECEnabledValue  bool

	// SavedZone captures the most recent zone passed to Save/SaveAndSign so
	// tests can assert on delegated mutations.
	SavedZone *entities.Zone

	// Call tracking for verification
	calls map[string]int
}

// NewMockDNSService creates a new mock DNS service with default behavior.
func NewMockDNSService() *MockDNSService {
	return &MockDNSService{
		calls:               make(map[string]int),
		InternalDomainValue: "internal.example.com.",
		PublicDomainValue:   "example.com.",
		DNSSECEnabledValue:  false,
	}
}

// trackCall records a method call for later verification.
func (m *MockDNSService) trackCall(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[method]++
}

// CallCount returns the number of times a method was called.
func (m *MockDNSService) CallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.calls[method]
}

// ResetCalls resets the call tracking.
func (m *MockDNSService) ResetCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = make(map[string]int)
}

// =============================================================================
// Zone operations
// =============================================================================

// Zone implements dns.DNSService.Zone
func (m *MockDNSService) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {
	m.trackCall("Zone")
	if m.ZoneFunc != nil {
		return m.ZoneFunc(ctx, zoneName)
	}
	return &entities.Zone{
		ID:          1,
		Name:        zoneName,
		TTL:         3600,
		Description: "Test zone",
		Internal:    true,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "test", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}, nil
}

// CreateZone implements dns.DNSService.CreateZone
func (m *MockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	m.trackCall("CreateZone")
	if m.CreateZoneFunc != nil {
		return m.CreateZoneFunc(ctx, zoneName)
	}
	return nil
}

// DeleteZone implements dns.DNSService.DeleteZone
func (m *MockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	m.trackCall("DeleteZone")
	if m.DeleteZoneFunc != nil {
		return m.DeleteZoneFunc(ctx, zoneName)
	}
	return nil
}

// ListZones implements dns.DNSService.ListZones
func (m *MockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	m.trackCall("ListZones")
	if m.ListZonesFunc != nil {
		return m.ListZonesFunc(ctx)
	}
	return []*entities.Zone{
		{
			ID:          1,
			Name:        "example.com.",
			TTL:         3600,
			Description: "Public zone",
			Internal:    false,
			RecordSet: entities.RecordSet{
				ARecords: []*entities.ARecord{
					{Name: "@", Value: "1.2.3.4", TTL: 3600},
				},
			},
		},
		{
			ID:          2,
			Name:        "internal.example.com.",
			TTL:         3600,
			Description: "Internal zone",
			Internal:    true,
			RecordSet: entities.RecordSet{
				ARecords: []*entities.ARecord{
					{Name: "server1", Value: "192.168.1.10", TTL: 3600},
				},
			},
		},
	}, nil
}

// Save implements dns.DNSService.Save
func (m *MockDNSService) Save(ctx context.Context, zone *entities.Zone) error {
	m.trackCall("Save")
	m.mu.Lock()
	m.SavedZone = zone
	m.mu.Unlock()
	if m.SaveFunc != nil {
		return m.SaveFunc(ctx, zone)
	}
	return nil
}

// SaveAndSign implements dns.DNSService.SaveAndSign
func (m *MockDNSService) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	m.trackCall("SaveAndSign")
	m.mu.Lock()
	m.SavedZone = zone
	m.mu.Unlock()
	if m.SaveAndSignFunc != nil {
		return m.SaveAndSignFunc(ctx, zone)
	}
	return nil
}

// Delete implements dns.DNSService.Delete
func (m *MockDNSService) Delete(ctx context.Context, zone *entities.Zone) error {
	m.trackCall("Delete")
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, zone)
	}
	return nil
}

// Register implements dns.DNSService.Register
func (m *MockDNSService) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {
	m.trackCall("Register")
	if m.RegisterFunc != nil {
		return m.RegisterFunc(ctx, fqdn, ip)
	}
	return &entities.Zone{Name: fqdn}, nil
}

// InternalZone implements dns.DNSService.InternalZone
func (m *MockDNSService) InternalZone(ctx context.Context) (*entities.Zone, error) {
	m.trackCall("InternalZone")
	if m.InternalZoneFunc != nil {
		return m.InternalZoneFunc(ctx)
	}
	return &entities.Zone{Name: m.InternalDomainValue, Internal: true}, nil
}

// PublicZone implements dns.DNSService.PublicZone
func (m *MockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	m.trackCall("PublicZone")
	if m.PublicZoneFunc != nil {
		return m.PublicZoneFunc(ctx)
	}
	return &entities.Zone{Name: m.PublicDomainValue, Internal: false}, nil
}

// =============================================================================
// Record operations
// =============================================================================

// AddRecord implements dns.DNSService.AddRecord
func (m *MockDNSService) AddRecord(ctx context.Context, name, recordType, value string, ttl int) error {
	m.trackCall("AddRecord")
	if m.AddRecordFunc != nil {
		return m.AddRecordFunc(ctx, name, recordType, value, ttl)
	}
	return nil
}

// DeleteRecord implements dns.DNSService.DeleteRecord
func (m *MockDNSService) DeleteRecord(ctx context.Context, name, recordType string) error {
	m.trackCall("DeleteRecord")
	if m.DeleteRecordFunc != nil {
		return m.DeleteRecordFunc(ctx, name, recordType)
	}
	return nil
}

// GetRecord implements dns.DNSService.GetRecord
func (m *MockDNSService) GetRecord(ctx context.Context, name, recordType string) (interface{}, error) {
	m.trackCall("GetRecord")
	if m.GetRecordFunc != nil {
		return m.GetRecordFunc(ctx, name, recordType)
	}
	switch recordType {
	case "A":
		return &entities.ARecord{Name: name, Value: "192.168.1.1", TTL: 3600}, nil
	case "AAAA":
		return &entities.AAAARecord{Name: name, Value: "2001:db8::1", TTL: 3600}, nil
	case "CNAME":
		return &entities.CNAMERecord{Name: name, Value: "target.example.com.", TTL: 3600}, nil
	case "TXT":
		return &entities.TXTRecord{Name: name, Value: "test value", TTL: 3600}, nil
	case "MX":
		return &entities.MXRecord{Name: name, Value: "mail.example.com.", Priority: 10, TTL: 3600}, nil
	case "NS":
		return &entities.NSRecord{Name: name, Value: "ns1.example.com.", TTL: 3600}, nil
	default:
		return nil, ErrDNSRecordNotFound{Name: name, RecordType: recordType}
	}
}

// ListRecords implements dns.DNSService.ListRecords
func (m *MockDNSService) ListRecords(ctx context.Context, zoneName string) ([]interface{}, error) {
	m.trackCall("ListRecords")
	if m.ListRecordsFunc != nil {
		return m.ListRecordsFunc(ctx, zoneName)
	}
	return []interface{}{
		&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600},
		&entities.ARecord{Name: "api", Value: "192.168.1.2", TTL: 3600},
		&entities.CNAMERecord{Name: "mail", Value: "mailserver.example.com.", TTL: 3600},
	}, nil
}

// AddTLSARecord implements dns.DNSService.AddTLSARecord
func (m *MockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	m.trackCall("AddTLSARecord")
	if m.AddTLSARecordFunc != nil {
		return m.AddTLSARecordFunc(ctx, zoneName, record)
	}
	return nil
}

// =============================================================================
// DNSSEC operations
// =============================================================================

// SignZone implements dns.DNSService.SignZone
func (m *MockDNSService) SignZone(zone *entities.Zone) error {
	m.trackCall("SignZone")
	if m.SignZoneFunc != nil {
		return m.SignZoneFunc(zone)
	}
	return nil
}

// DNSSECService implements dns.DNSService.DNSSECService
func (m *MockDNSService) DNSSECService() *dns.DNSSECService {
	m.trackCall("DNSSECService")
	return nil
}

// IsDNSSECEnabled implements dns.DNSService.IsDNSSECEnabled
func (m *MockDNSService) IsDNSSECEnabled() bool {
	m.trackCall("IsDNSSECEnabled")
	return m.DNSSECEnabledValue
}

// =============================================================================
// Resolution / registration
// =============================================================================

// Resolve implements dns.DNSService.Resolve
func (m *MockDNSService) Resolve(ctx context.Context, name, recordType string) ([]string, error) {
	m.trackCall("Resolve")
	if m.ResolveFunc != nil {
		return m.ResolveFunc(ctx, name, recordType)
	}
	return []string{"192.168.1.1"}, nil
}

// RegisterWithNetworkZone implements dns.DNSService.RegisterWithNetworkZone
func (m *MockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	m.trackCall("RegisterWithNetworkZone")
	if m.RegisterWithNetworkZoneFunc != nil {
		return m.RegisterWithNetworkZoneFunc(ctx, host, networkZone, ip)
	}
	return nil
}

// =============================================================================
// Domain accessors
// =============================================================================

// InternalDomain implements dns.DNSService.InternalDomain
func (m *MockDNSService) InternalDomain() string {
	m.trackCall("InternalDomain")
	return m.InternalDomainValue
}

// PublicDomain implements dns.DNSService.PublicDomain
func (m *MockDNSService) PublicDomain() string {
	m.trackCall("PublicDomain")
	return m.PublicDomainValue
}

// Compile-time checks: the mock implements BOTH the narrow local DNSService
// (used by daemon-native handlers) and the full dns.DNSService (required by
// rebuildDNSGRPC's type assertion into NewDNSServiceServer).
var (
	_ DNSService     = (*MockDNSService)(nil)
	_ dns.DNSService = (*MockDNSService)(nil)
)
