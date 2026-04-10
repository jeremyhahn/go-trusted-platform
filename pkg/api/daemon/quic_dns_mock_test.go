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

//go:build codec_msgpack

package daemon

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// MockDNSService is a configurable mock implementation of DNSService for testing.
// It allows per-method error injection and return value configuration.
type MockDNSService struct {
	mu sync.RWMutex

	// Zone operations
	ZoneFunc       func(ctx context.Context, zoneName string) (*entities.Zone, error)
	CreateZoneFunc func(ctx context.Context, zoneName string) error
	DeleteZoneFunc func(ctx context.Context, zoneName string) error
	ListZonesFunc  func(ctx context.Context) ([]*entities.Zone, error)

	// Record operations
	AddRecordFunc    func(ctx context.Context, name, recordType, value string, ttl int) error
	DeleteRecordFunc func(ctx context.Context, name, recordType string) error
	GetRecordFunc    func(ctx context.Context, name, recordType string) (interface{}, error)
	ListRecordsFunc  func(ctx context.Context, zoneName string) ([]interface{}, error)

	// Resolution
	ResolveFunc func(ctx context.Context, name, recordType string) ([]string, error)

	// Configuration
	InternalDomainValue string
	PublicDomainValue   string
	DNSSECEnabledValue  bool

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

// Zone implements DNSService.Zone
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

// CreateZone implements DNSService.CreateZone
func (m *MockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	m.trackCall("CreateZone")
	if m.CreateZoneFunc != nil {
		return m.CreateZoneFunc(ctx, zoneName)
	}
	return nil
}

// DeleteZone implements DNSService.DeleteZone
func (m *MockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	m.trackCall("DeleteZone")
	if m.DeleteZoneFunc != nil {
		return m.DeleteZoneFunc(ctx, zoneName)
	}
	return nil
}

// ListZones implements DNSService.ListZones
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

// AddRecord implements DNSService.AddRecord
func (m *MockDNSService) AddRecord(ctx context.Context, name, recordType, value string, ttl int) error {
	m.trackCall("AddRecord")
	if m.AddRecordFunc != nil {
		return m.AddRecordFunc(ctx, name, recordType, value, ttl)
	}
	return nil
}

// DeleteRecord implements DNSService.DeleteRecord
func (m *MockDNSService) DeleteRecord(ctx context.Context, name, recordType string) error {
	m.trackCall("DeleteRecord")
	if m.DeleteRecordFunc != nil {
		return m.DeleteRecordFunc(ctx, name, recordType)
	}
	return nil
}

// GetRecord implements DNSService.GetRecord
func (m *MockDNSService) GetRecord(ctx context.Context, name, recordType string) (interface{}, error) {
	m.trackCall("GetRecord")
	if m.GetRecordFunc != nil {
		return m.GetRecordFunc(ctx, name, recordType)
	}
	// Return a default record based on type
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

// ListRecords implements DNSService.ListRecords
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

// Resolve implements DNSService.Resolve
func (m *MockDNSService) Resolve(ctx context.Context, name, recordType string) ([]string, error) {
	m.trackCall("Resolve")
	if m.ResolveFunc != nil {
		return m.ResolveFunc(ctx, name, recordType)
	}
	return []string{"192.168.1.1"}, nil
}

// InternalDomain implements DNSService.InternalDomain
func (m *MockDNSService) InternalDomain() string {
	m.trackCall("InternalDomain")
	return m.InternalDomainValue
}

// PublicDomain implements DNSService.PublicDomain
func (m *MockDNSService) PublicDomain() string {
	m.trackCall("PublicDomain")
	return m.PublicDomainValue
}

// IsDNSSECEnabled implements DNSService.IsDNSSECEnabled
func (m *MockDNSService) IsDNSSECEnabled() bool {
	m.trackCall("IsDNSSECEnabled")
	return m.DNSSECEnabledValue
}

// Ensure MockDNSService implements DNSService at compile time
var _ DNSService = (*MockDNSService)(nil)
