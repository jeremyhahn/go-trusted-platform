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

package mocks

import (
	"context"
	"errors"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

var (
	// ErrZoneNotFound is returned when a zone is not found.
	ErrZoneNotFound = errors.New("mock: zone not found")
	// ErrMockSave is returned when SaveFunc is configured to fail.
	ErrMockSave = errors.New("mock: save error")
	// ErrMockDelete is returned when DeleteFunc is configured to fail.
	ErrMockDelete = errors.New("mock: delete error")
	// ErrMockGet is returned when GetFunc is configured to fail.
	ErrMockGet = errors.New("mock: get error")
)

// MockZoneDAO is a mock implementation of dao.ZoneDAO for testing.
// It provides configurable behavior through function hooks and maintains
// an in-memory store for zones.
type MockZoneDAO struct {
	mu          sync.RWMutex
	zones       map[uint64]*entities.Zone
	zonesByName map[string]*entities.Zone

	// SaveFunc allows custom save behavior for testing error scenarios.
	SaveFunc func(ctx context.Context, zone *entities.Zone) error
	// GetFunc allows custom get behavior for testing error scenarios.
	GetFunc func(ctx context.Context, id uint64) (*entities.Zone, error)
	// GetByNameFunc allows custom get-by-name behavior for testing.
	GetByNameFunc func(ctx context.Context, name string) (*entities.Zone, error)
	// DeleteFunc allows custom delete behavior for testing error scenarios.
	DeleteFunc func(ctx context.Context, zone *entities.Zone) error
	// CountFunc allows custom count behavior for testing.
	CountFunc func(ctx context.Context) (int, error)
	// PageFunc allows custom pagination behavior for testing.
	PageFunc func(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Zone], error)
	// ForEachPageFunc allows custom iteration behavior for testing.
	ForEachPageFunc func(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.Zone]) error
}

// NewMockZoneDAO creates a new mock ZoneDAO with initialized maps.
func NewMockZoneDAO() *MockZoneDAO {
	return &MockZoneDAO{
		zones:       make(map[uint64]*entities.Zone),
		zonesByName: make(map[string]*entities.Zone),
	}
}

// Save persists a zone to the mock store.
func (m *MockZoneDAO) Save(ctx context.Context, zone *entities.Zone) error {
	if m.SaveFunc != nil {
		return m.SaveFunc(ctx, zone)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones[zone.ID] = zone
	m.zonesByName[zone.Name] = zone
	return nil
}

// Get retrieves a zone by ID.
func (m *MockZoneDAO) Get(ctx context.Context, id uint64) (*entities.Zone, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, id)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zone, ok := m.zones[id]; ok {
		return zone, nil
	}
	return nil, ErrZoneNotFound
}

// GetByName retrieves a zone by name.
func (m *MockZoneDAO) GetByName(ctx context.Context, name string) (*entities.Zone, error) {
	if m.GetByNameFunc != nil {
		return m.GetByNameFunc(ctx, name)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if zone, ok := m.zonesByName[name]; ok {
		return zone, nil
	}
	return nil, ErrZoneNotFound
}

// Delete removes a zone from the mock store.
func (m *MockZoneDAO) Delete(ctx context.Context, zone *entities.Zone) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, zone)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.zones, zone.ID)
	delete(m.zonesByName, zone.Name)
	return nil
}

// Count returns the number of zones in the mock store.
func (m *MockZoneDAO) Count(ctx context.Context) (int, error) {
	if m.CountFunc != nil {
		return m.CountFunc(ctx)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.zones), nil
}

// Page returns a paginated result of zones.
func (m *MockZoneDAO) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Zone], error) {
	if m.PageFunc != nil {
		return m.PageFunc(ctx, query)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := datastore.NewPageResultFromQuery[*entities.Zone](query)
	result.Total = len(m.zones)

	// Collect all zones into a slice
	allZones := make([]*entities.Zone, 0, len(m.zones))
	for _, zone := range m.zones {
		allZones = append(allZones, zone)
	}

	// Calculate pagination bounds
	start := (query.Page - 1) * query.PageSize
	if start >= len(allZones) {
		return result, nil
	}

	end := start + query.PageSize
	if end > len(allZones) {
		end = len(allZones)
	}

	result.Entities = allZones[start:end]
	result.HasMore = end < len(allZones)

	return result, nil
}

// ForEachPage iterates over all zones page by page.
func (m *MockZoneDAO) ForEachPage(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.Zone]) error {
	if m.ForEachPageFunc != nil {
		return m.ForEachPageFunc(ctx, query, fn)
	}

	currentQuery := query
	for {
		result, err := m.Page(ctx, currentQuery)
		if err != nil {
			return err
		}

		if err := fn(result); err != nil {
			if errors.Is(err, datastore.ErrStopIteration) {
				return nil
			}
			return err
		}

		if !result.HasMore {
			break
		}
		currentQuery.Page++
	}

	return nil
}

// AddZone adds a zone to the mock store for testing setup.
func (m *MockZoneDAO) AddZone(zone *entities.Zone) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones[zone.ID] = zone
	m.zonesByName[zone.Name] = zone
}

// Clear removes all zones from the mock store.
func (m *MockZoneDAO) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones = make(map[uint64]*entities.Zone)
	m.zonesByName = make(map[string]*entities.Zone)
}

// ZoneCount returns the current number of zones (for test assertions).
func (m *MockZoneDAO) ZoneCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.zones)
}

// Reset clears all zones and resets all function hooks.
func (m *MockZoneDAO) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones = make(map[uint64]*entities.Zone)
	m.zonesByName = make(map[string]*entities.Zone)
	m.SaveFunc = nil
	m.GetFunc = nil
	m.GetByNameFunc = nil
	m.DeleteFunc = nil
	m.CountFunc = nil
	m.PageFunc = nil
	m.ForEachPageFunc = nil
}
