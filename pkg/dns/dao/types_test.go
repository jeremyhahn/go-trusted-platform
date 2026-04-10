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

package dao

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test error types for mock implementations
var (
	ErrMockSave   = errors.New("mock: save error")
	ErrMockGet    = errors.New("mock: get error")
	ErrMockDelete = errors.New("mock: delete error")
	ErrMockCount  = errors.New("mock: count error")
	ErrMockPage   = errors.New("mock: page error")
)

// MockZoneDAO is a test implementation of ZoneDAO for testing consumers
type MockZoneDAO struct {
	mu           sync.RWMutex
	zones        map[uint64]*entities.Zone
	zonesByName  map[string]*entities.Zone
	nextID       uint64
	saveErr      error
	getErr       error
	deleteErr    error
	countErr     error
	pageErr      error
	getByNameErr error
}

// NewMockZoneDAO creates a new mock ZoneDAO for testing
func NewMockZoneDAO() *MockZoneDAO {
	return &MockZoneDAO{
		zones:       make(map[uint64]*entities.Zone),
		zonesByName: make(map[string]*entities.Zone),
		nextID:      1,
	}
}

// Save implements datastore.GenericDAO
func (m *MockZoneDAO) Save(ctx context.Context, entity *entities.Zone) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if entity.ID == 0 {
		entity.SetEntityID(m.nextID)
		m.nextID++
	}
	m.zones[entity.ID] = entity
	m.zonesByName[entity.Name] = entity
	return nil
}

// Get implements datastore.GenericDAO
func (m *MockZoneDAO) Get(ctx context.Context, id uint64) (*entities.Zone, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	zone, ok := m.zones[id]
	if !ok {
		return nil, datastore.ErrRecordNotFound
	}
	return zone, nil
}

// Delete implements datastore.GenericDAO
func (m *MockZoneDAO) Delete(ctx context.Context, entity *entities.Zone) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.zones[entity.ID]; !ok {
		return datastore.ErrRecordNotFound
	}
	delete(m.zones, entity.ID)
	delete(m.zonesByName, entity.Name)
	return nil
}

// Count implements datastore.GenericDAO
func (m *MockZoneDAO) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.zones), nil
}

// Page implements datastore.Pager
func (m *MockZoneDAO) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Zone], error) {
	if m.pageErr != nil {
		return datastore.PageResult[*entities.Zone]{}, m.pageErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := datastore.NewPageResultFromQuery[*entities.Zone](query)
	result.Total = len(m.zones)

	// Collect all zones
	var allZones []*entities.Zone
	for _, zone := range m.zones {
		allZones = append(allZones, zone)
	}

	// Apply pagination
	page := query.Page
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * query.PageSize
	if offset >= len(allZones) {
		return result, nil
	}

	end := offset + query.PageSize
	if end > len(allZones) {
		end = len(allZones)
	}

	result.Entities = allZones[offset:end]
	result.HasMore = end < len(allZones)
	return result, nil
}

// ForEachPage implements datastore.Pager
func (m *MockZoneDAO) ForEachPage(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.Zone]) error {
	pageResult, err := m.Page(ctx, query)
	if err != nil {
		return err
	}
	if len(pageResult.Entities) > 0 {
		if err = fn(pageResult); err != nil {
			if errors.Is(err, datastore.ErrStopIteration) {
				return nil
			}
			return err
		}
	}
	if pageResult.HasMore {
		nextQuery := datastore.PageQuery{
			Page:      query.Page + 1,
			PageSize:  query.PageSize,
			SortOrder: query.SortOrder,
		}
		return m.ForEachPage(ctx, nextQuery, fn)
	}
	return nil
}

// GetByName implements ZoneDAO
func (m *MockZoneDAO) GetByName(ctx context.Context, name string) (*entities.Zone, error) {
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	zone, ok := m.zonesByName[name]
	if !ok {
		return nil, datastore.ErrRecordNotFound
	}
	return zone, nil
}

// SetSaveError configures the mock to return an error on Save
func (m *MockZoneDAO) SetSaveError(err error) {
	m.saveErr = err
}

// SetGetError configures the mock to return an error on Get
func (m *MockZoneDAO) SetGetError(err error) {
	m.getErr = err
}

// SetDeleteError configures the mock to return an error on Delete
func (m *MockZoneDAO) SetDeleteError(err error) {
	m.deleteErr = err
}

// SetCountError configures the mock to return an error on Count
func (m *MockZoneDAO) SetCountError(err error) {
	m.countErr = err
}

// SetPageError configures the mock to return an error on Page
func (m *MockZoneDAO) SetPageError(err error) {
	m.pageErr = err
}

// SetGetByNameError configures the mock to return an error on GetByName
func (m *MockZoneDAO) SetGetByNameError(err error) {
	m.getByNameErr = err
}

// Verify MockZoneDAO implements ZoneDAO interface at compile time
var _ ZoneDAO = (*MockZoneDAO)(nil)

// TestZoneDAOInterface verifies that the interface is properly defined
func TestZoneDAOInterface(t *testing.T) {
	// Create a mock that implements the interface
	var dao ZoneDAO = NewMockZoneDAO()
	require.NotNil(t, dao)

	// Verify it can be used as both GenericDAO and ZoneDAO
	_, ok := dao.(datastore.GenericDAO[*entities.Zone])
	assert.True(t, ok, "ZoneDAO should embed GenericDAO")
}

func TestMockZoneDAO_Save(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			Name:        "example.com.",
			TTL:         3600,
			Description: "Test zone",
		}

		err := dao.Save(ctx, zone)
		require.NoError(t, err)
		assert.NotEqual(t, uint64(0), zone.ID)
	})

	t.Run("with_predefined_id", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			ID:          12345,
			Name:        "example.com.",
			TTL:         3600,
			Description: "Test zone",
		}

		err := dao.Save(ctx, zone)
		require.NoError(t, err)
		assert.Equal(t, uint64(12345), zone.ID)
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		dao.SetSaveError(ErrMockSave)

		zone := &entities.Zone{
			Name: "example.com.",
			TTL:  3600,
		}

		err := dao.Save(ctx, zone)
		assert.ErrorIs(t, err, ErrMockSave)
	})
}

func TestMockZoneDAO_Get(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			ID:          1,
			Name:        "example.com.",
			TTL:         3600,
			Description: "Test zone",
		}
		err := dao.Save(ctx, zone)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, zone.Name, retrieved.Name)
		assert.Equal(t, zone.TTL, retrieved.TTL)
	})

	t.Run("not_found", func(t *testing.T) {
		dao := NewMockZoneDAO()

		retrieved, err := dao.Get(ctx, 99999)
		assert.ErrorIs(t, err, datastore.ErrRecordNotFound)
		assert.Nil(t, retrieved)
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		dao.SetGetError(ErrMockGet)

		retrieved, err := dao.Get(ctx, 1)
		assert.ErrorIs(t, err, ErrMockGet)
		assert.Nil(t, retrieved)
	})
}

func TestMockZoneDAO_Delete(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			ID:   1,
			Name: "example.com.",
			TTL:  3600,
		}
		err := dao.Save(ctx, zone)
		require.NoError(t, err)

		err = dao.Delete(ctx, zone)
		require.NoError(t, err)

		// Verify it's deleted
		retrieved, err := dao.Get(ctx, 1)
		assert.ErrorIs(t, err, datastore.ErrRecordNotFound)
		assert.Nil(t, retrieved)
	})

	t.Run("not_found", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			ID:   99999,
			Name: "nonexistent.com.",
		}

		err := dao.Delete(ctx, zone)
		assert.ErrorIs(t, err, datastore.ErrRecordNotFound)
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		dao.SetDeleteError(ErrMockDelete)

		zone := &entities.Zone{
			ID:   1,
			Name: "example.com.",
		}

		err := dao.Delete(ctx, zone)
		assert.ErrorIs(t, err, ErrMockDelete)
	})
}

func TestMockZoneDAO_Count(t *testing.T) {
	ctx := context.Background()

	t.Run("empty", func(t *testing.T) {
		dao := NewMockZoneDAO()

		count, err := dao.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("with_zones", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zones := []*entities.Zone{
			{ID: 1, Name: "zone1.com.", TTL: 3600},
			{ID: 2, Name: "zone2.com.", TTL: 3600},
			{ID: 3, Name: "zone3.com.", TTL: 3600},
		}

		for _, zone := range zones {
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		count, err := dao.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		dao.SetCountError(ErrMockCount)

		count, err := dao.Count(ctx)
		assert.ErrorIs(t, err, ErrMockCount)
		assert.Equal(t, 0, count)
	})
}

func TestMockZoneDAO_Page(t *testing.T) {
	ctx := context.Background()

	t.Run("empty", func(t *testing.T) {
		dao := NewMockZoneDAO()

		query := datastore.NewPageQuery()
		result, err := dao.Page(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, 0, result.Total)
		assert.Empty(t, result.Entities)
		assert.False(t, result.HasMore)
	})

	t.Run("single_page", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zones := []*entities.Zone{
			{ID: 1, Name: "zone1.com.", TTL: 3600},
			{ID: 2, Name: "zone2.com.", TTL: 3600},
		}

		for _, zone := range zones {
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		query := datastore.PageQuery{Page: 1, PageSize: 10}
		result, err := dao.Page(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, 2, result.Total)
		assert.Len(t, result.Entities, 2)
		assert.False(t, result.HasMore)
	})

	t.Run("multiple_pages", func(t *testing.T) {
		dao := NewMockZoneDAO()

		for i := 1; i <= 5; i++ {
			zone := &entities.Zone{
				ID:   uint64(i),
				Name: "zone" + string(rune('0'+i)) + ".com.",
				TTL:  3600,
			}
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		// First page
		query := datastore.PageQuery{Page: 1, PageSize: 2}
		result, err := dao.Page(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, 5, result.Total)
		assert.Len(t, result.Entities, 2)
		assert.True(t, result.HasMore)

		// Last page
		query = datastore.PageQuery{Page: 3, PageSize: 2}
		result, err = dao.Page(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, 5, result.Total)
		assert.Len(t, result.Entities, 1)
		assert.False(t, result.HasMore)
	})

	t.Run("page_beyond_range", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{ID: 1, Name: "zone1.com.", TTL: 3600}
		err := dao.Save(ctx, zone)
		require.NoError(t, err)

		query := datastore.PageQuery{Page: 100, PageSize: 10}
		result, err := dao.Page(ctx, query)
		require.NoError(t, err)
		assert.Equal(t, 1, result.Total)
		assert.Empty(t, result.Entities)
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		dao.SetPageError(ErrMockPage)

		query := datastore.NewPageQuery()
		result, err := dao.Page(ctx, query)
		assert.ErrorIs(t, err, ErrMockPage)
		assert.Empty(t, result.Entities)
	})
}

func TestMockZoneDAO_ForEachPage(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := NewMockZoneDAO()

		for i := 1; i <= 5; i++ {
			zone := &entities.Zone{
				ID:   uint64(i),
				Name: "zone" + string(rune('0'+i)) + ".com.",
				TTL:  3600,
			}
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		var totalZones int
		query := datastore.PageQuery{Page: 1, PageSize: 2}
		err := dao.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
			totalZones += len(result.Entities)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 5, totalZones)
	})

	t.Run("stop_iteration", func(t *testing.T) {
		dao := NewMockZoneDAO()

		for i := 1; i <= 5; i++ {
			zone := &entities.Zone{
				ID:   uint64(i),
				Name: "zone" + string(rune('0'+i)) + ".com.",
				TTL:  3600,
			}
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		var pagesProcessed int
		query := datastore.PageQuery{Page: 1, PageSize: 2}
		err := dao.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
			pagesProcessed++
			return datastore.ErrStopIteration // Stop after first page
		})
		require.NoError(t, err)
		assert.Equal(t, 1, pagesProcessed)
	})

	t.Run("callback_error", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{ID: 1, Name: "zone1.com.", TTL: 3600}
		err := dao.Save(ctx, zone)
		require.NoError(t, err)

		callbackErr := errors.New("callback error")
		query := datastore.PageQuery{Page: 1, PageSize: 10}
		err = dao.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
			return callbackErr
		})
		assert.ErrorIs(t, err, callbackErr)
	})
}

func TestMockZoneDAO_GetByName(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zone := &entities.Zone{
			ID:          1,
			Name:        "example.com.",
			TTL:         3600,
			Description: "Test zone",
			Internal:    true,
		}
		err := dao.Save(ctx, zone)
		require.NoError(t, err)

		retrieved, err := dao.GetByName(ctx, "example.com.")
		require.NoError(t, err)
		assert.Equal(t, zone.Name, retrieved.Name)
		assert.Equal(t, zone.TTL, retrieved.TTL)
		assert.Equal(t, zone.Internal, retrieved.Internal)
	})

	t.Run("not_found", func(t *testing.T) {
		dao := NewMockZoneDAO()

		retrieved, err := dao.GetByName(ctx, "nonexistent.com.")
		assert.ErrorIs(t, err, datastore.ErrRecordNotFound)
		assert.Nil(t, retrieved)
	})

	t.Run("multiple_zones", func(t *testing.T) {
		dao := NewMockZoneDAO()

		zones := []*entities.Zone{
			{ID: 1, Name: "zone1.com.", TTL: 3600},
			{ID: 2, Name: "zone2.com.", TTL: 7200},
			{ID: 3, Name: "zone3.com.", TTL: 14400},
		}

		for _, zone := range zones {
			err := dao.Save(ctx, zone)
			require.NoError(t, err)
		}

		// Retrieve each by name
		for _, zone := range zones {
			retrieved, err := dao.GetByName(ctx, zone.Name)
			require.NoError(t, err)
			assert.Equal(t, zone.ID, retrieved.ID)
			assert.Equal(t, zone.TTL, retrieved.TTL)
		}
	})

	t.Run("error", func(t *testing.T) {
		dao := NewMockZoneDAO()
		getByNameErr := errors.New("get by name error")
		dao.SetGetByNameError(getByNameErr)

		retrieved, err := dao.GetByName(ctx, "example.com.")
		assert.ErrorIs(t, err, getByNameErr)
		assert.Nil(t, retrieved)
	})
}

func TestMockZoneDAO_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	dao := NewMockZoneDAO()

	var wg sync.WaitGroup
	numGoroutines := 10
	zonesPerGoroutine := 10

	// Concurrent saves
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < zonesPerGoroutine; i++ {
				zone := &entities.Zone{
					Name: "zone" + string(rune('0'+goroutineID)) + string(rune('0'+i)) + ".com.",
					TTL:  3600,
				}
				err := dao.Save(ctx, zone)
				assert.NoError(t, err)
			}
		}(g)
	}

	wg.Wait()

	// Verify count
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, numGoroutines*zonesPerGoroutine, count)
}

func TestMockZoneDAO_UpdateZone(t *testing.T) {
	ctx := context.Background()
	dao := NewMockZoneDAO()

	// Create zone
	zone := &entities.Zone{
		ID:          1,
		Name:        "example.com.",
		TTL:         3600,
		Description: "Original description",
	}
	err := dao.Save(ctx, zone)
	require.NoError(t, err)

	// Update zone
	zone.TTL = 7200
	zone.Description = "Updated description"
	err = dao.Save(ctx, zone)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(7200), retrieved.TTL)
	assert.Equal(t, "Updated description", retrieved.Description)
}

func TestMockZoneDAO_DeleteRemovesFromBothMaps(t *testing.T) {
	ctx := context.Background()
	dao := NewMockZoneDAO()

	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}
	err := dao.Save(ctx, zone)
	require.NoError(t, err)

	// Verify it exists by both ID and Name
	_, err = dao.Get(ctx, 1)
	require.NoError(t, err)

	_, err = dao.GetByName(ctx, "example.com.")
	require.NoError(t, err)

	// Delete
	err = dao.Delete(ctx, zone)
	require.NoError(t, err)

	// Verify it's gone from both lookups
	_, err = dao.Get(ctx, 1)
	assert.ErrorIs(t, err, datastore.ErrRecordNotFound)

	_, err = dao.GetByName(ctx, "example.com.")
	assert.ErrorIs(t, err, datastore.ErrRecordNotFound)
}

func TestMockZoneDAO_ZeroPageNumber(t *testing.T) {
	ctx := context.Background()
	dao := NewMockZoneDAO()

	zone := &entities.Zone{ID: 1, Name: "zone1.com.", TTL: 3600}
	err := dao.Save(ctx, zone)
	require.NoError(t, err)

	// Page 0 should be treated as page 1
	query := datastore.PageQuery{Page: 0, PageSize: 10}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Entities, 1)
}

func TestMockZoneDAO_NegativePageNumber(t *testing.T) {
	ctx := context.Background()
	dao := NewMockZoneDAO()

	zone := &entities.Zone{ID: 1, Name: "zone1.com.", TTL: 3600}
	err := dao.Save(ctx, zone)
	require.NoError(t, err)

	// Negative page should be treated as page 1
	query := datastore.PageQuery{Page: -5, PageSize: 10}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Entities, 1)
}
