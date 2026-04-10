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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMockZoneDAO_ImplementsInterface verifies that MockZoneDAO implements dao.ZoneDAO.
func TestMockZoneDAO_ImplementsInterface(t *testing.T) {
	var _ dao.ZoneDAO = (*MockZoneDAO)(nil)
}

// TestMockZoneDAO_BasicOperations tests basic CRUD operations.
func TestMockZoneDAO_BasicOperations(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	// Test Save
	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}

	err := mockDAO.Save(ctx, zone)
	require.NoError(t, err)

	// Test Get
	retrieved, err := mockDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)

	// Test GetByName
	retrieved, err = mockDAO.GetByName(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, zone.ID, retrieved.ID)

	// Test Count
	count, err := mockDAO.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Test Delete
	err = mockDAO.Delete(ctx, zone)
	require.NoError(t, err)

	// Verify deletion
	_, err = mockDAO.Get(ctx, 1)
	assert.ErrorIs(t, err, ErrZoneNotFound)
}

// TestMockZoneDAO_GetNotFound tests Get for non-existent zone.
func TestMockZoneDAO_GetNotFound(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	_, err := mockDAO.Get(ctx, 999)
	assert.ErrorIs(t, err, ErrZoneNotFound)
}

// TestMockZoneDAO_GetByNameNotFound tests GetByName for non-existent zone.
func TestMockZoneDAO_GetByNameNotFound(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	_, err := mockDAO.GetByName(ctx, "nonexistent.com.")
	assert.ErrorIs(t, err, ErrZoneNotFound)
}

// TestMockZoneDAO_CustomSaveFunc tests custom SaveFunc.
func TestMockZoneDAO_CustomSaveFunc(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		return ErrMockSave
	}

	ctx := context.Background()
	zone := &entities.Zone{ID: 1, Name: "test.com."}

	err := mockDAO.Save(ctx, zone)
	assert.ErrorIs(t, err, ErrMockSave)
}

// TestMockZoneDAO_CustomGetFunc tests custom GetFunc.
func TestMockZoneDAO_CustomGetFunc(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	customZone := &entities.Zone{ID: 99, Name: "custom.com."}
	mockDAO.GetFunc = func(ctx context.Context, id uint64) (*entities.Zone, error) {
		return customZone, nil
	}

	ctx := context.Background()
	zone, err := mockDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, customZone.Name, zone.Name)
}

// TestMockZoneDAO_CustomDeleteFunc tests custom DeleteFunc.
func TestMockZoneDAO_CustomDeleteFunc(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	mockDAO.DeleteFunc = func(ctx context.Context, zone *entities.Zone) error {
		return ErrMockDelete
	}

	ctx := context.Background()
	zone := &entities.Zone{ID: 1, Name: "test.com."}

	err := mockDAO.Delete(ctx, zone)
	assert.ErrorIs(t, err, ErrMockDelete)
}

// TestMockZoneDAO_AddZone tests the AddZone helper method.
func TestMockZoneDAO_AddZone(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}

	mockDAO.AddZone(zone)

	// Verify zone is accessible
	retrieved, err := mockDAO.Get(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, zone.Name, retrieved.Name)

	// Verify by name
	retrieved, err = mockDAO.GetByName(ctx, "example.com.")
	require.NoError(t, err)
	assert.Equal(t, zone.ID, retrieved.ID)
}

// TestMockZoneDAO_Clear tests the Clear helper method.
func TestMockZoneDAO_Clear(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	// Add some zones
	mockDAO.AddZone(&entities.Zone{ID: 1, Name: "one.com."})
	mockDAO.AddZone(&entities.Zone{ID: 2, Name: "two.com."})

	assert.Equal(t, 2, mockDAO.ZoneCount())

	// Clear
	mockDAO.Clear()

	assert.Equal(t, 0, mockDAO.ZoneCount())

	// Verify zones are gone
	_, err := mockDAO.Get(ctx, 1)
	assert.ErrorIs(t, err, ErrZoneNotFound)
}

// TestMockZoneDAO_Reset tests the Reset helper method.
func TestMockZoneDAO_Reset(t *testing.T) {
	mockDAO := NewMockZoneDAO()

	// Configure custom functions
	mockDAO.SaveFunc = func(ctx context.Context, zone *entities.Zone) error {
		return ErrMockSave
	}
	mockDAO.AddZone(&entities.Zone{ID: 1, Name: "test.com."})

	// Reset
	mockDAO.Reset()

	// Verify zones are cleared
	assert.Equal(t, 0, mockDAO.ZoneCount())

	// Verify functions are reset (save should work now)
	ctx := context.Background()
	err := mockDAO.Save(ctx, &entities.Zone{ID: 1, Name: "new.com."})
	require.NoError(t, err)
}

// TestMockZoneDAO_Page tests pagination.
func TestMockZoneDAO_Page(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	// Add multiple zones
	for i := uint64(1); i <= 10; i++ {
		mockDAO.AddZone(&entities.Zone{ID: i, Name: "zone" + string(rune('0'+i)) + ".com."})
	}

	// Test first page
	query := datastore.PageQuery{Page: 1, PageSize: 3}
	result, err := mockDAO.Page(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 10, result.Total)
	assert.True(t, result.HasMore)

	// Test last page
	query = datastore.PageQuery{Page: 4, PageSize: 3}
	result, err = mockDAO.Page(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, 1, len(result.Entities))
	assert.False(t, result.HasMore)

	// Test beyond last page
	query = datastore.PageQuery{Page: 5, PageSize: 3}
	result, err = mockDAO.Page(ctx, query)
	require.NoError(t, err)
	assert.Equal(t, 0, len(result.Entities))
}

// TestMockZoneDAO_ForEachPage tests pagination iteration.
func TestMockZoneDAO_ForEachPage(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	// Add zones
	for i := uint64(1); i <= 5; i++ {
		mockDAO.AddZone(&entities.Zone{ID: i})
	}

	var pageCount int
	var totalEntities int

	query := datastore.PageQuery{Page: 1, PageSize: 2}
	err := mockDAO.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
		pageCount++
		totalEntities += len(result.Entities)
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 3, pageCount)
	assert.Equal(t, 5, totalEntities)
}

// TestMockZoneDAO_ForEachPage_StopIteration tests stopping iteration.
func TestMockZoneDAO_ForEachPage_StopIteration(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	// Add zones
	for i := uint64(1); i <= 10; i++ {
		mockDAO.AddZone(&entities.Zone{ID: i})
	}

	var pageCount int
	query := datastore.PageQuery{Page: 1, PageSize: 2}
	err := mockDAO.ForEachPage(ctx, query, func(result datastore.PageResult[*entities.Zone]) error {
		pageCount++
		if pageCount >= 2 {
			return datastore.ErrStopIteration
		}
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, 2, pageCount)
}

// TestMockZoneDAO_CustomCountFunc tests custom CountFunc.
func TestMockZoneDAO_CustomCountFunc(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	mockDAO.CountFunc = func(ctx context.Context) (int, error) {
		return 999, nil
	}

	ctx := context.Background()
	count, err := mockDAO.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 999, count)
}

// TestMockZoneDAO_Concurrent tests concurrent access safety.
func TestMockZoneDAO_Concurrent(t *testing.T) {
	mockDAO := NewMockZoneDAO()
	ctx := context.Background()

	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := uint64(0); i < 100; i++ {
			zone := &entities.Zone{ID: i, Name: "zone.com."}
			_ = mockDAO.Save(ctx, zone)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = mockDAO.Get(ctx, uint64(i%10))
		}
		done <- true
	}()

	// Wait for both
	<-done
	<-done
}
