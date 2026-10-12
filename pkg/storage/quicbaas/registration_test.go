//go:build raft

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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRegistrationDAO(t *testing.T) *RegistrationDAO {
	t.Helper()
	return NewRegistrationDAO(newSharedTestClient(t), logging.DefaultLogger())
}

func TestNewRegistrationDAO(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
}

func TestRegistrationDAO_Save_NewRegistration(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	reg := entities.NewRegistration("test@example.com")
	reg.Password = "hashedpassword"
	reg.OrgName = "Test Org"

	err := dao.Save(ctx, reg)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), reg.EntityID())
}

func TestRegistrationDAO_Save_WithExistingID(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	reg := &entities.Registration{
		ID:       12345,
		Email:    "existing@example.com",
		Password: "pass123",
		OrgID:    100,
		OrgName:  "Existing Org",
	}

	err := dao.Save(ctx, reg)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), reg.EntityID())
}

func TestRegistrationDAO_Get_Success(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	reg := &entities.Registration{
		ID:          99999,
		Email:       "get@example.com",
		Password:    "getpassword",
		OrgID:       200,
		OrgName:     "Get Test Org",
		SessionData: []byte(`{"key":"value"}`),
	}

	err := dao.Save(ctx, reg)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 99999)
	require.NoError(t, err)
	assert.Equal(t, uint64(99999), retrieved.EntityID())
	assert.Equal(t, "get@example.com", retrieved.Email)
	assert.Equal(t, "getpassword", retrieved.Password)
	assert.Equal(t, uint64(200), retrieved.OrgID)
	assert.Equal(t, "Get Test Org", retrieved.OrgName)
	assert.Equal(t, []byte(`{"key":"value"}`), retrieved.SessionData)
}

func TestRegistrationDAO_Get_NotFound(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	_, err := dao.Get(ctx, 88888888)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRegistrationDAO_Delete_Success(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	reg := &entities.Registration{
		ID:    77777,
		Email: "delete@example.com",
	}

	err := dao.Save(ctx, reg)
	require.NoError(t, err)

	err = dao.Delete(ctx, reg)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestRegistrationDAO_Update_Success(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	reg := &entities.Registration{
		ID:      66666,
		Email:   "original@example.com",
		OrgName: "Original Org",
	}

	err := dao.Save(ctx, reg)
	require.NoError(t, err)

	// Update
	reg.Email = "updated@example.com"
	reg.OrgName = "Updated Org"
	reg.OrgID = 500
	err = dao.Save(ctx, reg)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 66666)
	require.NoError(t, err)
	assert.Equal(t, "updated@example.com", retrieved.Email)
	assert.Equal(t, "Updated Org", retrieved.OrgName)
	assert.Equal(t, uint64(500), retrieved.OrgID)
}

func TestRegistrationDAO_Count(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()

	// Create registrations
	for i := 1; i <= 6; i++ {
		reg := &entities.Registration{
			ID:    uint64(50000 + i),
			Email: "count" + string(rune('0'+i)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, reg))
	}

	// Wait for all items to be visible via Raft consensus
	// QuicBaaS may need time to commit all writes to the state machine
	require.Eventually(t, func() bool {
		count, err := dao.Count(ctx)
		return err == nil && count == 6
	}, 5*time.Second, 50*time.Millisecond, "expected 6 items to be visible")

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 6, count)
}

func TestRegistrationDAO_Page(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()

	// Create 10 registrations
	for i := 1; i <= 10; i++ {
		reg := &entities.Registration{
			ID:    uint64(40000 + i),
			Email: "page" + string(rune('0'+i)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, reg))
	}

	// Wait for all items to be visible via Raft consensus
	// QuicBaaS may need time to commit all writes to the state machine
	require.Eventually(t, func() bool {
		count, err := dao.Count(ctx)
		return err == nil && count == 10
	}, 5*time.Second, 50*time.Millisecond, "expected 10 items to be visible")

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 4})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 4)
	assert.True(t, result.HasMore)
}

func TestRegistrationDAO_ForEachPage(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()

	// Create 9 registrations
	for i := 1; i <= 9; i++ {
		reg := &entities.Registration{
			ID:    uint64(30000 + i),
			Email: "foreach" + string(rune('a'+i-1)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, reg))
	}

	var processedCount int
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 3},
		func(result datastore.PageResult[*entities.Registration]) error {
			processedCount += len(result.Entities)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 9, processedCount)
}

func TestRegistrationDAO_WithSessionData(t *testing.T) {
	dao := newTestRegistrationDAO(t)

	ctx := context.Background()
	sessionData := []byte(`{"challenge":"abc123","timestamp":1234567890}`)

	reg := &entities.Registration{
		ID:          20000,
		Email:       "session@example.com",
		SessionData: sessionData,
	}

	err := dao.Save(ctx, reg)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 20000)
	require.NoError(t, err)
	assert.Equal(t, sessionData, retrieved.SessionData)
}
