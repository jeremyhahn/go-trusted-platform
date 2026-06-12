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
	"encoding/json"
	"errors"
	"testing"
	"time"

	deventities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	dsentities "github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// GenericDAO: WithShard, WithPartition, ShardID, Partition, checkContext edges
// =============================================================================

func TestWithShard_Option(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
		WithShard(42),
	)

	assert.Equal(t, uint64(42), dao.ShardID())
}

func TestWithPartition_Option(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
		WithPartition("tenant-abc"),
	)

	assert.Equal(t, "tenant-abc", dao.Partition())
}

func TestGenericDAO_CheckContext_Save_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := dao.Save(ctx, &TestRole{Name: "admin"})
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "Save", ctxErr.Operation)
}

func TestGenericDAO_CheckContext_Get_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dao.Get(ctx, 12345)
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "Get", ctxErr.Operation)
}

func TestGenericDAO_CheckContext_Delete_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := dao.Delete(ctx, &TestRole{ID: 1})
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "Delete", ctxErr.Operation)
}

func TestGenericDAO_CheckContext_Count_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dao.Count(ctx)
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "Count", ctxErr.Operation)
}

func TestGenericDAO_CheckContext_Page_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "Page", ctxErr.Operation)
}

func TestGenericDAO_CheckContext_ForEachPage_Cancelled(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 10}, func(datastore.PageResult[*TestRole]) error {
		return nil
	})
	require.Error(t, err)
	var ctxErr ErrContextCancelled
	assert.ErrorAs(t, err, &ctxErr)
	assert.Equal(t, "ForEachPage", ctxErr.Operation)
}

func TestGenericDAO_ForEachPage_StopIteration(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		require.NoError(t, dao.Save(ctx, &TestRole{ID: uint64(i), Name: "role"}))
	}

	pageCount := 0
	err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 3}, func(datastore.PageResult[*TestRole]) error {
		pageCount++
		return datastore.ErrStopIteration
	})
	require.NoError(t, err)
	assert.Equal(t, 1, pageCount, "should stop after first page")
}

// =============================================================================
// MockClient tests
// =============================================================================

func TestMockClient_Lifecycle(t *testing.T) {
	mc := NewMockClient()
	assert.False(t, mc.IsStarted())
	assert.False(t, mc.IsClosed())
	assert.True(t, mc.IsEmbedded())

	require.NoError(t, mc.Start(context.Background()))
	assert.True(t, mc.IsStarted())

	require.NoError(t, mc.Stop(context.Background()))
	assert.False(t, mc.IsStarted())
	assert.True(t, mc.IsClosed())
}

func TestMockClient_StartWithService(t *testing.T) {
	mc := NewMockClient()
	require.NoError(t, mc.StartWithService(context.Background(), nil))
	assert.True(t, mc.IsStarted())
	assert.True(t, mc.IsEmbedded())
}

func TestMockClient_Start_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	mc.StartError = errors.New("start failed")
	err := mc.Start(context.Background())
	require.Error(t, err)
}

func TestMockClient_StartWithService_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	mc.StartError = errors.New("start failed")
	err := mc.StartWithService(context.Background(), nil)
	require.Error(t, err)
}

func TestMockClient_Stop_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	require.NoError(t, mc.Start(context.Background()))
	mc.StopError = errors.New("stop failed")
	err := mc.Stop(context.Background())
	require.Error(t, err)
}

func TestMockClient_SetEmbedded(t *testing.T) {
	mc := NewMockClient()
	assert.True(t, mc.IsEmbedded())
	mc.SetEmbedded(false)
	assert.False(t, mc.IsEmbedded())
}

func TestMockClient_CRUD(t *testing.T) {
	mc := NewMockClient()
	ctx := context.Background()

	require.NoError(t, mc.Put(ctx, "TestEntity", 1, []byte("data1"), 0))
	require.NoError(t, mc.Put(ctx, "TestEntity", 2, []byte("data2"), 0))

	data, found, err := mc.Get(ctx, "TestEntity", 1, 0)
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("data1"), data)

	_, found, err = mc.Get(ctx, "TestEntity", 999, 0)
	require.NoError(t, err)
	assert.False(t, found)

	require.NoError(t, mc.Delete(ctx, "TestEntity", 1, 0))
	_, found, err = mc.Get(ctx, "TestEntity", 1, 0)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestMockClient_CRUD_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	ctx := context.Background()

	mc.PutError = errors.New("put error")
	require.Error(t, mc.Put(ctx, "TestEntity", 1, []byte("data"), 0))

	mc.PutError = nil
	mc.GetError = errors.New("get error")
	_, _, err := mc.Get(ctx, "TestEntity", 1, 0)
	require.Error(t, err)

	mc.GetError = nil
	mc.DeleteError = errors.New("delete error")
	require.Error(t, mc.Delete(ctx, "TestEntity", 1, 0))
}

func TestMockClient_List(t *testing.T) {
	mc := NewMockClient()
	ctx := context.Background()

	mc.SetData("TestEntity", 1, []byte("data1"))
	mc.SetData("TestEntity", 2, []byte("data2"))

	result, nextToken, err := mc.List(ctx, "TestEntity", 10, "", 0)
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Empty(t, nextToken)
}

func TestMockClient_List_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	mc.ListError = errors.New("list error")
	_, _, err := mc.List(context.Background(), "TestEntity", 10, "", 0)
	require.Error(t, err)
}

func TestMockClient_Query(t *testing.T) {
	mc := NewMockClient()
	ctx := context.Background()

	mc.SetData("TestEntity", 1, []byte("data1"))

	result, err := mc.Query(ctx, "TestEntity", "field", []byte("value"), 0)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestMockClient_Query_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	mc.QueryError = errors.New("query error")
	_, err := mc.Query(context.Background(), "TestEntity", "field", []byte("value"), 0)
	require.Error(t, err)
}

func TestMockClient_Query_EmptyEntityType(t *testing.T) {
	mc := NewMockClient()
	result, err := mc.Query(context.Background(), "NonExistent", "field", []byte("value"), 0)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestMockClient_ListEntityTypes(t *testing.T) {
	mc := NewMockClient()
	mc.SetEntityTypes([]string{"User", "Role", "Device"})

	types, nextToken, total, err := mc.ListEntityTypes(context.Background(), 10, "")
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, types, 3)
	assert.Empty(t, nextToken)
}

func TestMockClient_ListEntityTypes_ErrorInjection(t *testing.T) {
	mc := NewMockClient()
	mc.ListEntityTypesError = errors.New("list types error")
	_, _, _, err := mc.ListEntityTypes(context.Background(), 10, "")
	require.Error(t, err)
}

func TestMockClient_Service_ReturnsNil(t *testing.T) {
	mc := NewMockClient()
	assert.Nil(t, mc.Service())
}

func TestMockClient_Reset(t *testing.T) {
	mc := NewMockClient()
	mc.SetData("TestEntity", 1, []byte("data"))
	mc.PutError = errors.New("error")
	mc.SetEntityTypes([]string{"TestEntity"})
	require.NoError(t, mc.Start(context.Background()))

	mc.Reset()
	assert.False(t, mc.IsStarted())
	assert.False(t, mc.IsClosed())
	assert.True(t, mc.IsEmbedded())
	assert.Nil(t, mc.PutError)

	_, found, err := mc.Get(context.Background(), "TestEntity", 1, 0)
	require.NoError(t, err)
	assert.False(t, found)

	types, _, total, err := mc.ListEntityTypes(context.Background(), 10, "")
	require.NoError(t, err)
	assert.Empty(t, types)
	assert.Equal(t, 0, total)
}

func TestMockClient_SetData_CreatesEntityType(t *testing.T) {
	mc := NewMockClient()
	mc.SetData("NewType", 1, []byte("data"))

	types, _, total, err := mc.ListEntityTypes(context.Background(), 10, "")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Contains(t, types, "NewType")
}

func TestMockClient_Delete_NonExistentEntity(t *testing.T) {
	mc := NewMockClient()
	// Deleting a non-existent entity type should not error
	require.NoError(t, mc.Delete(context.Background(), "NonExistent", 999, 0))
}

func TestMockClient_List_EmptyEntityType(t *testing.T) {
	mc := NewMockClient()
	result, nextToken, err := mc.List(context.Background(), "NonExistent", 10, "", 0)
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.Empty(t, nextToken)
}

// =============================================================================
// MockFactory tests
// =============================================================================

func TestMockFactory_Lifecycle(t *testing.T) {
	mf := NewMockFactory()
	ctx := context.Background()

	assert.False(t, mf.IsStarted())
	assert.False(t, mf.IsClosed())

	require.NoError(t, mf.Start(ctx))
	assert.True(t, mf.IsStarted())

	require.NoError(t, mf.Stop(ctx))
	assert.True(t, mf.IsClosed())
	assert.False(t, mf.IsStarted())
}

func TestMockFactory_StartError(t *testing.T) {
	mf := NewMockFactory()
	mf.StartError = errors.New("start error")
	require.Error(t, mf.Start(context.Background()))
}

func TestMockFactory_StopError(t *testing.T) {
	mf := NewMockFactory()
	require.NoError(t, mf.Start(context.Background()))
	mf.StopError = errors.New("stop error")
	require.Error(t, mf.Stop(context.Background()))
}

func TestMockFactory_WithClient(t *testing.T) {
	mc := NewMockClient()
	mf := NewMockFactoryWithClient(mc)

	assert.Equal(t, mc, mf.MockClient())
	assert.NotNil(t, mf.QuicBaaSClient())
}

func TestMockFactory_DataDir(t *testing.T) {
	mf := NewMockFactory()
	assert.Equal(t, "/tmp/mock-quicbaas", mf.DataDir())

	mf.SetDataDir("/tmp/custom-dir")
	assert.Equal(t, "/tmp/custom-dir", mf.DataDir())
}

func TestMockFactory_SerializerType(t *testing.T) {
	mf := NewMockFactory()
	assert.Equal(t, serializer.SERIALIZER_JSON, mf.SerializerType())
}

func TestMockFactory_DAOs_DefaultNil(t *testing.T) {
	mf := NewMockFactory()

	userDAO, err := mf.UserDAO()
	require.NoError(t, err)
	assert.Nil(t, userDAO)

	regDAO, err := mf.RegistrationDAO()
	require.NoError(t, err)
	assert.Nil(t, regDAO)

	invDAO, err := mf.InvitationDAO()
	require.NoError(t, err)
	assert.Nil(t, invDAO)

	roleDAO, err := mf.RoleDAO()
	require.NoError(t, err)
	assert.Nil(t, roleDAO)

	waDAO, err := mf.WebAuthnDAO()
	require.NoError(t, err)
	assert.Nil(t, waDAO)

	devDAO, err := mf.DeviceDAO()
	require.NoError(t, err)
	assert.Nil(t, devDAO)

	dpDAO, err := mf.DeviceProfileDAO()
	require.NoError(t, err)
	assert.Nil(t, dpDAO)

	zoneDAO, err := mf.ZoneDAO()
	require.NoError(t, err)
	assert.Nil(t, zoneDAO)
}

func TestMockFactory_ClientStartError_PropagatesToFactory(t *testing.T) {
	mc := NewMockClient()
	mc.StartError = errors.New("client start failed")
	mf := NewMockFactoryWithClient(mc)

	err := mf.Start(context.Background())
	require.Error(t, err)
}

func TestMockFactory_ClientStopError_PropagatesToFactory(t *testing.T) {
	mc := NewMockClient()
	mf := NewMockFactoryWithClient(mc)
	require.NoError(t, mf.Start(context.Background()))

	mc.StopError = errors.New("client stop failed")
	err := mf.Stop(context.Background())
	require.Error(t, err)
}

// =============================================================================
// SDKStorage lifecycle tests
// =============================================================================

func TestNewSDKStorage_NilClient(t *testing.T) {
	_, err := NewSDKStorage(nil)
	require.Error(t, err)
	var target ErrSDKClientNil
	assert.ErrorAs(t, err, &target)
}

func TestSDKStorage_Start_WhenClosed(t *testing.T) {
	storage := &SDKStorage{}
	storage.closed.Store(true)
	err := storage.Start(context.Background())
	require.Error(t, err)
	var target ErrStorageClosed
	assert.ErrorAs(t, err, &target)
}

func TestSDKStorage_IsStarted_IsClosed(t *testing.T) {
	storage := &SDKStorage{}

	assert.False(t, storage.IsStarted())
	assert.False(t, storage.IsClosed())

	storage.started.Store(true)
	assert.True(t, storage.IsStarted())

	storage.closed.Store(true)
	assert.False(t, storage.IsStarted()) // started && !closed
	assert.True(t, storage.IsClosed())
}

func TestSDKStorage_Operations_NotStarted(t *testing.T) {
	storage := &SDKStorage{}

	err := storage.Put(context.Background(), "Test", 1, []byte("data"), 0)
	require.Error(t, err)
	var target ErrStorageNotStarted
	assert.ErrorAs(t, err, &target)

	_, _, err = storage.Get(context.Background(), "Test", 1, 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	err = storage.Delete(context.Background(), "Test", 1, 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	_, _, err = storage.List(context.Background(), "Test", 10, "", 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	_, err = storage.Query(context.Background(), "Test", "field", []byte("value"), 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)
}

func TestSDKStorage_Stop(t *testing.T) {
	storage := &SDKStorage{}
	storage.started.Store(true)

	err := storage.Stop(context.Background())
	require.NoError(t, err)
	assert.False(t, storage.IsStarted())
	assert.True(t, storage.IsClosed())
}

func TestSDKStorage_SDK_ReturnsNil(t *testing.T) {
	storage := &SDKStorage{}
	assert.Nil(t, storage.SDK())
}

// =============================================================================
// isNotFoundString helper
// =============================================================================

func TestIsNotFoundString(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"not found lowercase", errors.New("entity not found"), true},
		{"not found uppercase", errors.New("Entity Not Found"), true},
		{"not_found underscore", errors.New("key_not_found"), true},
		{"NOT_FOUND caps", errors.New("KEY_NOT_FOUND"), true},
		{"unrelated error", errors.New("connection refused"), false},
		{"empty error", errors.New(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNotFoundString(tt.err))
		})
	}
}

// =============================================================================
// parsePageToken / formatPageToken edge cases
// =============================================================================

func TestParsePageToken_ShortToken(t *testing.T) {
	result := parsePageToken("short")
	assert.Equal(t, uint64(0), result)
}

func TestFormatPageToken_Roundtrip(t *testing.T) {
	id := uint64(12345678)
	token := formatPageToken(id)
	result := parsePageToken(token)
	assert.Equal(t, id, result)
}

func TestParsePageToken_EmptyString(t *testing.T) {
	result := parsePageToken("")
	assert.Equal(t, uint64(0), result)
}

// =============================================================================
// Client: NewClient, lifecycle, operations when not started
// =============================================================================

func TestClient_NewClient_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportEmbedded,
		DataDir:        "",
		WALDir:         "",
		RequestTimeout: 0,
	}
	logger := logging.DefaultLogger()
	_, err := NewClient(cfg, logger)
	require.Error(t, err)
}

func TestClient_NewClient_ValidConfig(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.False(t, client.IsStarted())
	assert.False(t, client.IsClosed())
	assert.True(t, client.IsEmbedded())
	assert.Nil(t, client.SDK())
	assert.Nil(t, client.Service())
}

func TestClient_Start_EmbeddedRequiresService(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	err = client.Start(context.Background())
	require.Error(t, err)
	var target ErrEmbeddedServiceRequired
	assert.ErrorAs(t, err, &target)
}

func TestClient_StartWithService_NilService_Coverage(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	err = client.StartWithService(context.Background(), nil)
	require.Error(t, err)
	var target ErrEmbeddedServiceRequired
	assert.ErrorAs(t, err, &target)
}

func TestClient_Stop_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	err = client.Stop(context.Background())
	require.NoError(t, err)
	assert.True(t, client.IsClosed())
}

func TestClient_Stop_Idempotent(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	require.NoError(t, client.Stop(context.Background()))
	require.NoError(t, client.Stop(context.Background()))
}

func TestClient_Start_AfterClosed(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	require.NoError(t, client.Stop(context.Background()))
	err = client.Start(context.Background())
	require.Error(t, err)
	var target ErrServerClosed
	assert.ErrorAs(t, err, &target)
}

func TestClient_StartWithService_AfterClosed(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	require.NoError(t, client.Stop(context.Background()))
	err = client.StartWithService(context.Background(), nil)
	require.Error(t, err)
	var target ErrServerClosed
	assert.ErrorAs(t, err, &target)
}

func TestClient_Operations_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()

	err = client.Put(ctx, "Test", 1, []byte("data"), 0)
	require.Error(t, err)
	var target ErrServerNotStarted
	assert.ErrorAs(t, err, &target)

	_, _, err = client.Get(ctx, "Test", 1, 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	err = client.Delete(ctx, "Test", 1, 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	_, _, err = client.List(ctx, "Test", 10, "", 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)

	_, err = client.Query(ctx, "Test", "field", []byte("value"), 0)
	require.Error(t, err)
	assert.ErrorAs(t, err, &target)
}

func TestClient_ListEntityTypes_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	_, _, _, err = client.ListEntityTypes(context.Background(), 10, "")
	require.Error(t, err)
}

func TestClient_toSDKConsistency(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	tests := []ConsistencyLevel{
		ConsistencyLinearizable,
		ConsistencyStrong,
		ConsistencyEventual,
		ConsistencyLevel(99), // unknown defaults to linearizable
	}

	for _, level := range tests {
		result := client.toSDKConsistency(level)
		assert.NotNil(t, result)
	}
}

func TestClient_ensureDeadline_WithExisting(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := client.ensureDeadline(ctx)
	deadline, ok := result.Deadline()
	assert.True(t, ok)
	assert.False(t, deadline.IsZero())
}

func TestClient_ensureDeadline_WithoutExisting(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	client, err := NewClient(cfg, logger)
	require.NoError(t, err)

	result := client.ensureDeadline(context.Background())
	deadline, ok := result.Deadline()
	assert.True(t, ok)
	assert.False(t, deadline.IsZero())
}

// =============================================================================
// Factory: DAO accessors not started, SerializerType, Storage
// =============================================================================

func TestFactory_DAO_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	_, err = factory.UserDAO()
	require.Error(t, err)
	var target ErrStorageNotStarted
	assert.ErrorAs(t, err, &target)
	_, err = factory.RegistrationDAO()
	require.Error(t, err)
	_, err = factory.InvitationDAO()
	require.Error(t, err)
	_, err = factory.RoleDAO()
	require.Error(t, err)
	_, err = factory.WebAuthnDAO()
	require.Error(t, err)
	_, err = factory.DeviceDAO()
	require.Error(t, err)
	_, err = factory.DeviceProfileDAO()
	require.Error(t, err)
	_, err = factory.ZoneDAO()
	require.Error(t, err)
}

func TestFactory_SerializerType_Value(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.Equal(t, serializer.SERIALIZER_JSON, factory.SerializerType())
}

func TestFactory_Storage_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.Nil(t, factory.Storage())
}

// =============================================================================
// EmbeddedServer: lifecycle guards
// =============================================================================

func TestEmbeddedServer_New_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportEmbedded,
		DataDir:        "",
		WALDir:         "",
		RequestTimeout: 0,
	}
	logger := logging.DefaultLogger()
	_, err := NewEmbeddedServer(cfg, logger)
	require.Error(t, err)
}

func TestEmbeddedServer_Lifecycle_Guards(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	srv, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err)

	assert.False(t, srv.IsStarted())
	assert.False(t, srv.IsClosed())
	assert.Nil(t, srv.Server())
	assert.Nil(t, srv.Service())

	require.NoError(t, srv.Stop(context.Background()))
	assert.True(t, srv.IsClosed())
	require.NoError(t, srv.Stop(context.Background())) // idempotent
}

func TestEmbeddedServer_NewWithCA_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportEmbedded,
		DataDir:        "",
		WALDir:         "",
		RequestTimeout: 0,
	}
	logger := logging.DefaultLogger()
	_, err := NewEmbeddedServerWithCA(cfg, logger, nil)
	require.Error(t, err)
}

func TestEmbeddedServer_NewWithCA_ValidConfig(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()
	srv, err := NewEmbeddedServerWithCA(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Nil(t, srv.loadActiveCA()) // nil CA was passed
}

// =============================================================================
// DeviceProfileDAO: FindByMACPrefix, FindBySerialPrefix, FindMatchingProfile
// =============================================================================

func TestDeviceProfileDAO_FindByMACPrefix_Success(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "TestRouter",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.FindByMACPrefix(ctx, "52:54:00:AB:CD:EF")
	require.NoError(t, err)
	assert.Equal(t, "TestRouter", retrieved.Model)
}

func TestDeviceProfileDAO_FindByMACPrefix_NotFound(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "TestRouter",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindByMACPrefix(ctx, "AA:BB:CC:DD:EE:FF")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestDeviceProfileDAO_FindByMACPrefix_EmptyMAC(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	_, err := dao.FindByMACPrefix(context.Background(), "")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestDeviceProfileDAO_FindByMACPrefix_NoMatchRules(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{ID: 1, Model: "BasicModel"}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindByMACPrefix(ctx, "52:54:00:AB:CD:EF")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindByMACPrefix_EmptyPrefix(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "EmptyPrefixModel",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "", // empty prefix won't match
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindByMACPrefix(ctx, "52:54:00:AB:CD:EF")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindByMACPrefix_ListError(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("list failed")
	_, err := dao.FindByMACPrefix(context.Background(), "52:54:00:AB:CD:EF")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindBySerialPrefix_Success(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "TestServer",
		MatchRules: &deventities.ProfileMatchRules{
			SerialPrefix: "SN-2025",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	// Case insensitive - input normalized to uppercase
	retrieved, err := dao.FindBySerialPrefix(ctx, "sn-2025-abc123")
	require.NoError(t, err)
	assert.Equal(t, "TestServer", retrieved.Model)
}

func TestDeviceProfileDAO_FindBySerialPrefix_NotFound(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "TestServer",
		MatchRules: &deventities.ProfileMatchRules{
			SerialPrefix: "SN-2025",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindBySerialPrefix(ctx, "DIFFERENT-SERIAL-123")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestDeviceProfileDAO_FindBySerialPrefix_EmptySerial(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	_, err := dao.FindBySerialPrefix(context.Background(), "")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestDeviceProfileDAO_FindBySerialPrefix_ListError(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("list failed")
	_, err := dao.FindBySerialPrefix(context.Background(), "SN-2025")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindBySerialPrefix_EmptyPrefix(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "EmptyPrefixModel",
		MatchRules: &deventities.ProfileMatchRules{
			SerialPrefix: "", // empty prefix won't match
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindBySerialPrefix(ctx, "SN-2025-ABC")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindMatchingProfile_ByMAC(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "MACMatchedRouter",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.FindMatchingProfile(ctx, "52:54:00:ab:cd:ef", "", "")
	require.NoError(t, err)
	assert.Equal(t, "MACMatchedRouter", retrieved.Model)
}

func TestDeviceProfileDAO_FindMatchingProfile_BySerial(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "SerialServer",
		MatchRules: &deventities.ProfileMatchRules{
			SerialPrefix: "SN-2025",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.FindMatchingProfile(ctx, "", "sn-2025-abc", "")
	require.NoError(t, err)
	assert.Equal(t, "SerialServer", retrieved.Model)
}

func TestDeviceProfileDAO_FindMatchingProfile_ByModel(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "SpecificModel",
		MatchRules: &deventities.ProfileMatchRules{
			Model: "SpecificModel",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	retrieved, err := dao.FindMatchingProfile(ctx, "", "", "SpecificModel")
	require.NoError(t, err)
	assert.Equal(t, "SpecificModel", retrieved.Model)
}

func TestDeviceProfileDAO_FindMatchingProfile_NotFound(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{
		ID:    1,
		Model: "SomeModel",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "AA:BB:CC",
		},
	}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindMatchingProfile(ctx, "11:22:33:44:55:66", "XXXX", "OtherModel")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestDeviceProfileDAO_FindMatchingProfile_ListError(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("list failed")
	_, err := dao.FindMatchingProfile(context.Background(), "52:54:00:ab", "SN123", "Model")
	require.Error(t, err)
}

func TestDeviceProfileDAO_FindMatchingProfile_NilMatchRules(t *testing.T) {
	dao, mock := setupMockDeviceProfileDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	profile := &deventities.DeviceProfile{ID: 1, Model: "BasicModel"}
	require.NoError(t, dao.Save(ctx, profile))

	_, err := dao.FindMatchingProfile(ctx, "52:54:00:ab", "SN123", "Model")
	require.Error(t, err)
}

// =============================================================================
// RoleDAO: GetByName edge cases
// =============================================================================

func TestRoleDAO_GetByName_ViaQuery_Match(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()
	role := &dsentities.Role{ID: 1, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))

	retrieved, err := dao.GetByName(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", retrieved.Name)
}

func TestRoleDAO_GetByName_NotFound_Scan(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()
	role := &dsentities.Role{ID: 1, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))

	mock.QueryError = errors.New("no index")
	_, err := dao.GetByName(ctx, "nonexistent")
	require.Error(t, err)
	var target ErrNotFoundByIndex
	assert.ErrorAs(t, err, &target)
}

func TestRoleDAO_GetByName_ListError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	mock.QueryError = errors.New("no index")
	mock.ListError = errors.New("list failed")

	_, err := dao.GetByName(context.Background(), "admin")
	require.Error(t, err)
}

func TestRoleDAO_GetByName_QueryReturnsMismatch_FallsBackToScan(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Save a role that doesn't match the query name
	role := &dsentities.Role{ID: 1, Name: "viewer"}
	require.NoError(t, dao.Save(ctx, role))

	// Also save the target role
	targetRole := &dsentities.Role{ID: 2, Name: "admin"}
	require.NoError(t, dao.Save(ctx, targetRole))

	// MockStorage Query returns ALL entities - none match "admin" in the first pass
	// but it should fall back to scan and find it
	retrieved, err := dao.GetByName(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", retrieved.Name)
}

// =============================================================================
// Invitation: edge cases with invalid JSON in scan
// =============================================================================

func TestInvitationDAO_GetByToken_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewInvitationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeInvitation, 1, []byte("not-json"))

	inv := &dsentities.Invitation{ID: 2, Token: "target-token", Email: "user@test.com"}
	data, _ := json.Marshal(inv)
	mock.SetData(entityTypeInvitation, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByToken(ctx, "target-token")
	require.NoError(t, err)
	assert.Equal(t, "target-token", retrieved.Token)
}

func TestInvitationDAO_GetByEmail_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewInvitationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeInvitation, 1, []byte("not-json"))

	inv := &dsentities.Invitation{ID: 2, Token: "tok", Email: "target@test.com"}
	data, _ := json.Marshal(inv)
	mock.SetData(entityTypeInvitation, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByEmail(ctx, "target@test.com")
	require.NoError(t, err)
	assert.Equal(t, "target@test.com", retrieved.Email)
}

func TestInvitationDAO_GetByTenant_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewInvitationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeInvitation, 1, []byte("not-json"))

	inv := &dsentities.Invitation{ID: 2, Token: "tok", Email: "user@test.com", TenantID: "tenant-abc"}
	data, _ := json.Marshal(inv)
	mock.SetData(entityTypeInvitation, 2, data)

	invitations, err := dao.GetByTenant(ctx, "tenant-abc")
	require.NoError(t, err)
	assert.Len(t, invitations, 1)
}

func TestInvitationDAO_GetPendingByTenant_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewInvitationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeInvitation, 1, []byte("not-json"))

	inv := &dsentities.Invitation{
		ID:       2,
		Token:    "tok",
		Email:    "user@test.com",
		TenantID: "tenant-abc",
		Status:   dsentities.InvitationStatusPending,
	}
	data, _ := json.Marshal(inv)
	mock.SetData(entityTypeInvitation, 2, data)

	invitations, err := dao.GetPendingByTenant(ctx, "tenant-abc")
	require.NoError(t, err)
	assert.Len(t, invitations, 1)
}

// =============================================================================
// Config edge cases: ToQuicBaaSConfig JoinAddresses
// =============================================================================

func TestConfig_ToQuicBaaSConfig_WithJoinAddresses(t *testing.T) {
	cfg := TestConfig(t)
	cfg.JoinAddresses = []string{"peer1:63000", "peer2:63000"}
	dbCfg := cfg.ToQuicBaaSConfig()
	assert.Equal(t, []string{"peer1:63000", "peer2:63000"}, dbCfg.Raft.JoinAddresses)
}

func TestConfig_ToQuicBaaSConfig_WithoutJoinAddresses(t *testing.T) {
	cfg := TestConfig(t)
	cfg.JoinAddresses = nil
	dbCfg := cfg.ToQuicBaaSConfig()
	assert.Nil(t, dbCfg.Raft.JoinAddresses)
}

func TestConfig_ToQuicBaaSConfig_EmptyStorageBackend(t *testing.T) {
	cfg := TestConfig(t)
	cfg.StorageBackend = ""
	dbCfg := cfg.ToQuicBaaSConfig()
	assert.NotEmpty(t, dbCfg.Storage.Backend) // defaults to pebble
}

// =============================================================================
// Zone DAO: GetByName with invalid JSON
// =============================================================================

func TestZoneDAO_GetByName_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewZoneDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeZone, 1, []byte("not-json"))

	zone := &dnsentities.Zone{ID: 2, Name: "example.com", TTL: 3600}
	data, _ := json.Marshal(zone)
	mock.SetData(entityTypeZone, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByName(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", retrieved.Name)
}

// Use dns entities Zone type alias for convenience

// =============================================================================
// Device DAO: GetByModel with invalid JSON, getDeviceByScan "Model" branch
// =============================================================================

func TestDeviceDAO_GetByModel_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDevice, 1, []byte("not-json"))

	device := &deventities.Device{ID: 2, Model: "TargetModel", Serial: "SN001"}
	data, _ := json.Marshal(device)
	mock.SetData(entityTypeDevice, 2, data)

	devices, err := dao.GetByModel(ctx, "TargetModel")
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "SN001", devices[0].Serial)
}

// =============================================================================
// MockStorage: Query with pre-configured results
// =============================================================================

func TestMockStorage_QueryPreConfigured_EmptyResult(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	// Seed data
	mock.SetData("Role", 1, []byte(`{"id":1,"name":"viewer"}`))

	// Set empty pre-configured results for specific query
	mock.SetQueryResult("Role", "Name", []byte("admin"), nil)

	// Should return the pre-configured nil result, not fall back to all entities
	results, err := mock.Query(context.Background(), "Role", "Name", []byte("admin"), 0)
	require.NoError(t, err)
	assert.Nil(t, results)
}

// =============================================================================
// Config: validateEmbeddedConfig memory backend
// =============================================================================

func TestConfig_ValidateEmbeddedConfig_MemoryBackend(t *testing.T) {
	cfg := MemoryTestConfig(t)
	err := cfg.Validate()
	require.NoError(t, err)
}

// =============================================================================
// GenericDAO: Save with serialization-breaking entity (unreachable in practice
// but good to have for edge coverage)
// =============================================================================

func TestGenericDAO_Page_DeserializationWarning(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
		WithRequestTimeout(5*time.Second),
	)

	ctx := context.Background()

	// Seed valid and invalid data
	mock.SetData("TestRole", 1, []byte(`{"id":1,"name":"valid"}`))
	mock.SetData("TestRole", 2, []byte("invalid-json"))
	mock.SetData("TestRole", 3, []byte(`{"id":3,"name":"also-valid"}`))

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.NoError(t, err)
	// Invalid JSON entities are skipped with a warning
	assert.Equal(t, 2, len(result.Entities))
}

// =============================================================================
// MockFactory: Set*DAO methods coverage
// =============================================================================

func TestMockFactory_SetDAOs(t *testing.T) {
	mf := NewMockFactory()

	// We just verify that Set* methods work and DAOs are returned correctly
	// No real DAO instances needed - nil values are acceptable for mock setters
	mf.SetUserDAO(nil)
	userDAO, err := mf.UserDAO()
	require.NoError(t, err)
	assert.Nil(t, userDAO)

	mf.SetRegistrationDAO(nil)
	regDAO, err := mf.RegistrationDAO()
	require.NoError(t, err)
	assert.Nil(t, regDAO)

	mf.SetInvitationDAO(nil)
	invDAO, err := mf.InvitationDAO()
	require.NoError(t, err)
	assert.Nil(t, invDAO)

	mf.SetRoleDAO(nil)
	roleDAO, err := mf.RoleDAO()
	require.NoError(t, err)
	assert.Nil(t, roleDAO)

	mf.SetWebAuthnDAO(nil)
	waDAO, err := mf.WebAuthnDAO()
	require.NoError(t, err)
	assert.Nil(t, waDAO)

	mf.SetDeviceDAO(nil)
	devDAO, err := mf.DeviceDAO()
	require.NoError(t, err)
	assert.Nil(t, devDAO)

	mf.SetDeviceProfileDAO(nil)
	dpDAO, err := mf.DeviceProfileDAO()
	require.NoError(t, err)
	assert.Nil(t, dpDAO)

	mf.SetZoneDAO(nil)
	zoneDAO, err := mf.ZoneDAO()
	require.NoError(t, err)
	assert.Nil(t, zoneDAO)
}

// =============================================================================
// ErrStorageClosed, ErrStorageNotStarted, ErrContextCancelled in errors.go
// These are lines 197, 204, 211 - the last 3 error types
// =============================================================================

func TestErrStorageClosed_ErrorMessage(t *testing.T) {
	err := ErrStorageClosed{}
	assert.NotEmpty(t, err.Error())
	assert.Contains(t, err.Error(), "storage is closed")
}

func TestErrStorageNotStarted_ErrorMessage(t *testing.T) {
	err := ErrStorageNotStarted{}
	assert.NotEmpty(t, err.Error())
	assert.Contains(t, err.Error(), "storage not started")
}

// =============================================================================
// SDKClient: Config, Transport, IsEmbedded accessors
// (sdk.go lines 148, 153, 158)
// =============================================================================

func TestSDKClient_ConfigAccessor(t *testing.T) {
	cfg := &Config{Transport: TransportGRPC, Address: "localhost:10443"}
	sdk := &SDKClient{config: cfg}
	assert.Equal(t, cfg, sdk.Config())
	assert.Equal(t, "localhost:10443", sdk.Config().Address)
}

func TestSDKClient_TransportAccessor(t *testing.T) {
	sdk := &SDKClient{config: &Config{Transport: TransportREST}}
	assert.Equal(t, TransportREST, sdk.Transport())
}

func TestSDKClient_IsEmbeddedAccessor(t *testing.T) {
	embedded := &SDKClient{config: &Config{Transport: TransportEmbedded}}
	assert.True(t, embedded.IsEmbedded())

	remote := &SDKClient{config: &Config{Transport: TransportQUIC}}
	assert.False(t, remote.IsEmbedded())
}

// =============================================================================
// RoleDAO: getRoleByScan with invalid JSON data (continue path)
// =============================================================================

func TestRoleDAO_GetByName_ScanInvalidJSON(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRoleDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	// Invalid JSON should be skipped
	mock.SetData(entityTypeRole, 1, []byte("invalid json"))

	// Valid role
	role := &dsentities.Role{ID: 2, Name: "admin"}
	data, _ := json.Marshal(role)
	mock.SetData(entityTypeRole, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByName(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", retrieved.Name)
}

// =============================================================================
// DeviceDAO: getDeviceByScan invalid JSON
// =============================================================================

func TestDeviceDAO_FindBySerial_ScanInvalidJSON(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDevice, 1, []byte("not json"))

	device := &deventities.Device{ID: 2, Model: "TestModel", Serial: "SN002"}
	data, _ := json.Marshal(device)
	mock.SetData(entityTypeDevice, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.FindBySerial(ctx, "SN002")
	require.NoError(t, err)
	assert.Equal(t, "SN002", retrieved.Serial)
}

// =============================================================================
// DeviceProfileDAO: getProfileByScan invalid JSON, FindByMACPrefix/SerialPrefix
// invalid JSON in scan
// =============================================================================

func TestDeviceProfileDAO_GetByModel_ScanInvalidJSON(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDeviceProfile, 1, []byte("not json"))

	profile := &deventities.DeviceProfile{ID: 2, Model: "TargetModel"}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByModel(ctx, "TargetModel")
	require.NoError(t, err)
	assert.Equal(t, "TargetModel", retrieved.Model)
}

func TestDeviceProfileDAO_FindByMACPrefix_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDeviceProfile, 1, []byte("bad json"))

	profile := &deventities.DeviceProfile{
		ID:    2,
		Model: "Router",
		MatchRules: &deventities.ProfileMatchRules{
			MACPrefix: "52:54:00",
		},
	}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 2, data)

	retrieved, err := dao.FindByMACPrefix(ctx, "52:54:00:ab:cd:ef")
	require.NoError(t, err)
	assert.Equal(t, "Router", retrieved.Model)
}

func TestDeviceProfileDAO_FindBySerialPrefix_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDeviceProfile, 1, []byte("bad json"))

	profile := &deventities.DeviceProfile{
		ID:    2,
		Model: "Server",
		MatchRules: &deventities.ProfileMatchRules{
			SerialPrefix: "SN-2025",
		},
	}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 2, data)

	retrieved, err := dao.FindBySerialPrefix(ctx, "SN-2025-XYZ")
	require.NoError(t, err)
	assert.Equal(t, "Server", retrieved.Model)
}

func TestDeviceProfileDAO_FindMatchingProfile_InvalidJSON_Skipped(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewDeviceProfileDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeDeviceProfile, 1, []byte("bad json"))

	profile := &deventities.DeviceProfile{
		ID:    2,
		Model: "MatchedModel",
		MatchRules: &deventities.ProfileMatchRules{
			Model: "MatchedModel",
		},
	}
	data, _ := json.Marshal(profile)
	mock.SetData(entityTypeDeviceProfile, 2, data)

	retrieved, err := dao.FindMatchingProfile(ctx, "", "", "MatchedModel")
	require.NoError(t, err)
	assert.Equal(t, "MatchedModel", retrieved.Model)
}

// =============================================================================
// GenericDAO: Get with invalid JSON stored in mock (deserialization error)
// =============================================================================

func TestGenericDAO_Get_DeserializationError(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
		WithRequestTimeout(5*time.Second),
	)

	mock.SetData("TestRole", 123, []byte("not valid json"))

	_, err := dao.Get(context.Background(), 123)
	require.Error(t, err)
	var target ErrDeserializationFailed
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "TestRole", target.EntityType)
}

// =============================================================================
// Config: validateEmbeddedConfig empty backend with empty DataDir/WALDir
// =============================================================================

func TestConfig_ValidateEmbeddedConfig_EmptyBackend_EmptyDataDir(t *testing.T) {
	cfg := &Config{
		Transport:      TransportEmbedded,
		StorageBackend: "",
		DataDir:        "",
		WALDir:         "",
		RequestTimeout: 5 * time.Second,
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidConfig
	assert.ErrorAs(t, err, &target)
}

// =============================================================================
// ZoneDAO: getZoneByScan invalid JSON
// =============================================================================

func TestZoneDAO_GetByName_ScanInvalidJSON(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewZoneDAO(mock, logger, WithRequestTimeout(5*time.Second))

	ctx := context.Background()

	mock.SetData(entityTypeZone, 1, []byte("bad json"))

	zone := &dnsentities.Zone{ID: 2, Name: "example.com", TTL: 3600}
	data, _ := json.Marshal(zone)
	mock.SetData(entityTypeZone, 2, data)

	mock.QueryError = errors.New("no index")

	retrieved, err := dao.GetByName(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "example.com", retrieved.Name)
}

// =============================================================================
// Config: Validate with unsupported transport number (default case)
// =============================================================================

func TestConfig_Validate_UnsupportedTransportNumber(t *testing.T) {
	cfg := &Config{
		Transport:      Transport(99),
		RequestTimeout: 30 * time.Second,
	}
	err := cfg.Validate()
	require.Error(t, err)
	var target ErrInvalidConfig
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "Transport", target.Field)
}

// =============================================================================
// MockStorage: List with empty entity type (no data for type)
// =============================================================================

func TestMockStorage_List_EmptyEntityType(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	result, nextToken, err := mock.List(context.Background(), "NonExistent", 10, "", 0)
	require.NoError(t, err)
	assert.Empty(t, result)
	assert.Empty(t, nextToken)
}

// =============================================================================
// MockStorage: Query with empty entity type (no data)
// =============================================================================

func TestMockStorage_Query_EmptyEntityType(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	result, err := mock.Query(context.Background(), "NonExistent", "field", []byte("value"), 0)
	require.NoError(t, err)
	assert.Empty(t, result)
}

// =============================================================================
// MockStorage: Delete non-existent entity (ok)
// =============================================================================

func TestMockStorage_Delete_NonExistentEntity(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	err := mock.Delete(context.Background(), "NonExistent", 999, 0)
	require.NoError(t, err)
}

// =============================================================================
// MockStorage: Delete from type that does exist, but ID doesn't
// =============================================================================

func TestMockStorage_Delete_ExistingType_NonExistentID(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	mock.SetData("TestEntity", 1, []byte("data"))
	err := mock.Delete(context.Background(), "TestEntity", 999, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, mock.Count("TestEntity"))
}

// =============================================================================
// ErrSDKClientNil explicit Error() call
// =============================================================================

func TestErrSDKClientNil_ErrorMessage(t *testing.T) {
	err := ErrSDKClientNil{}
	msg := err.Error()
	assert.Contains(t, msg, "cannot be nil")
}
