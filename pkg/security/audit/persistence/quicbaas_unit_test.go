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

package persistence

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVClient implements a mock KV client for testing.
type mockKVClient struct {
	mu       sync.RWMutex
	entities map[uint64][]byte
	putErr   error
	listErr  error
}

func newMockKVClient() *mockKVClient {
	return &mockKVClient{
		entities: make(map[uint64][]byte),
	}
}

func (m *mockKVClient) Put(ctx context.Context, req *service.PutRequest) (*service.PutResponse, error) {
	if m.putErr != nil {
		return nil, m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entities[req.ID] = req.Data
	return &service.PutResponse{}, nil
}

func (m *mockKVClient) Get(ctx context.Context, req *service.GetRequest) (*service.GetResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, found := m.entities[req.ID]
	return &service.GetResponse{Data: data, Found: found}, nil
}

func (m *mockKVClient) Delete(ctx context.Context, req *service.DeleteRequest) (*service.DeleteResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entities, req.ID)
	return &service.DeleteResponse{}, nil
}

func (m *mockKVClient) List(ctx context.Context, req *service.ListRequest) (*service.ListResponse, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	entities := make([]*service.Entity, 0, len(m.entities))
	for id, data := range m.entities {
		entities = append(entities, &service.Entity{
			ID:   id,
			Data: data,
		})
	}

	return &service.ListResponse{
		Entities:      entities,
		NextPageToken: "",
	}, nil
}

// mockQuicBaaSClient implements a minimal mock QuicBaaS client for testing.
type mockQuicBaaSClient struct {
	kv *mockKVClient
}

func newMockQuicBaaSClient() *mockQuicBaaSClient {
	return &mockQuicBaaSClient{
		kv: newMockKVClient(),
	}
}

func (m *mockQuicBaaSClient) KV() interface {
	Put(ctx context.Context, req *service.PutRequest) (*service.PutResponse, error)
	Get(ctx context.Context, req *service.GetRequest) (*service.GetResponse, error)
	Delete(ctx context.Context, req *service.DeleteRequest) (*service.DeleteResponse, error)
	List(ctx context.Context, req *service.ListRequest) (*service.ListResponse, error)
} {
	return m.kv
}

func (m *mockQuicBaaSClient) Close() error {
	return nil
}

func (m *mockQuicBaaSClient) Transport() interface{} {
	return nil
}

// mockSDKClient wraps mockQuicBaaSClient to satisfy quicbaas.Client interface.
type mockSDKClient struct {
	mock *mockQuicBaaSClient
}

func newMockSDKClient() *mockSDKClient {
	return &mockSDKClient{
		mock: newMockQuicBaaSClient(),
	}
}

func (m *mockSDKClient) KV() kvClient {
	return m.mock.kv
}

func (m *mockSDKClient) setKVPutError(err error) {
	m.mock.kv.putErr = err
}

func (m *mockSDKClient) setKVListError(err error) {
	m.mock.kv.listErr = err
}

// kvClient interface for mock compatibility.
type kvClient interface {
	Put(ctx context.Context, req *service.PutRequest) (*service.PutResponse, error)
	Get(ctx context.Context, req *service.GetRequest) (*service.GetResponse, error)
	Delete(ctx context.Context, req *service.DeleteRequest) (*service.DeleteResponse, error)
	List(ctx context.Context, req *service.ListRequest) (*service.ListResponse, error)
}

// testPersister wraps QuicBaaSPersister with a mock client for testing.
type testPersister struct {
	*QuicBaaSPersister
	mockClient *mockSDKClient
}

func newTestPersister(t *testing.T) *testPersister {
	mock := newMockSDKClient()

	// Create a test persister that uses the mock client
	p := &QuicBaaSPersister{
		shardID:        DefaultShardID,
		requestTimeout: DefaultRequestTimeout,
	}
	p.started.Store(true)

	return &testPersister{
		QuicBaaSPersister: p,
		mockClient:        mock,
	}
}

// Persist overrides to use mock client.
func (tp *testPersister) Persist(ctx context.Context, event audit.AuditEvent) error {
	if tp.closed.Load() {
		return ErrStorageClosed{}
	}
	if !tp.started.Load() {
		return ErrStorageNotStarted{}
	}

	stored := newStoredEvent(event)
	data, err := json.Marshal(stored)
	if err != nil {
		return ErrSerializationFailed{EventID: event.ID, Cause: err}
	}

	ctx, cancel := context.WithTimeout(ctx, tp.requestTimeout)
	defer cancel()

	req := &service.PutRequest{
		EntityType:  EntityTypeAuditEvent,
		ID:          stored.ID,
		Data:        data,
		ShardID:     tp.shardID,
		Consistency: service.ConsistencyLevelLinearizable,
	}

	if _, err := tp.mockClient.KV().Put(ctx, req); err != nil {
		return ErrPutFailed{EventID: event.ID, Cause: err}
	}

	return nil
}

// Query overrides to use mock client.
func (tp *testPersister) Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditEvent, error) {
	if tp.closed.Load() {
		return nil, ErrStorageClosed{}
	}
	if !tp.started.Load() {
		return nil, ErrStorageNotStarted{}
	}

	if err := filter.Validate(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, tp.requestTimeout)
	defer cancel()

	qb := newQueryBuilder(filter)

	events, err := tp.fetchAndFilterEventsWithMock(ctx, qb)
	if err != nil {
		return nil, ErrQueryFailed{Reason: "fetch failed", Cause: err}
	}

	tp.sortEvents(events, filter.SortDesc)
	events = tp.applyPagination(events, qb.getEffectiveOffset(), qb.getEffectiveLimit())

	return events, nil
}

func (tp *testPersister) fetchAndFilterEventsWithMock(ctx context.Context, qb *queryBuilder) ([]audit.AuditEvent, error) {
	var events []audit.AuditEvent
	pageToken := ""

	for {
		req := &service.ListRequest{
			EntityType: EntityTypeAuditEvent,
			PageSize:   1000,
			PageToken:  pageToken,
			ShardID:    tp.shardID,
		}

		resp, err := tp.mockClient.KV().List(ctx, req)
		if err != nil {
			return nil, err
		}

		for _, entity := range resp.Entities {
			var stored storedEvent
			if err := json.Unmarshal(entity.Data, &stored); err != nil {
				continue
			}

			if qb.matchesEvent(&stored.Event) {
				events = append(events, stored.Event)
			}
		}

		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	return events, nil
}

func createTestEvent(id string, actor string, action string, outcome audit.Outcome) audit.AuditEvent {
	return audit.AuditEvent{
		ID:           id,
		Timestamp:    time.Now(),
		Actor:        actor,
		Action:       action,
		Resource:     "test-resource",
		ResourceType: "test",
		Outcome:      outcome,
		SourceIP:     "192.168.1.1",
		RequestID:    "req-" + id,
	}
}

func TestNewQuicBaaSPersister_NilClient(t *testing.T) {
	_, err := NewQuicBaaSPersister(nil)
	require.Error(t, err)

	var nilErr ErrNilSDKClient
	assert.True(t, errors.As(err, &nilErr))
}

func TestQuicBaaSPersister_Persist_Success(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()
	event := createTestEvent("evt-001", "user@example.com", "login", audit.OutcomeSuccess)

	err := tp.Persist(ctx, event)
	require.NoError(t, err)
}

func TestQuicBaaSPersister_Persist_Closed(t *testing.T) {
	tp := newTestPersister(t)
	tp.Close()

	ctx := context.Background()
	event := createTestEvent("evt-001", "user@example.com", "login", audit.OutcomeSuccess)

	err := tp.Persist(ctx, event)
	require.Error(t, err)

	var closedErr ErrStorageClosed
	assert.True(t, errors.As(err, &closedErr))
}

func TestQuicBaaSPersister_Persist_NotStarted(t *testing.T) {
	tp := newTestPersister(t)
	tp.started.Store(false)

	ctx := context.Background()
	event := createTestEvent("evt-001", "user@example.com", "login", audit.OutcomeSuccess)

	err := tp.Persist(ctx, event)
	require.Error(t, err)

	var notStartedErr ErrStorageNotStarted
	assert.True(t, errors.As(err, &notStartedErr))
}

func TestQuicBaaSPersister_Persist_PutError(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	tp.mockClient.setKVPutError(errors.New("storage error"))

	ctx := context.Background()
	event := createTestEvent("evt-001", "user@example.com", "login", audit.OutcomeSuccess)

	err := tp.Persist(ctx, event)
	require.Error(t, err)

	var putErr ErrPutFailed
	assert.True(t, errors.As(err, &putErr))
}

func TestQuicBaaSPersister_Query_Success(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	// Persist some events
	events := []audit.AuditEvent{
		createTestEvent("evt-001", "user1@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-002", "user2@example.com", "logout", audit.OutcomeSuccess),
		createTestEvent("evt-003", "user1@example.com", "create", audit.OutcomeFailure),
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	// Query all events
	filter := audit.AuditFilter{}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 3)
}

func TestQuicBaaSPersister_Query_FilterByActor(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	// Persist events with different actors
	events := []audit.AuditEvent{
		createTestEvent("evt-001", "user1@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-002", "user2@example.com", "logout", audit.OutcomeSuccess),
		createTestEvent("evt-003", "user1@example.com", "create", audit.OutcomeFailure),
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	// Query for user1 only
	filter := audit.AuditFilter{Actor: "user1@example.com"}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	for _, e := range result {
		assert.Equal(t, "user1@example.com", e.Actor)
	}
}

func TestQuicBaaSPersister_Query_FilterByAction(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		createTestEvent("evt-001", "user1@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-002", "user2@example.com", "logout", audit.OutcomeSuccess),
		createTestEvent("evt-003", "user1@example.com", "login", audit.OutcomeFailure),
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	filter := audit.AuditFilter{Action: "login"}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	for _, e := range result {
		assert.Equal(t, "login", e.Action)
	}
}

func TestQuicBaaSPersister_Query_FilterByOutcome(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		createTestEvent("evt-001", "user1@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-002", "user2@example.com", "logout", audit.OutcomeSuccess),
		createTestEvent("evt-003", "user1@example.com", "create", audit.OutcomeFailure),
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	filter := audit.AuditFilter{Outcome: audit.OutcomeFailure}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, audit.OutcomeFailure, result[0].Outcome)
}

func TestQuicBaaSPersister_Query_FilterByTimeRange(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	now := time.Now()
	events := []audit.AuditEvent{
		{
			ID:           "evt-001",
			Timestamp:    now.Add(-2 * time.Hour),
			Actor:        "user1@example.com",
			Action:       "login",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
		{
			ID:           "evt-002",
			Timestamp:    now.Add(-1 * time.Hour),
			Actor:        "user2@example.com",
			Action:       "logout",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
		{
			ID:           "evt-003",
			Timestamp:    now,
			Actor:        "user1@example.com",
			Action:       "create",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	// Query for events in the last 90 minutes
	filter := audit.AuditFilter{
		StartTime: now.Add(-90 * time.Minute),
		EndTime:   now.Add(time.Minute),
	}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestQuicBaaSPersister_Query_Pagination(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	// Create 10 events
	for i := 0; i < 10; i++ {
		event := createTestEvent(
			"evt-"+string(rune('0'+i)),
			"user@example.com",
			"action",
			audit.OutcomeSuccess,
		)
		event.Timestamp = time.Now().Add(time.Duration(i) * time.Second)
		err := tp.Persist(ctx, event)
		require.NoError(t, err)
	}

	// Query with limit and offset
	filter := audit.AuditFilter{
		Limit:  3,
		Offset: 2,
	}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 3)
}

func TestQuicBaaSPersister_Query_SortDescending(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	now := time.Now()
	events := []audit.AuditEvent{
		{
			ID:           "evt-001",
			Timestamp:    now.Add(-2 * time.Hour),
			Actor:        "user@example.com",
			Action:       "action1",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
		{
			ID:           "evt-002",
			Timestamp:    now.Add(-1 * time.Hour),
			Actor:        "user@example.com",
			Action:       "action2",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
		{
			ID:           "evt-003",
			Timestamp:    now,
			Actor:        "user@example.com",
			Action:       "action3",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
		},
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	// Query with descending sort
	filter := audit.AuditFilter{SortDesc: true}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	require.Len(t, result, 3)

	// Verify descending order
	assert.Equal(t, "evt-003", result[0].ID)
	assert.Equal(t, "evt-002", result[1].ID)
	assert.Equal(t, "evt-001", result[2].ID)
}

func TestQuicBaaSPersister_Query_Closed(t *testing.T) {
	tp := newTestPersister(t)
	tp.Close()

	ctx := context.Background()
	filter := audit.AuditFilter{}

	_, err := tp.Query(ctx, filter)
	require.Error(t, err)

	var closedErr ErrStorageClosed
	assert.True(t, errors.As(err, &closedErr))
}

func TestQuicBaaSPersister_Query_NotStarted(t *testing.T) {
	tp := newTestPersister(t)
	tp.started.Store(false)

	ctx := context.Background()
	filter := audit.AuditFilter{}

	_, err := tp.Query(ctx, filter)
	require.Error(t, err)

	var notStartedErr ErrStorageNotStarted
	assert.True(t, errors.As(err, &notStartedErr))
}

func TestQuicBaaSPersister_Query_InvalidFilter(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()
	filter := audit.AuditFilter{
		StartTime: time.Now(),
		EndTime:   time.Now().Add(-1 * time.Hour), // End before start
	}

	_, err := tp.Query(ctx, filter)
	require.Error(t, err)
}

func TestQuicBaaSPersister_Query_ListError(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	tp.mockClient.setKVListError(errors.New("list error"))

	ctx := context.Background()
	filter := audit.AuditFilter{}

	_, err := tp.Query(ctx, filter)
	require.Error(t, err)

	var queryErr ErrQueryFailed
	assert.True(t, errors.As(err, &queryErr))
}

func TestQuicBaaSPersister_Close_Multiple(t *testing.T) {
	tp := newTestPersister(t)

	err := tp.Close()
	require.NoError(t, err)

	// Second close should be no-op
	err = tp.Close()
	require.NoError(t, err)

	assert.True(t, tp.IsClosed())
	assert.False(t, tp.IsStarted())
}

func TestQuicBaaSPersister_Query_MultipleFilters(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		createTestEvent("evt-001", "user1@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-002", "user1@example.com", "logout", audit.OutcomeSuccess),
		createTestEvent("evt-003", "user2@example.com", "login", audit.OutcomeSuccess),
		createTestEvent("evt-004", "user1@example.com", "login", audit.OutcomeFailure),
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	// Query with multiple filters
	filter := audit.AuditFilter{
		Actor:   "user1@example.com",
		Action:  "login",
		Outcome: audit.OutcomeSuccess,
	}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "evt-001", result[0].ID)
}

func TestQuicBaaSPersister_Query_EmptyResult(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()
	filter := audit.AuditFilter{Actor: "nonexistent@example.com"}

	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestQuicBaaSPersister_Query_OffsetBeyondTotal(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	// Persist 3 events
	for i := 0; i < 3; i++ {
		event := createTestEvent(
			"evt-"+string(rune('0'+i)),
			"user@example.com",
			"action",
			audit.OutcomeSuccess,
		)
		err := tp.Persist(ctx, event)
		require.NoError(t, err)
	}

	// Query with offset beyond total
	filter := audit.AuditFilter{
		Offset: 100,
		Limit:  10,
	}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestQuicBaaSPersister_FilterByResourceType(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		{
			ID:           "evt-001",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "create",
			Resource:     "cert-123",
			ResourceType: "certificate",
			Outcome:      audit.OutcomeSuccess,
		},
		{
			ID:           "evt-002",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "create",
			Resource:     "key-456",
			ResourceType: "key",
			Outcome:      audit.OutcomeSuccess,
		},
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	filter := audit.AuditFilter{ResourceType: "certificate"}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "certificate", result[0].ResourceType)
}

func TestQuicBaaSPersister_FilterBySourceIP(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		{
			ID:           "evt-001",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "login",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
			SourceIP:     "192.168.1.1",
		},
		{
			ID:           "evt-002",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "login",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
			SourceIP:     "10.0.0.1",
		},
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	filter := audit.AuditFilter{SourceIP: "192.168.1.1"}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "192.168.1.1", result[0].SourceIP)
}

func TestQuicBaaSPersister_FilterByRequestID(t *testing.T) {
	tp := newTestPersister(t)
	defer tp.Close()

	ctx := context.Background()

	events := []audit.AuditEvent{
		{
			ID:           "evt-001",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "action",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
			RequestID:    "req-abc",
		},
		{
			ID:           "evt-002",
			Timestamp:    time.Now(),
			Actor:        "user@example.com",
			Action:       "action",
			Resource:     "test",
			ResourceType: "test",
			Outcome:      audit.OutcomeSuccess,
			RequestID:    "req-xyz",
		},
	}

	for _, e := range events {
		err := tp.Persist(ctx, e)
		require.NoError(t, err)
	}

	filter := audit.AuditFilter{RequestID: "req-abc"}
	result, err := tp.Query(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "req-abc", result[0].RequestID)
}
