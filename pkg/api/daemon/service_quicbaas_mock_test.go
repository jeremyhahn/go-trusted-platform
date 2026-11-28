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
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// getQuicBaaSClient Tests with MockFactory
// =============================================================================

func TestGetQuicBaaSClient_WithInjectedFactory(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	client, dataDir, err := svc.getQuicBaaSClient()
	if err != nil {
		t.Fatalf("getQuicBaaSClient failed: %v", err)
	}

	if client == nil {
		t.Error("expected non-nil client")
	}

	if dataDir != "/tmp/mock-quicbaas" {
		t.Errorf("expected dataDir '/tmp/mock-quicbaas', got '%s'", dataDir)
	}
}

func TestGetQuicBaaSClient_InjectedFactoryNotStarted(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	// Don't start the factory

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	_, _, err = svc.getQuicBaaSClient()
	if err == nil {
		t.Error("expected error for client not started")
	}

	var dbErr ErrDatabaseNotAvailable
	if !errors.As(err, &dbErr) {
		t.Errorf("expected ErrDatabaseNotAvailable, got %T", err)
	}
}

func TestGetQuicBaaSClient_NoFactoryAndNoApp(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	_, _, err = svc.getQuicBaaSClient()
	if err == nil {
		t.Error("expected error for nil app")
	}

	var dbErr ErrDatabaseNotAvailable
	if !errors.As(err, &dbErr) {
		t.Errorf("expected ErrDatabaseNotAvailable, got %T", err)
	}
}

// =============================================================================
// ListEntityTypes Tests with MockFactory
// =============================================================================

func TestListEntityTypes_Success(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	// Pre-populate mock with data - SetData automatically adds entity types
	mockClient := mockFactory.MockClient()
	mockClient.SetData("users", 1, []byte(`{"name":"alice"}`))
	mockClient.SetData("users", 2, []byte(`{"name":"bob"}`))
	mockClient.SetData("devices", 1, []byte(`{"type":"laptop"}`))
	mockClient.SetData("certificates", 1, []byte(`{"cn":"test"}`))

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if len(resp.EntityTypes) != 3 {
		t.Errorf("expected 3 entity types, got %d", len(resp.EntityTypes))
	}

	// Check users count
	var usersFound bool
	for _, et := range resp.EntityTypes {
		if et.Name == "users" {
			usersFound = true
			if et.EntityCount != 2 {
				t.Errorf("expected 2 users, got %d", et.EntityCount)
			}
			if et.Status != "active" {
				t.Errorf("expected status 'active', got '%s'", et.Status)
			}
		}
	}
	if !usersFound {
		t.Error("users entity type not found")
	}
}

func TestListEntityTypes_EmptyDatabase(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if len(resp.EntityTypes) != 0 {
		t.Errorf("expected 0 entity types, got %d", len(resp.EntityTypes))
	}
}

func TestListEntityTypes_ListEntityTypesError(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	// Inject error
	mockClient := mockFactory.MockClient()
	mockClient.ListEntityTypesError = errors.New("database error")

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	_, err = svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err == nil {
		t.Error("expected error from ListEntityTypes")
	}
}

func TestListEntityTypes_ListEntitiesError(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"users"})
	mockClient.ListError = errors.New("list error")

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes should not fail, got: %v", err)
	}

	// Entity type should be returned with error status
	if len(resp.EntityTypes) != 1 {
		t.Errorf("expected 1 entity type, got %d", len(resp.EntityTypes))
	}

	if resp.EntityTypes[0].Status != "error" {
		t.Errorf("expected status 'error', got '%s'", resp.EntityTypes[0].Status)
	}
}

func TestListEntityTypes_NoFactory(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	ctx := context.Background()
	_, err = svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err == nil {
		t.Error("expected error for no factory")
	}
}

func TestListEntityTypes_MultipleTypes(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"type1", "type2", "type3"})

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}

	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	if len(resp.EntityTypes) != 3 {
		t.Errorf("expected 3 entity types, got %d", len(resp.EntityTypes))
	}
}

// =============================================================================
// DumpEntityType Tests with MockFactory
// =============================================================================

// mockDumpStream implements the server stream interface for DumpEntityType
type mockDumpStream struct {
	platformv1.PlatformDaemon_DumpEntityTypeServer
	responses []*platformv1.DumpEntityTypeResponse
	ctx       context.Context
	sendErr   error
}

func (m *mockDumpStream) Send(resp *platformv1.DumpEntityTypeResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockDumpStream) Context() context.Context {
	return m.ctx
}

func TestDumpEntityType_AllTypes(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	// SetData automatically adds entity types
	mockClient := mockFactory.MockClient()
	mockClient.SetData("users", 1, []byte(`{"name":"alice"}`))
	mockClient.SetData("devices", 1, []byte(`{"type":"laptop"}`))

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, stream)
	if err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}

	if len(stream.responses) != 2 {
		t.Errorf("expected 2 responses, got %d", len(stream.responses))
	}
}

func TestDumpEntityType_SpecificType(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	mockClient := mockFactory.MockClient()
	mockClient.SetData("users", 1, []byte(`{"name":"alice"}`))
	mockClient.SetData("users", 2, []byte(`{"name":"bob"}`))
	mockClient.SetData("devices", 1, []byte(`{"type":"laptop"}`))

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{EntityType: "users"}, stream)
	if err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}

	if len(stream.responses) != 2 {
		t.Errorf("expected 2 responses (only users), got %d", len(stream.responses))
	}

	for _, resp := range stream.responses {
		if resp.EntityType != "users" {
			t.Errorf("expected entity type 'users', got '%s'", resp.EntityType)
		}
	}
}

func TestDumpEntityType_EmptyDatabase(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, stream)
	if err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}

	if len(stream.responses) != 0 {
		t.Errorf("expected 0 responses, got %d", len(stream.responses))
	}
}

func TestDumpEntityType_SendError(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	mockClient := mockFactory.MockClient()
	mockClient.SetData("users", 1, []byte(`{"name":"alice"}`))

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{
		ctx:     ctx,
		sendErr: errors.New("stream error"),
	}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{EntityType: "users"}, stream)
	if err == nil {
		t.Error("expected error from send failure")
	}
}

func TestDumpEntityType_ListError(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"users"})
	mockClient.ListError = errors.New("list error")

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, stream)
	if err != nil {
		t.Fatalf("DumpEntityType should not fail on list error, got: %v", err)
	}

	// Should have no responses due to list error
	if len(stream.responses) != 0 {
		t.Errorf("expected 0 responses due to list error, got %d", len(stream.responses))
	}
}

func TestDumpEntityType_NoFactory(t *testing.T) {
	config := DefaultConfig()
	config.App = nil

	svc, err := NewService(config)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	ctx := context.Background()
	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, stream)
	if err == nil {
		t.Error("expected error for no factory")
	}
}

// =============================================================================
// Entity Data Verification
// =============================================================================

func TestDumpEntityType_DataIntegrity(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()
	ctx := context.Background()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	defer mockFactory.Stop(ctx)

	testData := map[string]string{
		"name":  "test-user",
		"email": "test@example.com",
	}
	jsonData, _ := json.Marshal(testData)

	mockClient := mockFactory.MockClient()
	mockClient.SetData("users", 42, jsonData)

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{EntityType: "users"}, stream)
	if err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}

	if len(stream.responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(stream.responses))
	}

	resp := stream.responses[0]
	if resp.EntityId != 42 {
		t.Errorf("expected entity ID 42, got %d", resp.EntityId)
	}

	var decoded map[string]string
	if err := json.Unmarshal(resp.Data, &decoded); err != nil {
		t.Fatalf("failed to decode response data: %v", err)
	}

	if decoded["name"] != "test-user" {
		t.Errorf("expected name 'test-user', got '%s'", decoded["name"])
	}

	if decoded["email"] != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", decoded["email"])
	}
}

// =============================================================================
// WithQuicBaaSFactory Option Tests
// =============================================================================

func TestWithQuicBaaSFactory_SetsFactory(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if svc.quicbaasFactory != mockFactory {
		t.Error("expected quicbaasFactory to be set")
	}
}

func TestNewService_MultipleOptions(t *testing.T) {
	mockFactory := quicbaas.NewMockFactory()

	config := DefaultConfig()
	svc, err := NewService(config,
		WithQuicBaaSFactory(mockFactory),
		// Can add more options here in the future
	)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	if svc.quicbaasFactory != mockFactory {
		t.Error("expected quicbaasFactory to be set")
	}
}

// =============================================================================
// Error Path Coverage
// =============================================================================

func TestGetQuicBaaSClient_NilClientFromFactory(t *testing.T) {
	// Create a custom mock factory that returns nil client
	mockFactory := &nilClientMockFactory{}

	config := DefaultConfig()
	svc, err := NewService(config, WithQuicBaaSFactory(mockFactory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	_, _, err = svc.getQuicBaaSClient()
	if err == nil {
		t.Error("expected error for nil client")
	}

	var dbErr ErrDatabaseNotAvailable
	if !errors.As(err, &dbErr) {
		t.Errorf("expected ErrDatabaseNotAvailable, got %T", err)
	}
}

// nilClientMockFactory returns nil from QuicBaaSClient()
type nilClientMockFactory struct {
	quicbaas.MockFactory
}

func (m *nilClientMockFactory) QuicBaaSClient() quicbaas.ClientInterface {
	return nil
}

func (m *nilClientMockFactory) DataDir() string {
	return "/tmp/test"
}

func (m *nilClientMockFactory) IsStarted() bool {
	return true
}

func (m *nilClientMockFactory) IsClosed() bool {
	return false
}

// aggregatingListClient behaves like the pinned go-quicbaas embedded List:
// it ignores the page token, returns every record in one response and keeps
// the first batch's next token. From the 5th call it returns an empty token
// so a walk that trusts the token ends instead of looping forever.
type aggregatingListClient struct {
	*quicbaas.MockClient
	records int
	calls   int
}

func (c *aggregatingListClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	c.calls++
	entities := make([]*service.Entity, 0, c.records)
	for i := 1; i <= c.records; i++ {
		entities = append(entities, &service.Entity{ID: uint64(i), Data: []byte(`{}`)})
	}
	if c.calls >= 5 {
		return entities, "", nil
	}
	return entities, "batch-1", nil
}

// aggregatingListFactory hands out an aggregatingListClient.
type aggregatingListFactory struct {
	*quicbaas.MockFactory
	client *aggregatingListClient
}

func (f *aggregatingListFactory) QuicBaaSClient() quicbaas.ClientInterface {
	return f.client
}

func newAggregatingListFactory(t *testing.T, ctx context.Context) *aggregatingListFactory {
	t.Helper()
	mockFactory := quicbaas.NewMockFactory()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	t.Cleanup(func() { _ = mockFactory.Stop(ctx) })
	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"users"})
	return &aggregatingListFactory{
		MockFactory: mockFactory,
		client:      &aggregatingListClient{MockClient: mockClient, records: 150},
	}
}

// zeroIDListClient behaves like the pinned go-quicbaas SDK REST List,
// which builds every entity without its ID: each record reads ID 0.
type zeroIDListClient struct {
	*quicbaas.MockClient
}

func (c *zeroIDListClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	return []*service.Entity{
		{ID: 0, Data: []byte(`{"n":1}`)},
		{ID: 0, Data: []byte(`{"n":2}`)},
	}, "", nil
}

// zeroIDListFactory hands out a zeroIDListClient.
type zeroIDListFactory struct {
	*quicbaas.MockFactory
	client *zeroIDListClient
}

func (f *zeroIDListFactory) QuicBaaSClient() quicbaas.ClientInterface {
	return f.client
}

func newZeroIDListFactory(t *testing.T, ctx context.Context) *zeroIDListFactory {
	t.Helper()
	mockFactory := quicbaas.NewMockFactory()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	t.Cleanup(func() { _ = mockFactory.Stop(ctx) })
	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"users"})
	return &zeroIDListFactory{
		MockFactory: mockFactory,
		client:      &zeroIDListClient{MockClient: mockClient},
	}
}

func TestDumpEntityType_RecordsWithoutIDsAreAllSent(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(newZeroIDListFactory(t, ctx)))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	if err := svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{EntityType: "users"}, stream); err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}
	if len(stream.responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(stream.responses))
	}
	got := map[string]bool{}
	for _, resp := range stream.responses {
		got[string(resp.Data)] = true
	}
	for _, want := range []string{`{"n":1}`, `{"n":2}`} {
		if !got[want] {
			t.Errorf("record %s not sent", want)
		}
	}
}

func TestListEntityTypes_RecordsWithoutIDsAreAllCounted(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(newZeroIDListFactory(t, ctx)))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}
	if len(resp.EntityTypes) != 1 {
		t.Fatalf("expected 1 entity type, got %d", len(resp.EntityTypes))
	}
	if resp.EntityTypes[0].EntityCount != 2 {
		t.Errorf("expected users count 2, got %d", resp.EntityTypes[0].EntityCount)
	}
}

func TestListEntityTypes_AggregatedListResponseCountsOnce(t *testing.T) {
	ctx := context.Background()
	factory := newAggregatingListFactory(t, ctx)
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(factory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}
	if resp.TotalEntities != 150 {
		t.Errorf("expected 150 total entities, got %d", resp.TotalEntities)
	}
	if len(resp.EntityTypes) != 1 {
		t.Fatalf("expected 1 entity type, got %d", len(resp.EntityTypes))
	}
	if resp.EntityTypes[0].EntityCount != 150 {
		t.Errorf("expected users count 150, got %d", resp.EntityTypes[0].EntityCount)
	}
}

func TestDumpEntityType_AggregatedListResponseSendsOnce(t *testing.T) {
	ctx := context.Background()
	factory := newAggregatingListFactory(t, ctx)
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(factory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	if err := svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{}, stream); err != nil {
		t.Fatalf("DumpEntityType failed: %v", err)
	}
	if len(stream.responses) != 150 {
		t.Errorf("expected 150 responses, got %d", len(stream.responses))
	}
	seen := make(map[uint64]struct{}, len(stream.responses))
	for _, resp := range stream.responses {
		if _, dup := seen[resp.EntityId]; dup {
			t.Fatalf("entity %d sent twice", resp.EntityId)
		}
		seen[resp.EntityId] = struct{}{}
	}
}

// restListClient behaves like the pinned go-quicbaas SDK REST List: it
// ignores the page token, returns only the first batch (at most pageSize of
// its records, every one with ID 0) and the same next token on every call.
// From the 5th call it returns an empty token, so a walk that trusts the
// token ends instead of looping forever.
type restListClient struct {
	*quicbaas.MockClient
	records int
	calls   int
}

func (c *restListClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	c.calls++
	n := min(c.records, int(pageSize))
	entities := make([]*service.Entity, 0, n)
	for i := 0; i < n; i++ {
		entities = append(entities, &service.Entity{ID: 0, Data: []byte(`{}`)})
	}
	if c.calls >= 5 {
		return entities, "", nil
	}
	return entities, "batch-1", nil
}

type restListFactory struct {
	*quicbaas.MockFactory
	client *restListClient
}

func (f *restListFactory) QuicBaaSClient() quicbaas.ClientInterface {
	return f.client
}

func newRestListFactory(t *testing.T, ctx context.Context) *restListFactory {
	t.Helper()
	mockFactory := quicbaas.NewMockFactory()
	if err := mockFactory.Start(ctx); err != nil {
		t.Fatalf("failed to start mock factory: %v", err)
	}
	t.Cleanup(func() { _ = mockFactory.Stop(ctx) })
	mockClient := mockFactory.MockClient()
	mockClient.SetEntityTypes([]string{"users"})
	mockClient.SetEmbedded(false)
	return &restListFactory{
		MockFactory: mockFactory,
		client:      &restListClient{MockClient: mockClient, records: 150},
	}
}

// TestDumpEntityType_IncompleteRemoteWalkFails covers #2081 Codex round 5:
// a remote List that repeats its page token and leaves every ID 0 must end
// the dump with an Internal error, not a duplicated, partial success.
func TestDumpEntityType_IncompleteRemoteWalkFails(t *testing.T) {
	ctx := context.Background()
	factory := newRestListFactory(t, ctx)
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(factory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	stream := &mockDumpStream{ctx: ctx}
	err = svc.DumpEntityType(&platformv1.DumpEntityTypeRequest{EntityType: "users"}, stream)
	if err == nil {
		t.Fatalf("an incomplete remote walk must fail the dump")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("expected codes.Internal, got %v (%v)", status.Code(err), err)
	}
	if len(stream.responses) != 100 {
		t.Errorf("the repeated remote page must not be sent: got %d responses, want 100", len(stream.responses))
	}
}

// TestListEntityTypes_IncompleteRemoteWalkReportsError covers #2081 Codex
// round 5: a remote List that repeats its page token reports the type as
// error with no count.
func TestListEntityTypes_IncompleteRemoteWalkReportsError(t *testing.T) {
	ctx := context.Background()
	factory := newRestListFactory(t, ctx)
	svc, err := NewService(DefaultConfig(), WithQuicBaaSFactory(factory))
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	resp, err := svc.ListEntityTypes(ctx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		t.Fatalf("ListEntityTypes failed: %v", err)
	}
	if len(resp.EntityTypes) != 1 {
		t.Fatalf("expected 1 entity type, got %d", len(resp.EntityTypes))
	}
	if resp.EntityTypes[0].Status != "error" {
		t.Errorf("an incomplete remote walk reports no count: status %q, want error", resp.EntityTypes[0].Status)
	}
	if resp.EntityTypes[0].EntityCount != 0 {
		t.Errorf("an incomplete remote walk reports no count: entity count %d", resp.EntityTypes[0].EntityCount)
	}
	if resp.TotalEntities != 0 {
		t.Errorf("an incomplete remote walk reports no count: total entities %d", resp.TotalEntities)
	}
	if resp.ActiveTypes != 0 {
		t.Errorf("an incomplete remote walk reports no count: active types %d", resp.ActiveTypes)
	}
}
