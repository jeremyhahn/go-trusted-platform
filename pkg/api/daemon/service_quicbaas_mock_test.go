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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
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
