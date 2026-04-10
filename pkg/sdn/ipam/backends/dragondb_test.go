//go:build !platform_p2p

// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package backends

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// MockQuicBaaSClient implements QuicBaaSClient for testing.
type MockQuicBaaSClient struct {
	mu       sync.RWMutex
	data     map[string]map[uint64][]byte // entityType -> id -> data
	started  bool
	putErr   error
	getErr   error
	listErr  error
	delErr   error
	queryErr error
}

// NewMockQuicBaaSClient creates a new mock client.
func NewMockQuicBaaSClient() *MockQuicBaaSClient {
	return &MockQuicBaaSClient{
		data:    make(map[string]map[uint64][]byte),
		started: true,
	}
}

func (m *MockQuicBaaSClient) IsStarted() bool {
	return m.started
}

func (m *MockQuicBaaSClient) SetStarted(started bool) {
	m.started = started
}

func (m *MockQuicBaaSClient) SetPutError(err error) {
	m.putErr = err
}

func (m *MockQuicBaaSClient) SetGetError(err error) {
	m.getErr = err
}

func (m *MockQuicBaaSClient) SetListError(err error) {
	m.listErr = err
}

func (m *MockQuicBaaSClient) SetDeleteError(err error) {
	m.delErr = err
}

func (m *MockQuicBaaSClient) SetQueryError(err error) {
	m.queryErr = err
}

func (m *MockQuicBaaSClient) Put(ctx context.Context, entityType string, id uint64, data []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[entityType]; !ok {
		m.data[entityType] = make(map[uint64][]byte)
	}
	// Store a copy to prevent external modification
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	m.data[entityType][id] = dataCopy
	return nil
}

func (m *MockQuicBaaSClient) Get(ctx context.Context, entityType string, id uint64) ([]byte, bool, error) {
	if m.getErr != nil {
		return nil, false, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if typeData, ok := m.data[entityType]; ok {
		if data, ok := typeData[id]; ok {
			// Return a copy to prevent external modification
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			return dataCopy, true, nil
		}
	}
	return nil, false, nil
}

func (m *MockQuicBaaSClient) Delete(ctx context.Context, entityType string, id uint64) error {
	if m.delErr != nil {
		return m.delErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if typeData, ok := m.data[entityType]; ok {
		delete(typeData, id)
	}
	return nil
}

func (m *MockQuicBaaSClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string) ([]*service.Entity, string, error) {
	if m.listErr != nil {
		return nil, "", m.listErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entities []*service.Entity
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: dataCopy,
			})
		}
	}
	return entities, "", nil
}

func (m *MockQuicBaaSClient) Query(ctx context.Context, entityType, indexField string, value []byte) ([]*service.Entity, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	// Simple mock - just return all entities for the type
	m.mu.RLock()
	defer m.mu.RUnlock()
	var entities []*service.Entity
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: dataCopy,
			})
		}
	}
	return entities, nil
}

func TestNewQuicBaaSBackend(t *testing.T) {
	t.Run("nil client returns error", func(t *testing.T) {
		_, err := NewQuicBaaSBackend(nil, nil)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("valid client succeeds", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend == nil {
			t.Fatal("expected non-nil backend")
		}
	})

	t.Run("with config", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		config := &QuicBaaSBackendConfig{
			MaxRetries: 5,
		}
		backend, err := NewQuicBaaSBackend(client, config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if backend.maxRetries != 5 {
			t.Errorf("expected maxRetries=5, got %d", backend.maxRetries)
		}
	})
}

func TestQuicBaaSBackend_CreatePool(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	t.Run("valid pool creation", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "pool-1",
			Name: "test-pool",
			CIDR: netip.MustParsePrefix("192.168.1.0/24"),
		}

		err := backend.CreatePool(ctx, pool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify pool was stored
		retrieved, err := backend.GetPool(ctx, "pool-1")
		if err != nil {
			t.Fatalf("failed to retrieve pool: %v", err)
		}
		if retrieved.Name != "test-pool" {
			t.Errorf("expected name 'test-pool', got '%s'", retrieved.Name)
		}
		if retrieved.TotalIPs != 254 { // /24 = 256 - 2 (network + broadcast)
			t.Errorf("expected 254 total IPs, got %d", retrieved.TotalIPs)
		}
	})

	t.Run("nil pool returns error", func(t *testing.T) {
		err := backend.CreatePool(ctx, nil)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("empty pool ID returns error", func(t *testing.T) {
		pool := &ipam.Pool{
			Name: "test",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("empty pool name returns error", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "pool-empty-name",
			CIDR: netip.MustParsePrefix("10.0.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != ipam.ErrInvalidPoolName {
			t.Errorf("expected ErrInvalidPoolName, got %v", err)
		}
	})

	t.Run("duplicate pool ID returns error", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "pool-1", // Same as above
			Name: "duplicate-pool",
			CIDR: netip.MustParsePrefix("172.16.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != ipam.ErrPoolAlreadyExists {
			t.Errorf("expected ErrPoolAlreadyExists, got %v", err)
		}
	})

	t.Run("duplicate pool name returns error", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "pool-2",
			Name: "test-pool", // Same as pool-1
			CIDR: netip.MustParsePrefix("172.16.0.0/24"),
		}
		err := backend.CreatePool(ctx, pool)
		if err != ipam.ErrPoolNameExists {
			t.Errorf("expected ErrPoolNameExists, got %v", err)
		}
	})

	t.Run("overlapping CIDR returns error", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "pool-3",
			Name: "overlap-pool",
			CIDR: netip.MustParsePrefix("192.168.1.0/25"), // Overlaps with pool-1
		}
		err := backend.CreatePool(ctx, pool)
		if err != ipam.ErrPoolCIDROverlaps {
			t.Errorf("expected ErrPoolCIDROverlaps, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		pool := &ipam.Pool{
			ID:   "closed-pool",
			Name: "closed-pool",
			CIDR: netip.MustParsePrefix("10.99.0.0/24"),
		}
		err := closedBackend.CreatePool(ctx, pool)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_GetPool(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool first
	pool := &ipam.Pool{
		ID:   "get-pool-1",
		Name: "get-test-pool",
		CIDR: netip.MustParsePrefix("10.0.0.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("existing pool", func(t *testing.T) {
		retrieved, err := backend.GetPool(ctx, "get-pool-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.Name != "get-test-pool" {
			t.Errorf("expected name 'get-test-pool', got '%s'", retrieved.Name)
		}
	})

	t.Run("non-existent pool", func(t *testing.T) {
		_, err := backend.GetPool(ctx, "non-existent")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("empty pool ID", func(t *testing.T) {
		_, err := backend.GetPool(ctx, "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetPool(ctx, "any-pool")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("storage error returns wrapped error", func(t *testing.T) {
		errClient := NewMockQuicBaaSClient()
		errBackend, _ := NewQuicBaaSBackend(errClient, nil)
		errClient.SetGetError(errors.New("storage failure"))

		_, err := errBackend.GetPool(ctx, "any-pool")
		var storageErr *ipam.ErrStorageOperation
		if !errors.As(err, &storageErr) {
			t.Errorf("expected ErrStorageOperation, got %T: %v", err, err)
		}
	})
}

func TestQuicBaaSBackend_GetPoolByName(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	pool := &ipam.Pool{
		ID:   "name-pool-1",
		Name: "named-pool",
		CIDR: netip.MustParsePrefix("10.1.0.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("existing pool by name", func(t *testing.T) {
		retrieved, err := backend.GetPoolByName(ctx, "named-pool")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.ID != "name-pool-1" {
			t.Errorf("expected ID 'name-pool-1', got '%s'", retrieved.ID)
		}
	})

	t.Run("non-existent name", func(t *testing.T) {
		_, err := backend.GetPoolByName(ctx, "non-existent")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetPoolByName(ctx, "any-name")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_GetPoolByCIDR(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	cidr := netip.MustParsePrefix("10.2.0.0/24")
	pool := &ipam.Pool{
		ID:   "cidr-pool-1",
		Name: "cidr-pool",
		CIDR: cidr,
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("existing pool by CIDR", func(t *testing.T) {
		retrieved, err := backend.GetPoolByCIDR(ctx, cidr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.ID != "cidr-pool-1" {
			t.Errorf("expected ID 'cidr-pool-1', got '%s'", retrieved.ID)
		}
	})

	t.Run("non-existent CIDR", func(t *testing.T) {
		_, err := backend.GetPoolByCIDR(ctx, netip.MustParsePrefix("172.16.0.0/16"))
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetPoolByCIDR(ctx, netip.MustParsePrefix("10.0.0.0/8"))
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_ListPools(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create multiple pools
	pools := []*ipam.Pool{
		{ID: "list-pool-1", Name: "list-1", CIDR: netip.MustParsePrefix("10.10.0.0/24")},
		{ID: "list-pool-2", Name: "list-2", CIDR: netip.MustParsePrefix("10.11.0.0/24")},
		{ID: "list-pool-3", Name: "list-3", CIDR: netip.MustParsePrefix("10.12.0.0/24")},
	}
	for _, p := range pools {
		if err := backend.CreatePool(ctx, p); err != nil {
			t.Fatalf("failed to create pool %s: %v", p.ID, err)
		}
	}

	t.Run("list all pools", func(t *testing.T) {
		listed, err := backend.ListPools(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(listed) != 3 {
			t.Errorf("expected 3 pools, got %d", len(listed))
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.ListPools(ctx)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("storage error returns wrapped error", func(t *testing.T) {
		errClient := NewMockQuicBaaSClient()
		errBackend, _ := NewQuicBaaSBackend(errClient, nil)
		errClient.SetListError(errors.New("list failure"))

		_, err := errBackend.ListPools(ctx)
		var storageErr *ipam.ErrStorageOperation
		if !errors.As(err, &storageErr) {
			t.Errorf("expected ErrStorageOperation, got %T: %v", err, err)
		}
	})
}

func TestQuicBaaSBackend_UpdatePool(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	pool := &ipam.Pool{
		ID:   "update-pool-1",
		Name: "update-pool",
		CIDR: netip.MustParsePrefix("10.20.0.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("update pool name successfully", func(t *testing.T) {
		updatedPool := &ipam.Pool{
			ID:   "update-pool-1",
			Name: "updated-name",
			CIDR: netip.MustParsePrefix("10.20.0.0/24"),
		}
		err := backend.UpdatePool(ctx, updatedPool)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		retrieved, err := backend.GetPool(ctx, "update-pool-1")
		if err != nil {
			t.Fatalf("failed to get pool: %v", err)
		}
		if retrieved.Name != "updated-name" {
			t.Errorf("expected name 'updated-name', got '%s'", retrieved.Name)
		}
	})

	t.Run("update nil pool returns error", func(t *testing.T) {
		err := backend.UpdatePool(ctx, nil)
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("update pool with empty ID returns error", func(t *testing.T) {
		err := backend.UpdatePool(ctx, &ipam.Pool{Name: "test"})
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("update non-existent pool returns error", func(t *testing.T) {
		nonExistent := &ipam.Pool{
			ID:   "non-existent",
			Name: "non-existent",
			CIDR: netip.MustParsePrefix("10.99.0.0/24"),
		}
		err := backend.UpdatePool(ctx, nonExistent)
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("update pool name conflicts with another pool", func(t *testing.T) {
		// Create another pool
		pool2 := &ipam.Pool{
			ID:   "update-pool-2",
			Name: "other-pool",
			CIDR: netip.MustParsePrefix("10.21.0.0/24"),
		}
		if err := backend.CreatePool(ctx, pool2); err != nil {
			t.Fatalf("failed to create pool2: %v", err)
		}

		// Try to update pool1 with pool2's name
		conflictPool := &ipam.Pool{
			ID:   "update-pool-1",
			Name: "other-pool", // Conflicts with pool2
			CIDR: netip.MustParsePrefix("10.20.0.0/24"),
		}
		err := backend.UpdatePool(ctx, conflictPool)
		if err != ipam.ErrPoolNameExists {
			t.Errorf("expected ErrPoolNameExists, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		err := closedBackend.UpdatePool(ctx, &ipam.Pool{ID: "any", Name: "any"})
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_DeletePool(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	t.Run("delete pool without allocations", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "delete-pool-1",
			Name: "delete-pool",
			CIDR: netip.MustParsePrefix("192.168.70.0/24"),
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		err := backend.DeletePool(ctx, "delete-pool-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify pool is deleted
		_, err = backend.GetPool(ctx, "delete-pool-1")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("delete pool with active allocations fails", func(t *testing.T) {
		pool := &ipam.Pool{
			ID:   "delete-pool-2",
			Name: "delete-pool-2",
			CIDR: netip.MustParsePrefix("192.168.71.0/24"),
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate an IP
		req := &ipam.AllocationRequest{
			PoolID:   "delete-pool-2",
			DeviceID: "device-delete-1",
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Try to delete - should fail
		err := backend.DeletePool(ctx, "delete-pool-2")
		if err != ipam.ErrPoolHasAllocations {
			t.Errorf("expected ErrPoolHasAllocations, got %v", err)
		}
	})

	t.Run("delete pool with empty ID returns error", func(t *testing.T) {
		err := backend.DeletePool(ctx, "")
		if err != ipam.ErrInvalidPoolID {
			t.Errorf("expected ErrInvalidPoolID, got %v", err)
		}
	})

	t.Run("delete non-existent pool returns error", func(t *testing.T) {
		err := backend.DeletePool(ctx, "non-existent-pool")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		err := closedBackend.DeletePool(ctx, "any-pool")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_Allocate(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	pool := &ipam.Pool{
		ID:   "alloc-pool-1",
		Name: "allocation-pool",
		CIDR: netip.MustParsePrefix("192.168.10.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("successful allocation", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			PoolID:   "alloc-pool-1",
			DeviceID: "device-1",
			Hostname: "host1.example.com",
		}

		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if alloc.DeviceID != "device-1" {
			t.Errorf("expected device-1, got %s", alloc.DeviceID)
		}
		if !alloc.IP.IsValid() {
			t.Error("allocated IP is not valid")
		}
		// First usable IP in /24 should be .1 (skipping .0 network address)
		expectedIP := netip.MustParseAddr("192.168.10.1")
		if alloc.IP != expectedIP {
			t.Errorf("expected first allocation to be %s, got %s", expectedIP, alloc.IP)
		}
	})

	t.Run("sequential allocations", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			PoolID:   "alloc-pool-1",
			DeviceID: "device-2",
		}

		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Second allocation should be .2
		expectedIP := netip.MustParseAddr("192.168.10.2")
		if alloc.IP != expectedIP {
			t.Errorf("expected second allocation to be %s, got %s", expectedIP, alloc.IP)
		}
	})

	t.Run("missing pool ID", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			DeviceID: "device-3",
		}

		_, err := backend.Allocate(ctx, req)
		if err != ipam.ErrPoolIDRequired {
			t.Errorf("expected ErrPoolIDRequired, got %v", err)
		}
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			PoolID: "alloc-pool-1",
		}

		_, err := backend.Allocate(ctx, req)
		if err != ipam.ErrDeviceIDRequired {
			t.Errorf("expected ErrDeviceIDRequired, got %v", err)
		}
	})

	t.Run("non-existent pool", func(t *testing.T) {
		req := &ipam.AllocationRequest{
			PoolID:   "non-existent",
			DeviceID: "device-4",
		}

		_, err := backend.Allocate(ctx, req)
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		req := &ipam.AllocationRequest{
			PoolID:   "any-pool",
			DeviceID: "any-device",
		}
		_, err := closedBackend.Allocate(ctx, req)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_AllocateSpecific(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	pool := &ipam.Pool{
		ID:   "specific-pool-1",
		Name: "specific-pool",
		CIDR: netip.MustParsePrefix("192.168.20.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	t.Run("successful specific allocation", func(t *testing.T) {
		requestedIP := netip.MustParseAddr("192.168.20.100")
		req := &ipam.AllocationRequest{
			PoolID:      "specific-pool-1",
			DeviceID:    "device-specific-1",
			RequestedIP: requestedIP,
		}

		alloc, err := backend.AllocateSpecific(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if alloc.IP != requestedIP {
			t.Errorf("expected %s, got %s", requestedIP, alloc.IP)
		}
	})

	t.Run("IP already allocated", func(t *testing.T) {
		requestedIP := netip.MustParseAddr("192.168.20.100")
		req := &ipam.AllocationRequest{
			PoolID:      "specific-pool-1",
			DeviceID:    "device-specific-2",
			RequestedIP: requestedIP,
		}

		_, err := backend.AllocateSpecific(ctx, req)
		var conflict *ipam.ErrIPConflict
		if err == nil {
			t.Error("expected error, got nil")
		} else if _, ok := err.(*ipam.ErrIPConflict); !ok {
			t.Errorf("expected ErrIPConflict, got %T: %v", err, err)
		}
		_ = conflict
	})

	t.Run("IP not in pool", func(t *testing.T) {
		requestedIP := netip.MustParseAddr("10.0.0.1") // Not in pool CIDR
		req := &ipam.AllocationRequest{
			PoolID:      "specific-pool-1",
			DeviceID:    "device-specific-3",
			RequestedIP: requestedIP,
		}

		_, err := backend.AllocateSpecific(ctx, req)
		if err != ipam.ErrIPNotInPool {
			t.Errorf("expected ErrIPNotInPool, got %v", err)
		}
	})

	t.Run("network address", func(t *testing.T) {
		requestedIP := netip.MustParseAddr("192.168.20.0") // Network address
		req := &ipam.AllocationRequest{
			PoolID:      "specific-pool-1",
			DeviceID:    "device-specific-4",
			RequestedIP: requestedIP,
		}

		_, err := backend.AllocateSpecific(ctx, req)
		if err != ipam.ErrNetworkAddress {
			t.Errorf("expected ErrNetworkAddress, got %v", err)
		}
	})

	t.Run("broadcast address", func(t *testing.T) {
		requestedIP := netip.MustParseAddr("192.168.20.255") // Broadcast address
		req := &ipam.AllocationRequest{
			PoolID:      "specific-pool-1",
			DeviceID:    "device-specific-5",
			RequestedIP: requestedIP,
		}

		_, err := backend.AllocateSpecific(ctx, req)
		if err != ipam.ErrNetworkAddress { // QuicBaaS uses IsNetworkOrBroadcast which returns ErrNetworkAddress for both
			t.Errorf("expected ErrNetworkAddress (for broadcast), got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		req := &ipam.AllocationRequest{
			PoolID:      "any-pool",
			DeviceID:    "any-device",
			RequestedIP: netip.MustParseAddr("10.0.0.1"),
		}
		_, err := closedBackend.AllocateSpecific(ctx, req)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_Release(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool and allocate an IP
	pool := &ipam.Pool{
		ID:   "release-pool-1",
		Name: "release-pool",
		CIDR: netip.MustParsePrefix("192.168.30.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	req := &ipam.AllocationRequest{
		PoolID:   "release-pool-1",
		DeviceID: "device-release-1",
	}
	alloc, err := backend.Allocate(ctx, req)
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	t.Run("successful release", func(t *testing.T) {
		err := backend.Release(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify allocation is marked as released
		released, err := backend.GetAllocation(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("failed to get allocation: %v", err)
		}
		if released.Status != ipam.AllocationStatusReleased {
			t.Errorf("expected status released, got %s", released.Status)
		}
	})

	t.Run("already released", func(t *testing.T) {
		err := backend.Release(ctx, alloc.IP)
		if err != ipam.ErrAllocationReleased {
			t.Errorf("expected ErrAllocationReleased, got %v", err)
		}
	})

	t.Run("non-existent allocation", func(t *testing.T) {
		err := backend.Release(ctx, netip.MustParseAddr("192.168.30.200"))
		if err != ipam.ErrAllocationNotFound {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		err := closedBackend.Release(ctx, netip.MustParseAddr("10.0.0.1"))
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_Renew(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool with lease duration
	pool := &ipam.Pool{
		ID:                   "renew-pool-1",
		Name:                 "renew-pool",
		CIDR:                 netip.MustParsePrefix("192.168.40.0/24"),
		DefaultLeaseDuration: 1 * time.Hour,
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	req := &ipam.AllocationRequest{
		PoolID:   "renew-pool-1",
		DeviceID: "device-renew-1",
	}
	alloc, err := backend.Allocate(ctx, req)
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	t.Run("successful renew", func(t *testing.T) {
		err := backend.Renew(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify LastSeen was updated
		renewed, err := backend.GetAllocation(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("failed to get allocation: %v", err)
		}
		if renewed.LastSeen.Before(alloc.LastSeen) || renewed.LastSeen.Equal(alloc.LastSeen) {
			t.Error("LastSeen should have been updated")
		}
	})

	t.Run("non-existent allocation", func(t *testing.T) {
		err := backend.Renew(ctx, netip.MustParseAddr("192.168.40.200"))
		if err != ipam.ErrAllocationNotFound {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("renew released allocation fails", func(t *testing.T) {
		// Allocate and release
		req := &ipam.AllocationRequest{
			PoolID:   "renew-pool-1",
			DeviceID: "device-renew-released",
		}
		released, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}
		if err := backend.Release(ctx, released.IP); err != nil {
			t.Fatalf("failed to release: %v", err)
		}

		// Try to renew
		err = backend.Renew(ctx, released.IP)
		if err != ipam.ErrAllocationReleased {
			t.Errorf("expected ErrAllocationReleased, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		err := closedBackend.Renew(ctx, netip.MustParseAddr("10.0.0.1"))
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_GetAllocation(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool and allocate
	pool := &ipam.Pool{
		ID:   "getalloc-pool-1",
		Name: "getalloc-pool",
		CIDR: netip.MustParsePrefix("192.168.90.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	req := &ipam.AllocationRequest{
		PoolID:   "getalloc-pool-1",
		DeviceID: "device-getalloc-1",
	}
	alloc, err := backend.Allocate(ctx, req)
	if err != nil {
		t.Fatalf("failed to allocate: %v", err)
	}

	t.Run("get existing allocation", func(t *testing.T) {
		retrieved, err := backend.GetAllocation(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if retrieved.DeviceID != "device-getalloc-1" {
			t.Errorf("expected device-getalloc-1, got %s", retrieved.DeviceID)
		}
	})

	t.Run("non-existent allocation", func(t *testing.T) {
		_, err := backend.GetAllocation(ctx, netip.MustParseAddr("192.168.90.200"))
		if err != ipam.ErrAllocationNotFound {
			t.Errorf("expected ErrAllocationNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetAllocation(ctx, netip.MustParseAddr("10.0.0.1"))
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_GetAllocationsByDevice(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool and allocate IPs
	pool := &ipam.Pool{
		ID:   "device-alloc-pool-1",
		Name: "device-alloc-pool",
		CIDR: netip.MustParsePrefix("198.18.1.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// Allocate multiple IPs for same device
	for i := 0; i < 3; i++ {
		req := &ipam.AllocationRequest{
			PoolID:   "device-alloc-pool-1",
			DeviceID: "multi-device-1",
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}
	}

	t.Run("get allocations by device", func(t *testing.T) {
		allocs, err := backend.GetAllocationsByDevice(ctx, "multi-device-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(allocs) != 3 {
			t.Errorf("expected 3 allocations, got %d", len(allocs))
		}
	})

	t.Run("non-existent device", func(t *testing.T) {
		allocs, err := backend.GetAllocationsByDevice(ctx, "non-existent")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(allocs) != 0 {
			t.Errorf("expected 0 allocations, got %d", len(allocs))
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetAllocationsByDevice(ctx, "any-device")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_GetAllocationsByPool(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool
	pool := &ipam.Pool{
		ID:   "pool-allocs-1",
		Name: "pool-allocs",
		CIDR: netip.MustParsePrefix("192.168.91.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// Allocate multiple IPs
	for i := 0; i < 3; i++ {
		req := &ipam.AllocationRequest{
			PoolID:   "pool-allocs-1",
			DeviceID: fmt.Sprintf("device-pool-allocs-%d", i),
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}
	}

	t.Run("get allocations by pool", func(t *testing.T) {
		allocs, err := backend.GetAllocationsByPool(ctx, "pool-allocs-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(allocs) != 3 {
			t.Errorf("expected 3 allocations, got %d", len(allocs))
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetAllocationsByPool(ctx, "any-pool")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_ReleaseByDeviceID(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool and allocate IPs
	pool := &ipam.Pool{
		ID:   "release-device-pool-1",
		Name: "release-device-pool",
		CIDR: netip.MustParsePrefix("192.168.60.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// Allocate multiple IPs for same device
	for i := 0; i < 3; i++ {
		req := &ipam.AllocationRequest{
			PoolID:   "release-device-pool-1",
			DeviceID: "release-device-1",
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}
	}

	t.Run("release all by device", func(t *testing.T) {
		released, err := backend.ReleaseByDeviceID(ctx, "release-device-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if released != 3 {
			t.Errorf("expected 3 released, got %d", released)
		}
	})

	t.Run("release non-existent device returns zero", func(t *testing.T) {
		released, err := backend.ReleaseByDeviceID(ctx, "non-existent-device")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if released != 0 {
			t.Errorf("expected 0 released, got %d", released)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.ReleaseByDeviceID(ctx, "any-device")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_ExpireInactive(t *testing.T) {
	ctx := context.Background()

	t.Run("expires inactive allocations", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		// Create a pool with short inactivity timeout
		pool := &ipam.Pool{
			ID:                "expire-pool-1",
			Name:              "expire-pool",
			CIDR:              netip.MustParsePrefix("192.168.100.0/24"),
			InactivityTimeout: 1 * time.Nanosecond, // Very short timeout for testing
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate an IP
		req := &ipam.AllocationRequest{
			PoolID:   "expire-pool-1",
			DeviceID: "device-expire-1",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Manually set LastSeen to past to trigger expiration
		alloc.LastSeen = time.Now().Add(-1 * time.Hour)
		allocData, _ := json.Marshal(alloc)
		allocID := stringToID(alloc.IP.String())
		client.Put(ctx, entityTypeAllocation, allocID, allocData)

		// Run expire
		expired, err := backend.ExpireInactive(ctx, "expire-pool-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(expired) != 1 {
			t.Errorf("expected 1 expired allocation, got %d", len(expired))
		}

		// Verify allocation is marked as expired
		retrieved, err := backend.GetAllocation(ctx, alloc.IP)
		if err != nil {
			t.Fatalf("failed to get allocation: %v", err)
		}
		if retrieved.Status != ipam.AllocationStatusExpired {
			t.Errorf("expected status expired, got %s", retrieved.Status)
		}
	})

	t.Run("does not expire active allocations", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		// Create a pool with long inactivity timeout
		pool := &ipam.Pool{
			ID:                "expire-pool-2",
			Name:              "expire-pool-2",
			CIDR:              netip.MustParsePrefix("198.51.100.0/24"),
			InactivityTimeout: 24 * time.Hour, // Long timeout
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate an IP
		req := &ipam.AllocationRequest{
			PoolID:   "expire-pool-2",
			DeviceID: "device-expire-2",
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Run expire - should not expire anything
		expired, err := backend.ExpireInactive(ctx, "expire-pool-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(expired) != 0 {
			t.Errorf("expected 0 expired allocations, got %d", len(expired))
		}
	})

	t.Run("skips already expired allocations", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		// Create a pool
		pool := &ipam.Pool{
			ID:                "expire-pool-3",
			Name:              "expire-pool-3",
			CIDR:              netip.MustParsePrefix("192.168.102.0/24"),
			InactivityTimeout: 1 * time.Nanosecond,
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate and manually set to expired
		req := &ipam.AllocationRequest{
			PoolID:   "expire-pool-3",
			DeviceID: "device-expire-3",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Manually set status to expired
		alloc.Status = ipam.AllocationStatusExpired
		alloc.LastSeen = time.Now().Add(-1 * time.Hour)
		allocData, _ := json.Marshal(alloc)
		allocID := stringToID(alloc.IP.String())
		client.Put(ctx, entityTypeAllocation, allocID, allocData)

		// Run expire
		expired, err := backend.ExpireInactive(ctx, "expire-pool-3")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(expired) != 0 {
			t.Errorf("expected 0 expired allocations (already expired), got %d", len(expired))
		}
	})

	t.Run("skips released allocations", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		// Create a pool
		pool := &ipam.Pool{
			ID:                "expire-pool-4",
			Name:              "expire-pool-4",
			CIDR:              netip.MustParsePrefix("192.168.103.0/24"),
			InactivityTimeout: 1 * time.Nanosecond,
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate and release
		req := &ipam.AllocationRequest{
			PoolID:   "expire-pool-4",
			DeviceID: "device-expire-4",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Release the allocation
		if err := backend.Release(ctx, alloc.IP); err != nil {
			t.Fatalf("failed to release: %v", err)
		}

		// Run expire
		expired, err := backend.ExpireInactive(ctx, "expire-pool-4")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(expired) != 0 {
			t.Errorf("expected 0 expired allocations (already released), got %d", len(expired))
		}
	})

	t.Run("non-existent pool returns error", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, _ := NewQuicBaaSBackend(client, nil)

		_, err := backend.ExpireInactive(ctx, "non-existent")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.ExpireInactive(ctx, "any-pool")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("uses default inactivity timeout when pool timeout is zero", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, err := NewQuicBaaSBackend(client, nil)
		if err != nil {
			t.Fatalf("failed to create backend: %v", err)
		}

		// Create a pool with zero inactivity timeout (should use default)
		pool := &ipam.Pool{
			ID:                "expire-pool-5",
			Name:              "expire-pool-5",
			CIDR:              netip.MustParsePrefix("192.168.104.0/24"),
			InactivityTimeout: 0, // Zero - should use default
		}
		if err := backend.CreatePool(ctx, pool); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate an IP
		req := &ipam.AllocationRequest{
			PoolID:   "expire-pool-5",
			DeviceID: "device-expire-5",
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Run expire - should use default timeout (24h by default)
		expired, err := backend.ExpireInactive(ctx, "expire-pool-5")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should not expire since we just allocated (default timeout is long)
		if len(expired) != 0 {
			t.Errorf("expected 0 expired allocations with default timeout, got %d", len(expired))
		}
	})
}

func TestQuicBaaSBackend_Ping(t *testing.T) {
	ctx := context.Background()

	t.Run("healthy backend", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, _ := NewQuicBaaSBackend(client, nil)

		err := backend.Ping(ctx)
		if err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})

	t.Run("client not started", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		client.SetStarted(false)
		backend, _ := NewQuicBaaSBackend(client, nil)

		err := backend.Ping(ctx)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})

	t.Run("closed backend", func(t *testing.T) {
		client := NewMockQuicBaaSClient()
		backend, _ := NewQuicBaaSBackend(client, nil)
		backend.Close()

		err := backend.Ping(ctx)
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}

func TestQuicBaaSBackend_Close(t *testing.T) {
	client := NewMockQuicBaaSClient()
	backend, _ := NewQuicBaaSBackend(client, nil)

	err := backend.Close()
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Verify backend is closed
	ctx := context.Background()
	err = backend.Ping(ctx)
	if err != ipam.ErrBackendUnavailable {
		t.Errorf("expected ErrBackendUnavailable after close, got %v", err)
	}
}

func TestQuicBaaSBackend_GetPoolStats(t *testing.T) {
	ctx := context.Background()
	client := NewMockQuicBaaSClient()
	backend, err := NewQuicBaaSBackend(client, nil)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}

	// Create a pool and allocate some IPs
	pool := &ipam.Pool{
		ID:   "stats-pool-1",
		Name: "stats-pool",
		CIDR: netip.MustParsePrefix("192.168.80.0/24"),
	}
	if err := backend.CreatePool(ctx, pool); err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// Allocate a few IPs
	for i := 0; i < 5; i++ {
		req := &ipam.AllocationRequest{
			PoolID:   "stats-pool-1",
			DeviceID: "device-stats-" + string(rune('0'+i)),
		}
		if _, err := backend.Allocate(ctx, req); err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}
	}

	t.Run("get pool stats", func(t *testing.T) {
		stats, err := backend.GetPoolStats(ctx, "stats-pool-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stats.TotalIPs != 254 {
			t.Errorf("expected 254 total IPs, got %d", stats.TotalIPs)
		}
		if stats.AllocatedIPs != 5 {
			t.Errorf("expected 5 allocated IPs, got %d", stats.AllocatedIPs)
		}
		if stats.AvailableIPs != 249 {
			t.Errorf("expected 249 available IPs, got %d", stats.AvailableIPs)
		}
	})

	t.Run("get stats for pool with expired allocations", func(t *testing.T) {
		// Create another pool
		pool2 := &ipam.Pool{
			ID:                "stats-pool-2",
			Name:              "stats-pool-2",
			CIDR:              netip.MustParsePrefix("192.168.81.0/24"),
			InactivityTimeout: 1 * time.Nanosecond,
		}
		if err := backend.CreatePool(ctx, pool2); err != nil {
			t.Fatalf("failed to create pool: %v", err)
		}

		// Allocate and expire
		req := &ipam.AllocationRequest{
			PoolID:   "stats-pool-2",
			DeviceID: "device-stats-expired",
		}
		alloc, err := backend.Allocate(ctx, req)
		if err != nil {
			t.Fatalf("failed to allocate: %v", err)
		}

		// Manually expire
		alloc.Status = ipam.AllocationStatusExpired
		alloc.LastSeen = time.Now().Add(-1 * time.Hour)
		allocData, _ := json.Marshal(alloc)
		allocID := stringToID(alloc.IP.String())
		client.Put(ctx, entityTypeAllocation, allocID, allocData)

		stats, err := backend.GetPoolStats(ctx, "stats-pool-2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if stats.ExpiredIPs != 1 {
			t.Errorf("expected 1 expired IP, got %d", stats.ExpiredIPs)
		}
	})

	t.Run("non-existent pool returns error", func(t *testing.T) {
		_, err := backend.GetPoolStats(ctx, "non-existent")
		if err != ipam.ErrPoolNotFound {
			t.Errorf("expected ErrPoolNotFound, got %v", err)
		}
	})

	t.Run("backend closed returns error", func(t *testing.T) {
		closedClient := NewMockQuicBaaSClient()
		closedBackend, _ := NewQuicBaaSBackend(closedClient, nil)
		closedBackend.Close()

		_, err := closedBackend.GetPoolStats(ctx, "any-pool")
		if err != ipam.ErrBackendUnavailable {
			t.Errorf("expected ErrBackendUnavailable, got %v", err)
		}
	})
}
