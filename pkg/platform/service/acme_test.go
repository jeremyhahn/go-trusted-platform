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

package service

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAcmeServer(t *testing.T) {
	server := NewAcmeServer(nil)

	require.NotNil(t, server)
	assert.NotNil(t, server.orders)
	assert.NotNil(t, server.authorizations)
	assert.NotNil(t, server.nonces)
}

func TestAcmeServer_CreateOrder_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	order, err := server.CreateOrder("example.com")

	require.NoError(t, err)
	assert.NotEmpty(t, order.ID)
	assert.Equal(t, OrderStatusPending, order.Status)
	assert.Equal(t, "example.com", order.Domain)
}

func TestAcmeServer_CreateOrder_MultipleDomains(t *testing.T) {
	server := NewAcmeServer(nil)

	domains := []string{"example.com", "test.org", "demo.net"}
	orderIDs := make(map[string]bool)

	for _, domain := range domains {
		order, err := server.CreateOrder(domain)
		require.NoError(t, err)
		assert.Equal(t, domain, order.Domain)
		assert.Equal(t, OrderStatusPending, order.Status)

		// Ensure IDs are unique
		assert.False(t, orderIDs[order.ID], "duplicate order ID generated")
		orderIDs[order.ID] = true
	}

	assert.Equal(t, len(domains), len(orderIDs))
}

func TestAcmeServer_FetchOrder_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	created, err := server.CreateOrder("fetch-test.com")
	require.NoError(t, err)

	fetched, err := server.FetchOrder(created.ID)

	require.NoError(t, err)
	assert.Equal(t, created.ID, fetched.ID)
	assert.Equal(t, created.Domain, fetched.Domain)
	assert.Equal(t, created.Status, fetched.Status)
}

func TestAcmeServer_FetchOrder_NotFound(t *testing.T) {
	server := NewAcmeServer(nil)

	_, err := server.FetchOrder("nonexistent-order-id")

	assert.Error(t, err)
	assert.Equal(t, "order not found", err.Error())
}

func TestAcmeServer_FinalizeOrder_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	created, err := server.CreateOrder("finalize-test.com")
	require.NoError(t, err)

	csr := []byte("test-csr-data")
	finalized, err := server.FinalizeOrder(created.ID, csr)

	require.NoError(t, err)
	assert.Equal(t, created.ID, finalized.ID)
	assert.Equal(t, OrderStatusValid, finalized.Status)
	assert.Equal(t, csr, finalized.Certificate)
}

func TestAcmeServer_FinalizeOrder_NotFound(t *testing.T) {
	server := NewAcmeServer(nil)

	csr := []byte("test-csr-data")
	_, err := server.FinalizeOrder("nonexistent-order-id", csr)

	assert.Error(t, err)
	assert.Equal(t, "order not found", err.Error())
}

func TestAcmeServer_FinalizeOrder_UpdatesOrderState(t *testing.T) {
	server := NewAcmeServer(nil)

	order, err := server.CreateOrder("update-test.com")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusPending, order.Status)

	csr := []byte("finalize-csr")
	_, err = server.FinalizeOrder(order.ID, csr)
	require.NoError(t, err)

	// Fetch again to verify state was updated
	fetched, err := server.FetchOrder(order.ID)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusValid, fetched.Status)
	assert.Equal(t, csr, fetched.Certificate)
}

func TestAcmeServer_FetchAuthorization_NotFound(t *testing.T) {
	server := NewAcmeServer(nil)

	_, err := server.FetchAuthorization("nonexistent-authz-id")

	assert.Error(t, err)
	assert.Equal(t, "authorization not found", err.Error())
}

func TestAcmeServer_FetchAuthorization_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	// Manually add an authorization for testing
	authz := Authorization{
		ID:     "test-authz-id",
		Status: OrderStatusPending,
		Domain: "auth-test.com",
	}
	server.mu.Lock()
	server.authorizations[authz.ID] = authz
	server.mu.Unlock()

	fetched, err := server.FetchAuthorization(authz.ID)

	require.NoError(t, err)
	assert.Equal(t, authz.ID, fetched.ID)
	assert.Equal(t, authz.Status, fetched.Status)
	assert.Equal(t, authz.Domain, fetched.Domain)
}

func TestAcmeServer_DeactivateAuthorization_NotFound(t *testing.T) {
	server := NewAcmeServer(nil)

	err := server.DeactivateAuthorization("nonexistent-authz-id")

	assert.Error(t, err)
	assert.Equal(t, "authorization not found", err.Error())
}

func TestAcmeServer_DeactivateAuthorization_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	// Manually add an authorization for testing
	authz := Authorization{
		ID:     "deactivate-authz-id",
		Status: OrderStatusPending,
		Domain: "deactivate-test.com",
	}
	server.mu.Lock()
	server.authorizations[authz.ID] = authz
	server.mu.Unlock()

	err := server.DeactivateAuthorization(authz.ID)

	require.NoError(t, err)

	// Verify it was deactivated
	fetched, err := server.FetchAuthorization(authz.ID)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusDeactivated, fetched.Status)
}

func TestAcmeServer_NewNonce_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	nonce, err := server.NewNonce()

	require.NoError(t, err)
	assert.NotEmpty(t, nonce)
}

func TestAcmeServer_NewNonce_UniqueNonces(t *testing.T) {
	server := NewAcmeServer(nil)

	nonces := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		nonce, err := server.NewNonce()
		require.NoError(t, err)
		assert.False(t, nonces[nonce], "duplicate nonce generated")
		nonces[nonce] = true
	}

	assert.Equal(t, count, len(nonces))
}

func TestAcmeServer_NewNonce_StoresNonce(t *testing.T) {
	server := NewAcmeServer(nil)

	nonce, err := server.NewNonce()
	require.NoError(t, err)

	server.mu.Lock()
	_, exists := server.nonces[nonce]
	server.mu.Unlock()

	assert.True(t, exists, "nonce should be stored in server")
}

func TestAcmeServer_RevokeCertificate_Success(t *testing.T) {
	server := NewAcmeServer(nil)

	cert := []byte("test-certificate-data")
	reason := 0

	err := server.RevokeCertificate(cert, reason)

	require.NoError(t, err)
}

func TestAcmeServer_RevokeCertificate_DifferentReasons(t *testing.T) {
	server := NewAcmeServer(nil)
	cert := []byte("test-certificate")

	reasons := []int{0, 1, 2, 3, 4, 5}
	for _, reason := range reasons {
		err := server.RevokeCertificate(cert, reason)
		require.NoError(t, err)
	}
}

func TestAcmeServer_ConcurrentOrderCreation(t *testing.T) {
	server := NewAcmeServer(nil)

	var wg sync.WaitGroup
	orderCount := 50
	orders := make(chan Order, orderCount)

	for i := 0; i < orderCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			order, err := server.CreateOrder("concurrent-test.com")
			require.NoError(t, err)
			orders <- order
		}(i)
	}

	wg.Wait()
	close(orders)

	orderIDs := make(map[string]bool)
	for order := range orders {
		assert.False(t, orderIDs[order.ID], "duplicate order ID in concurrent creation")
		orderIDs[order.ID] = true
	}

	assert.Equal(t, orderCount, len(orderIDs))
}

func TestAcmeServer_ConcurrentNonceGeneration(t *testing.T) {
	server := NewAcmeServer(nil)

	var wg sync.WaitGroup
	nonceCount := 50
	nonces := make(chan string, nonceCount)

	for i := 0; i < nonceCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nonce, err := server.NewNonce()
			require.NoError(t, err)
			nonces <- nonce
		}()
	}

	wg.Wait()
	close(nonces)

	nonceSet := make(map[string]bool)
	for nonce := range nonces {
		assert.False(t, nonceSet[nonce], "duplicate nonce in concurrent generation")
		nonceSet[nonce] = true
	}

	assert.Equal(t, nonceCount, len(nonceSet))
}

func TestAcmeServer_OrderWorkflow(t *testing.T) {
	server := NewAcmeServer(nil)

	// Create order
	order, err := server.CreateOrder("workflow-test.com")
	require.NoError(t, err)
	assert.Equal(t, OrderStatusPending, order.Status)

	// Fetch order
	fetched, err := server.FetchOrder(order.ID)
	require.NoError(t, err)
	assert.Equal(t, order.ID, fetched.ID)
	assert.Equal(t, OrderStatusPending, fetched.Status)

	// Finalize order
	csr := []byte("test-csr")
	finalized, err := server.FinalizeOrder(order.ID, csr)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusValid, finalized.Status)
	assert.Equal(t, csr, finalized.Certificate)

	// Verify final state
	final, err := server.FetchOrder(order.ID)
	require.NoError(t, err)
	assert.Equal(t, OrderStatusValid, final.Status)
}

func TestOrderStatusConstants(t *testing.T) {
	assert.Equal(t, "pending", OrderStatusPending)
	assert.Equal(t, "valid", OrderStatusValid)
	assert.Equal(t, "deactivated", OrderStatusDeactivated)
	assert.Equal(t, "expired", OrderStatusExpired)
	assert.Equal(t, "revoked", OrderStatusRevoked)
}

func TestGenerateID(t *testing.T) {
	ids := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		id := generateID()
		assert.NotEmpty(t, id)
		assert.False(t, ids[id], "duplicate ID generated")
		ids[id] = true
	}

	assert.Equal(t, count, len(ids))
}

func TestGenerateNonce(t *testing.T) {
	nonces := make(map[string]bool)
	count := 100

	for i := 0; i < count; i++ {
		nonce := generateNonce()
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "duplicate nonce generated")
		nonces[nonce] = true
	}

	assert.Equal(t, count, len(nonces))
}
