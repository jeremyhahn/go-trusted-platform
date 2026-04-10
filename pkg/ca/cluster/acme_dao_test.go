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

package cluster

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// ACMEAccount Tests
// ============================================================================

func TestACMEDAO_CreateAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID:    "acct-1",
		Status:       "valid",
		Contact:      []string{"mailto:test@example.com"},
		PublicKeyJWK: []byte(`{"kty":"RSA"}`),
		TenantID:     "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if account.Version != 1 {
		t.Errorf("expected version 1, got %d", account.Version)
	}

	if account.EntityID() == 0 {
		t.Error("expected entity ID to be set")
	}
}

func TestACMEDAO_CreateAccount_NilAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.CreateAccount(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil account")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_CreateAccount_EmptyID(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		Status:   "valid",
		TenantID: "tenant1",
	}

	err := dao.CreateAccount(ctx, account)

	if err == nil {
		t.Fatal("expected error for empty account ID")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_CreateAccount_AlreadyExists(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on first create, got %v", err)
	}

	err = dao.CreateAccount(ctx, account)
	if err == nil {
		t.Fatal("expected error on duplicate create")
	}

	if _, ok := err.(ErrACMEAccountAlreadyExists); !ok {
		t.Errorf("expected ErrACMEAccountAlreadyExists, got %T", err)
	}
}

func TestACMEDAO_GetAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID:    "acct-1",
		Status:       "valid",
		Contact:      []string{"mailto:test@example.com"},
		PublicKeyJWK: []byte(`{"kty":"RSA"}`),
		TenantID:     "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.GetAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.AccountID != account.AccountID {
		t.Errorf("expected AccountID %s, got %s", account.AccountID, retrieved.AccountID)
	}

	if retrieved.Status != account.Status {
		t.Errorf("expected Status %s, got %s", account.Status, retrieved.Status)
	}
}

func TestACMEDAO_GetAccount_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetAccount(ctx, "non-existent", "tenant1")

	if err == nil {
		t.Fatal("expected error for non-existent account")
	}

	if _, ok := err.(ErrACMEAccountNotFound); !ok {
		t.Errorf("expected ErrACMEAccountNotFound, got %T", err)
	}
}

func TestACMEDAO_UpdateAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	account.Status = "deactivated"
	err = dao.UpdateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on update, got %v", err)
	}

	if account.Version != 2 {
		t.Errorf("expected version 2, got %d", account.Version)
	}

	retrieved, err := dao.GetAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.Status != "deactivated" {
		t.Errorf("expected status deactivated, got %s", retrieved.Status)
	}
}

func TestACMEDAO_UpdateAccount_VersionConflict(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger, WithACMEOptimisticLocking(true))

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	account.Version = 5
	err = dao.UpdateAccount(ctx, account)

	if err == nil {
		t.Fatal("expected version conflict error")
	}

	if _, ok := err.(ErrVersionConflict); !ok {
		t.Errorf("expected ErrVersionConflict, got %T", err)
	}
}

func TestACMEDAO_DeleteAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-1",
		Status:    "valid",
		TenantID:  "tenant1",
	}

	err := dao.CreateAccount(ctx, account)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.DeleteAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = dao.GetAccount(ctx, "acct-1", "tenant1")
	if _, ok := err.(ErrACMEAccountNotFound); !ok {
		t.Errorf("expected ErrACMEAccountNotFound after delete, got %T", err)
	}
}

// ============================================================================
// ACMEOrder Tests
// ============================================================================

func TestACMEDAO_CreateOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		Identifiers: []ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		TenantID: "tenant1",
	}

	err := dao.CreateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if order.Version != 1 {
		t.Errorf("expected version 1, got %d", order.Version)
	}

	if order.EntityID() == 0 {
		t.Error("expected entity ID to be set")
	}
}

func TestACMEDAO_CreateOrder_NilOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.CreateOrder(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil order")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_GetOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		Identifiers: []ACMEIdentifier{
			{Type: "dns", Value: "example.com"},
		},
		TenantID: "tenant1",
	}

	err := dao.CreateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.GetOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.OrderID != order.OrderID {
		t.Errorf("expected OrderID %s, got %s", order.OrderID, retrieved.OrderID)
	}

	if len(retrieved.Identifiers) != 1 {
		t.Errorf("expected 1 identifier, got %d", len(retrieved.Identifiers))
	}
}

func TestACMEDAO_GetOrder_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetOrder(ctx, "non-existent", "tenant1")

	if err == nil {
		t.Fatal("expected error for non-existent order")
	}

	if _, ok := err.(ErrACMEOrderNotFound); !ok {
		t.Errorf("expected ErrACMEOrderNotFound, got %T", err)
	}
}

func TestACMEDAO_UpdateOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := dao.CreateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	order.Status = "ready"
	err = dao.UpdateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error on update, got %v", err)
	}

	if order.Version != 2 {
		t.Errorf("expected version 2, got %d", order.Version)
	}

	retrieved, err := dao.GetOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.Status != "ready" {
		t.Errorf("expected status ready, got %s", retrieved.Status)
	}
}

func TestACMEDAO_DeleteOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	order := &ACMEOrder{
		OrderID:   "order-1",
		AccountID: "acct-1",
		Status:    "pending",
		TenantID:  "tenant1",
	}

	err := dao.CreateOrder(ctx, order)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.DeleteOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = dao.GetOrder(ctx, "order-1", "tenant1")
	if _, ok := err.(ErrACMEOrderNotFound); !ok {
		t.Errorf("expected ErrACMEOrderNotFound after delete, got %T", err)
	}
}

func TestACMEDAO_ListOrdersByAccount(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	// Create orders for account 1
	for i := 1; i <= 3; i++ {
		order := &ACMEOrder{
			OrderID:   "order-a1-" + string(rune('0'+i)),
			AccountID: "acct-1",
			Status:    "pending",
			TenantID:  "tenant1",
		}
		err := dao.CreateOrder(ctx, order)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	// Create orders for account 2
	for i := 1; i <= 2; i++ {
		order := &ACMEOrder{
			OrderID:   "order-a2-" + string(rune('0'+i)),
			AccountID: "acct-2",
			Status:    "pending",
			TenantID:  "tenant1",
		}
		err := dao.CreateOrder(ctx, order)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	// List orders for account 1
	orders1, err := dao.ListOrdersByAccount(ctx, "acct-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(orders1) != 3 {
		t.Errorf("expected 3 orders for acct-1, got %d", len(orders1))
	}

	// List orders for account 2
	orders2, err := dao.ListOrdersByAccount(ctx, "acct-2", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(orders2) != 2 {
		t.Errorf("expected 2 orders for acct-2, got %d", len(orders2))
	}
}

func TestACMEDAO_CleanupExpiredOrders(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create expired order
	expiredOrder := &ACMEOrder{
		OrderID:   "order-expired",
		AccountID: "acct-1",
		Status:    "pending",
		ExpiresAt: now.Add(-1 * time.Hour),
		TenantID:  "tenant1",
	}
	err := dao.CreateOrder(ctx, expiredOrder)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create valid order
	validOrder := &ACMEOrder{
		OrderID:   "order-valid",
		AccountID: "acct-1",
		Status:    "pending",
		ExpiresAt: now.Add(24 * time.Hour),
		TenantID:  "tenant1",
	}
	err = dao.CreateOrder(ctx, validOrder)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	deleted, err := dao.CleanupExpiredOrders(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify valid order still exists
	_, err = dao.GetOrder(ctx, "order-valid", "tenant1")
	if err != nil {
		t.Fatalf("expected valid order to still exist, got %v", err)
	}

	// Verify expired order is deleted
	_, err = dao.GetOrder(ctx, "order-expired", "tenant1")
	if _, ok := err.(ErrACMEOrderNotFound); !ok {
		t.Error("expected expired order to be deleted")
	}
}

// ============================================================================
// ACMEAuthorization Tests
// ============================================================================

func TestACMEDAO_CreateAuthorization(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		Identifier:      ACMEIdentifier{Type: "dns", Value: "example.com"},
		TenantID:        "tenant1",
	}

	err := dao.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if authz.Version != 1 {
		t.Errorf("expected version 1, got %d", authz.Version)
	}

	if authz.EntityID() == 0 {
		t.Error("expected entity ID to be set")
	}
}

func TestACMEDAO_CreateAuthorization_NilAuthz(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	err := dao.CreateAuthorization(ctx, nil)

	if err == nil {
		t.Fatal("expected error for nil authorization")
	}

	if _, ok := err.(ErrInvalidInput); !ok {
		t.Errorf("expected ErrInvalidInput, got %T", err)
	}
}

func TestACMEDAO_GetAuthorization(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		Identifier:      ACMEIdentifier{Type: "dns", Value: "example.com"},
		TenantID:        "tenant1",
	}

	err := dao.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	retrieved, err := dao.GetAuthorization(ctx, "authz-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.AuthorizationID != authz.AuthorizationID {
		t.Errorf("expected AuthorizationID %s, got %s", authz.AuthorizationID, retrieved.AuthorizationID)
	}

	if retrieved.Identifier.Value != "example.com" {
		t.Errorf("expected identifier value example.com, got %s", retrieved.Identifier.Value)
	}
}

func TestACMEDAO_GetAuthorization_NotFound(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	_, err := dao.GetAuthorization(ctx, "non-existent", "tenant1")

	if err == nil {
		t.Fatal("expected error for non-existent authorization")
	}

	if _, ok := err.(ErrACMEAuthorizationNotFound); !ok {
		t.Errorf("expected ErrACMEAuthorizationNotFound, got %T", err)
	}
}

func TestACMEDAO_UpdateAuthorization(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := dao.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	authz.Status = "valid"
	err = dao.UpdateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error on update, got %v", err)
	}

	if authz.Version != 2 {
		t.Errorf("expected version 2, got %d", authz.Version)
	}

	retrieved, err := dao.GetAuthorization(ctx, "authz-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if retrieved.Status != "valid" {
		t.Errorf("expected status valid, got %s", retrieved.Status)
	}
}

func TestACMEDAO_DeleteAuthorization(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	authz := &ACMEAuthorization{
		AuthorizationID: "authz-1",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		TenantID:        "tenant1",
	}

	err := dao.CreateAuthorization(ctx, authz)
	if err != nil {
		t.Fatalf("expected no error on create, got %v", err)
	}

	err = dao.DeleteAuthorization(ctx, "authz-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error on delete, got %v", err)
	}

	_, err = dao.GetAuthorization(ctx, "authz-1", "tenant1")
	if _, ok := err.(ErrACMEAuthorizationNotFound); !ok {
		t.Errorf("expected ErrACMEAuthorizationNotFound after delete, got %T", err)
	}
}

func TestACMEDAO_ListAuthorizationsByOrder(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	// Create authorizations for order 1
	for i := 1; i <= 3; i++ {
		authz := &ACMEAuthorization{
			AuthorizationID: "authz-o1-" + string(rune('0'+i)),
			AccountID:       "acct-1",
			OrderID:         "order-1",
			Status:          "pending",
			TenantID:        "tenant1",
		}
		err := dao.CreateAuthorization(ctx, authz)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	// Create authorizations for order 2
	for i := 1; i <= 2; i++ {
		authz := &ACMEAuthorization{
			AuthorizationID: "authz-o2-" + string(rune('0'+i)),
			AccountID:       "acct-1",
			OrderID:         "order-2",
			Status:          "pending",
			TenantID:        "tenant1",
		}
		err := dao.CreateAuthorization(ctx, authz)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	// List authorizations for order 1
	authzs1, err := dao.ListAuthorizationsByOrder(ctx, "order-1", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(authzs1) != 3 {
		t.Errorf("expected 3 authorizations for order-1, got %d", len(authzs1))
	}

	// List authorizations for order 2
	authzs2, err := dao.ListAuthorizationsByOrder(ctx, "order-2", "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(authzs2) != 2 {
		t.Errorf("expected 2 authorizations for order-2, got %d", len(authzs2))
	}
}

func TestACMEDAO_CleanupExpiredAuthorizations(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create expired authorization
	expiredAuthz := &ACMEAuthorization{
		AuthorizationID: "authz-expired",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		ExpiresAt:       now.Add(-1 * time.Hour),
		TenantID:        "tenant1",
	}
	err := dao.CreateAuthorization(ctx, expiredAuthz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Create valid authorization
	validAuthz := &ACMEAuthorization{
		AuthorizationID: "authz-valid",
		AccountID:       "acct-1",
		OrderID:         "order-1",
		Status:          "pending",
		ExpiresAt:       now.Add(24 * time.Hour),
		TenantID:        "tenant1",
	}
	err = dao.CreateAuthorization(ctx, validAuthz)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	deleted, err := dao.CleanupExpiredAuthorizations(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if deleted != 1 {
		t.Errorf("expected 1 deleted, got %d", deleted)
	}

	// Verify valid authorization still exists
	_, err = dao.GetAuthorization(ctx, "authz-valid", "tenant1")
	if err != nil {
		t.Fatalf("expected valid authorization to still exist, got %v", err)
	}

	// Verify expired authorization is deleted
	_, err = dao.GetAuthorization(ctx, "authz-expired", "tenant1")
	if _, ok := err.(ErrACMEAuthorizationNotFound); !ok {
		t.Error("expected expired authorization to be deleted")
	}
}

// ============================================================================
// Count Tests
// ============================================================================

func TestACMEDAO_CountAccounts(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		account := &ACMEAccount{
			AccountID: "acct-" + string(rune('0'+i)),
			Status:    "valid",
			TenantID:  "tenant1",
		}
		err := dao.CreateAccount(ctx, account)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := dao.CountAccounts(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}
}

func TestACMEDAO_CountOrders(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		order := &ACMEOrder{
			OrderID:   "order-" + string(rune('0'+i)),
			AccountID: "acct-1",
			Status:    "pending",
			TenantID:  "tenant1",
		}
		err := dao.CreateOrder(ctx, order)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := dao.CountOrders(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}
}

func TestACMEDAO_CountAuthorizations(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		authz := &ACMEAuthorization{
			AuthorizationID: "authz-" + string(rune('0'+i)),
			AccountID:       "acct-1",
			OrderID:         "order-1",
			Status:          "pending",
			TenantID:        "tenant1",
		}
		err := dao.CreateAuthorization(ctx, authz)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	}

	count, err := dao.CountAuthorizations(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if count != 4 {
		t.Errorf("expected count 4, got %d", count)
	}
}

// ============================================================================
// Options and Helper Tests
// ============================================================================

func TestACMEDAO_Options(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()

	dao := NewACMEDAO(
		storage,
		logger,
		WithACMERequestTimeout(5*time.Second),
		WithACMEOptimisticLocking(false),
	)

	if dao.requestTimeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", dao.requestTimeout)
	}

	if dao.enableOptimisticLocking {
		t.Error("expected optimistic locking to be disabled")
	}
}

func TestACMEIDToEntityID(t *testing.T) {
	id1 := acmeIDToEntityID("acct-1", "tenant1")
	id2 := acmeIDToEntityID("acct-1", "tenant1")
	id3 := acmeIDToEntityID("acct-2", "tenant1")
	id4 := acmeIDToEntityID("acct-1", "tenant2")

	// Same ID and tenant should produce same entity ID
	if id1 != id2 {
		t.Errorf("expected same entity ID, got %d and %d", id1, id2)
	}

	// Different ACME ID should produce different entity ID
	if id1 == id3 {
		t.Error("expected different entity ID for different ACME ID")
	}

	// Different tenant should produce different entity ID
	if id1 == id4 {
		t.Error("expected different entity ID for different tenant")
	}

	// ID should not be zero
	if id1 == 0 {
		t.Error("expected non-zero ID")
	}
}

// ============================================================================
// Entity Helper Method Tests
// ============================================================================

func TestACMEAccount_IsActive(t *testing.T) {
	activeAccount := &ACMEAccount{Status: "valid"}
	if !activeAccount.IsActive() {
		t.Error("expected IsActive() to return true for valid status")
	}

	inactiveAccount := &ACMEAccount{Status: "deactivated"}
	if inactiveAccount.IsActive() {
		t.Error("expected IsActive() to return false for deactivated status")
	}
}

func TestACMEOrder_IsExpired(t *testing.T) {
	now := time.Now().UTC()

	expiredOrder := &ACMEOrder{ExpiresAt: now.Add(-1 * time.Hour)}
	if !expiredOrder.IsExpired() {
		t.Error("expected IsExpired() to return true")
	}

	validOrder := &ACMEOrder{ExpiresAt: now.Add(1 * time.Hour)}
	if validOrder.IsExpired() {
		t.Error("expected IsExpired() to return false")
	}
}

func TestACMEAuthorization_IsExpired(t *testing.T) {
	now := time.Now().UTC()

	expiredAuthz := &ACMEAuthorization{ExpiresAt: now.Add(-1 * time.Hour)}
	if !expiredAuthz.IsExpired() {
		t.Error("expected IsExpired() to return true")
	}

	validAuthz := &ACMEAuthorization{ExpiresAt: now.Add(1 * time.Hour)}
	if validAuthz.IsExpired() {
		t.Error("expected IsExpired() to return false")
	}
}

func TestNewACMEAccount(t *testing.T) {
	account := NewACMEAccount("acct-1", []byte(`{"kty":"RSA"}`), []string{"mailto:test@example.com"}, "tenant1")

	if account.AccountID != "acct-1" {
		t.Errorf("expected AccountID acct-1, got %s", account.AccountID)
	}

	if account.Status != "valid" {
		t.Errorf("expected Status valid, got %s", account.Status)
	}

	if !account.TermsOfServiceAgreed {
		t.Error("expected TermsOfServiceAgreed to be true")
	}

	if account.Version != 1 {
		t.Errorf("expected Version 1, got %d", account.Version)
	}
}

func TestNewACMEOrder(t *testing.T) {
	identifiers := []ACMEIdentifier{
		{Type: "dns", Value: "example.com"},
	}
	order := NewACMEOrder("order-1", "acct-1", identifiers, "tenant1")

	if order.OrderID != "order-1" {
		t.Errorf("expected OrderID order-1, got %s", order.OrderID)
	}

	if order.AccountID != "acct-1" {
		t.Errorf("expected AccountID acct-1, got %s", order.AccountID)
	}

	if order.Status != "pending" {
		t.Errorf("expected Status pending, got %s", order.Status)
	}

	if len(order.Identifiers) != 1 {
		t.Errorf("expected 1 identifier, got %d", len(order.Identifiers))
	}

	if order.Version != 1 {
		t.Errorf("expected Version 1, got %d", order.Version)
	}

	// Should expire in approximately 7 days
	expectedExpiry := time.Now().Add(7 * 24 * time.Hour)
	diff := order.ExpiresAt.Sub(expectedExpiry)
	if diff < -1*time.Second || diff > 1*time.Second {
		t.Errorf("expected ExpiresAt to be approximately 7 days from now")
	}
}

func TestNewACMEAuthorization(t *testing.T) {
	identifier := ACMEIdentifier{Type: "dns", Value: "example.com"}
	authz := NewACMEAuthorization("authz-1", "acct-1", "order-1", identifier, "tenant1")

	if authz.AuthorizationID != "authz-1" {
		t.Errorf("expected AuthorizationID authz-1, got %s", authz.AuthorizationID)
	}

	if authz.AccountID != "acct-1" {
		t.Errorf("expected AccountID acct-1, got %s", authz.AccountID)
	}

	if authz.OrderID != "order-1" {
		t.Errorf("expected OrderID order-1, got %s", authz.OrderID)
	}

	if authz.Status != "pending" {
		t.Errorf("expected Status pending, got %s", authz.Status)
	}

	if authz.Identifier.Value != "example.com" {
		t.Errorf("expected identifier value example.com, got %s", authz.Identifier.Value)
	}

	if authz.Version != 1 {
		t.Errorf("expected Version 1, got %d", authz.Version)
	}
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestACMEDAO_ConcurrentAccess(t *testing.T) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent account creates
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			account := &ACMEAccount{
				AccountID: "acct-" + string(rune('A'+id)),
				Status:    "valid",
				TenantID:  "tenant1",
			}
			err := dao.CreateAccount(ctx, account)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	count, err := dao.CountAccounts(ctx, "tenant1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if count != numGoroutines {
		t.Errorf("expected %d accounts, got %d", numGoroutines, count)
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkACMEDAO_CreateAccount(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		account := &ACMEAccount{
			AccountID: "acct-" + string(rune('A'+i%26)),
			Status:    "valid",
			TenantID:  "tenant1",
		}
		_ = dao.CreateAccount(ctx, account)
	}
}

func BenchmarkACMEDAO_GetAccount(b *testing.B) {
	storage := NewMockDAOStorage()
	logger := newTestLogger()
	dao := NewACMEDAO(storage, logger)

	ctx := context.Background()
	account := &ACMEAccount{
		AccountID: "acct-test",
		Status:    "valid",
		TenantID:  "tenant1",
	}
	_ = dao.CreateAccount(ctx, account)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = dao.GetAccount(ctx, "acct-test", "tenant1")
	}
}

func BenchmarkACMEIDToEntityID(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = acmeIDToEntityID("acct-test-id", "tenant1")
	}
}
