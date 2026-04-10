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
	"encoding/json"
	"hash/fnv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ACMEDAO provides QuicBaaS-backed storage for ACME entities.
// It handles ACMEAccount, ACMEOrder, and ACMEAuthorization with
// optimistic locking and tenant isolation.
//
// Thread Safety: All methods are thread-safe as they delegate to the
// underlying QuicBaaS service which handles concurrency internally.
type ACMEDAO struct {
	storage                 DAOStorage
	logger                  *logging.Logger
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// ACMEDAOOption is a functional option for configuring ACMEDAO.
type ACMEDAOOption func(*acmeDAOConfig)

type acmeDAOConfig struct {
	requestTimeout          time.Duration
	enableOptimisticLocking bool
}

// WithACMERequestTimeout sets the request timeout for DAO operations.
func WithACMERequestTimeout(timeout time.Duration) ACMEDAOOption {
	return func(c *acmeDAOConfig) {
		c.requestTimeout = timeout
	}
}

// WithACMEOptimisticLocking enables or disables optimistic locking.
func WithACMEOptimisticLocking(enabled bool) ACMEDAOOption {
	return func(c *acmeDAOConfig) {
		c.enableOptimisticLocking = enabled
	}
}

// NewACMEDAO creates a new ACMEDAO.
func NewACMEDAO(
	storage DAOStorage,
	logger *logging.Logger,
	opts ...ACMEDAOOption,
) *ACMEDAO {
	cfg := &acmeDAOConfig{
		requestTimeout:          DefaultRequestTimeout,
		enableOptimisticLocking: true,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	return &ACMEDAO{
		storage:                 storage,
		logger:                  logger,
		requestTimeout:          cfg.requestTimeout,
		enableOptimisticLocking: cfg.enableOptimisticLocking,
	}
}

// ============================================================================
// ACMEAccount Operations
// ============================================================================

// CreateAccount stores a new ACME account.
// Returns ErrACMEAccountAlreadyExists if an account with the same ID exists.
func (d *ACMEDAO) CreateAccount(ctx context.Context, account *ACMEAccount) error {
	if account == nil {
		return ErrInvalidInput{Field: "account", Reason: "cannot be nil"}
	}
	if account.AccountID == "" {
		return ErrInvalidInput{Field: "account_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(account.AccountID, account.TenantID)
	account.SetEntityID(entityID)

	// Check if account already exists
	_, found, err := d.storage.Get(ctx, EntityTypeACMEAccount, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "create ACME account", Cause: err}
	}
	if found {
		return ErrACMEAccountAlreadyExists{
			AccountID: account.AccountID,
			TenantID:  account.TenantID,
		}
	}

	account.Version = 1

	data, err := json.Marshal(account)
	if err != nil {
		return ErrOperationFailed{Operation: "create ACME account", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEAccount, entityID, data, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "create ACME account", Cause: err}
	}

	d.logger.Debug("ACME account created",
		"id", account.AccountID,
		"tenant", account.TenantID)

	return nil
}

// GetAccount retrieves an ACME account by ID.
// Returns ErrACMEAccountNotFound if the account does not exist.
func (d *ACMEDAO) GetAccount(ctx context.Context, accountID string, tenantID string) (*ACMEAccount, error) {
	if accountID == "" {
		return nil, ErrInvalidInput{Field: "account_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(accountID, tenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEAccount, entityID, DefaultShardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME account", Cause: err}
	}
	if !found {
		return nil, ErrACMEAccountNotFound{AccountID: accountID, TenantID: tenantID}
	}

	var account ACMEAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME account", Cause: err}
	}

	account.SetEntityID(entityID)
	return &account, nil
}

// UpdateAccount updates an existing ACME account.
// Returns ErrACMEAccountNotFound if the account does not exist.
// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
func (d *ACMEDAO) UpdateAccount(ctx context.Context, account *ACMEAccount) error {
	if account == nil {
		return ErrInvalidInput{Field: "account", Reason: "cannot be nil"}
	}
	if account.AccountID == "" {
		return ErrInvalidInput{Field: "account_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(account.AccountID, account.TenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEAccount, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME account", Cause: err}
	}
	if !found {
		return ErrACMEAccountNotFound{AccountID: account.AccountID, TenantID: account.TenantID}
	}

	if d.enableOptimisticLocking {
		var existing ACMEAccount
		if err := json.Unmarshal(data, &existing); err != nil {
			return ErrOperationFailed{Operation: "update ACME account", Cause: err}
		}

		if account.Version != existing.Version {
			return ErrVersionConflict{
				EntityType:      EntityTypeACMEAccount,
				EntityID:        account.AccountID,
				ExpectedVersion: account.Version,
				ActualVersion:   existing.Version,
			}
		}
	}

	account.Version++
	account.SetEntityID(entityID)

	updatedData, err := json.Marshal(account)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME account", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEAccount, entityID, updatedData, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "update ACME account", Cause: err}
	}

	d.logger.Debug("ACME account updated",
		"id", account.AccountID,
		"version", account.Version)

	return nil
}

// DeleteAccount removes an ACME account from storage.
// Returns ErrACMEAccountNotFound if the account does not exist.
func (d *ACMEDAO) DeleteAccount(ctx context.Context, accountID string, tenantID string) error {
	if accountID == "" {
		return ErrInvalidInput{Field: "account_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(accountID, tenantID)

	_, found, err := d.storage.Get(ctx, EntityTypeACMEAccount, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete ACME account", Cause: err}
	}
	if !found {
		return ErrACMEAccountNotFound{AccountID: accountID, TenantID: tenantID}
	}

	if err := d.storage.Delete(ctx, EntityTypeACMEAccount, entityID, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "delete ACME account", Cause: err}
	}

	d.logger.Debug("ACME account deleted", "id", accountID)
	return nil
}

// ============================================================================
// ACMEOrder Operations
// ============================================================================

// CreateOrder stores a new ACME order.
func (d *ACMEDAO) CreateOrder(ctx context.Context, order *ACMEOrder) error {
	if order == nil {
		return ErrInvalidInput{Field: "order", Reason: "cannot be nil"}
	}
	if order.OrderID == "" {
		return ErrInvalidInput{Field: "order_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(order.OrderID, order.TenantID)
	order.SetEntityID(entityID)
	order.Version = 1

	data, err := json.Marshal(order)
	if err != nil {
		return ErrOperationFailed{Operation: "create ACME order", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEOrder, entityID, data, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "create ACME order", Cause: err}
	}

	d.logger.Debug("ACME order created",
		"id", order.OrderID,
		"account", order.AccountID,
		"tenant", order.TenantID)

	return nil
}

// GetOrder retrieves an ACME order by ID.
// Returns ErrACMEOrderNotFound if the order does not exist.
func (d *ACMEDAO) GetOrder(ctx context.Context, orderID string, tenantID string) (*ACMEOrder, error) {
	if orderID == "" {
		return nil, ErrInvalidInput{Field: "order_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(orderID, tenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEOrder, entityID, DefaultShardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME order", Cause: err}
	}
	if !found {
		return nil, ErrACMEOrderNotFound{OrderID: orderID, TenantID: tenantID}
	}

	var order ACMEOrder
	if err := json.Unmarshal(data, &order); err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME order", Cause: err}
	}

	order.SetEntityID(entityID)
	return &order, nil
}

// UpdateOrder updates an existing ACME order.
// Returns ErrACMEOrderNotFound if the order does not exist.
// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
func (d *ACMEDAO) UpdateOrder(ctx context.Context, order *ACMEOrder) error {
	if order == nil {
		return ErrInvalidInput{Field: "order", Reason: "cannot be nil"}
	}
	if order.OrderID == "" {
		return ErrInvalidInput{Field: "order_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(order.OrderID, order.TenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEOrder, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME order", Cause: err}
	}
	if !found {
		return ErrACMEOrderNotFound{OrderID: order.OrderID, TenantID: order.TenantID}
	}

	if d.enableOptimisticLocking {
		var existing ACMEOrder
		if err := json.Unmarshal(data, &existing); err != nil {
			return ErrOperationFailed{Operation: "update ACME order", Cause: err}
		}

		if order.Version != existing.Version {
			return ErrVersionConflict{
				EntityType:      EntityTypeACMEOrder,
				EntityID:        order.OrderID,
				ExpectedVersion: order.Version,
				ActualVersion:   existing.Version,
			}
		}
	}

	order.Version++
	order.SetEntityID(entityID)

	updatedData, err := json.Marshal(order)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME order", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEOrder, entityID, updatedData, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "update ACME order", Cause: err}
	}

	d.logger.Debug("ACME order updated",
		"id", order.OrderID,
		"version", order.Version)

	return nil
}

// DeleteOrder removes an ACME order from storage.
// Returns ErrACMEOrderNotFound if the order does not exist.
func (d *ACMEDAO) DeleteOrder(ctx context.Context, orderID string, tenantID string) error {
	if orderID == "" {
		return ErrInvalidInput{Field: "order_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(orderID, tenantID)

	_, found, err := d.storage.Get(ctx, EntityTypeACMEOrder, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete ACME order", Cause: err}
	}
	if !found {
		return ErrACMEOrderNotFound{OrderID: orderID, TenantID: tenantID}
	}

	if err := d.storage.Delete(ctx, EntityTypeACMEOrder, entityID, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "delete ACME order", Cause: err}
	}

	d.logger.Debug("ACME order deleted", "id", orderID)
	return nil
}

// ListOrdersByAccount retrieves all orders for a given account.
func (d *ACMEDAO) ListOrdersByAccount(ctx context.Context, accountID string, tenantID string) ([]*ACMEOrder, error) {
	if accountID == "" {
		return nil, ErrInvalidInput{Field: "account_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var orders []*ACMEOrder
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeACMEOrder, 1000, pageToken, DefaultShardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list ACME orders", Cause: err}
		}

		for _, entity := range entities {
			var order ACMEOrder
			if err := json.Unmarshal(entity.Data, &order); err != nil {
				d.logger.Warn("Failed to deserialize ACME order",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by account and tenant
			if order.AccountID == accountID && (tenantID == "" || order.TenantID == tenantID) {
				order.SetEntityID(entity.ID)
				orders = append(orders, &order)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return orders, nil
}

// CleanupExpiredOrders removes expired ACME orders.
// Returns the number of orders deleted.
func (d *ACMEDAO) CleanupExpiredOrders(ctx context.Context, tenantID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout*10)
	defer cancel()

	now := time.Now().UTC()
	var deletedCount int
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeACMEOrder, 1000, pageToken, DefaultShardID)
		if err != nil {
			return deletedCount, ErrOperationFailed{Operation: "cleanup expired orders", Cause: err}
		}

		for _, entity := range entities {
			var order ACMEOrder
			if err := json.Unmarshal(entity.Data, &order); err != nil {
				d.logger.Warn("Failed to deserialize ACME order during cleanup",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by tenant
			if tenantID != "" && order.TenantID != tenantID {
				continue
			}

			// Delete if expired
			if order.ExpiresAt.Before(now) {
				if err := d.storage.Delete(ctx, EntityTypeACMEOrder, entity.ID, DefaultShardID); err != nil {
					d.logger.Warn("Failed to delete expired order",
						"id", order.OrderID,
						"error", err)
					continue
				}
				deletedCount++
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return deletedCount, nil
}

// ============================================================================
// ACMEAuthorization Operations
// ============================================================================

// CreateAuthorization stores a new ACME authorization.
func (d *ACMEDAO) CreateAuthorization(ctx context.Context, authz *ACMEAuthorization) error {
	if authz == nil {
		return ErrInvalidInput{Field: "authorization", Reason: "cannot be nil"}
	}
	if authz.AuthorizationID == "" {
		return ErrInvalidInput{Field: "authorization_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(authz.AuthorizationID, authz.TenantID)
	authz.SetEntityID(entityID)
	authz.Version = 1

	data, err := json.Marshal(authz)
	if err != nil {
		return ErrOperationFailed{Operation: "create ACME authorization", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEAuth, entityID, data, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "create ACME authorization", Cause: err}
	}

	d.logger.Debug("ACME authorization created",
		"id", authz.AuthorizationID,
		"order", authz.OrderID,
		"tenant", authz.TenantID)

	return nil
}

// GetAuthorization retrieves an ACME authorization by ID.
// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
func (d *ACMEDAO) GetAuthorization(ctx context.Context, authzID string, tenantID string) (*ACMEAuthorization, error) {
	if authzID == "" {
		return nil, ErrInvalidInput{Field: "authorization_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(authzID, tenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEAuth, entityID, DefaultShardID)
	if err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME authorization", Cause: err}
	}
	if !found {
		return nil, ErrACMEAuthorizationNotFound{AuthorizationID: authzID, TenantID: tenantID}
	}

	var authz ACMEAuthorization
	if err := json.Unmarshal(data, &authz); err != nil {
		return nil, ErrOperationFailed{Operation: "get ACME authorization", Cause: err}
	}

	authz.SetEntityID(entityID)
	return &authz, nil
}

// UpdateAuthorization updates an existing ACME authorization.
// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
// Returns ErrVersionConflict if optimistic locking is enabled and version mismatch occurs.
func (d *ACMEDAO) UpdateAuthorization(ctx context.Context, authz *ACMEAuthorization) error {
	if authz == nil {
		return ErrInvalidInput{Field: "authorization", Reason: "cannot be nil"}
	}
	if authz.AuthorizationID == "" {
		return ErrInvalidInput{Field: "authorization_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(authz.AuthorizationID, authz.TenantID)

	data, found, err := d.storage.Get(ctx, EntityTypeACMEAuth, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME authorization", Cause: err}
	}
	if !found {
		return ErrACMEAuthorizationNotFound{AuthorizationID: authz.AuthorizationID, TenantID: authz.TenantID}
	}

	if d.enableOptimisticLocking {
		var existing ACMEAuthorization
		if err := json.Unmarshal(data, &existing); err != nil {
			return ErrOperationFailed{Operation: "update ACME authorization", Cause: err}
		}

		if authz.Version != existing.Version {
			return ErrVersionConflict{
				EntityType:      EntityTypeACMEAuth,
				EntityID:        authz.AuthorizationID,
				ExpectedVersion: authz.Version,
				ActualVersion:   existing.Version,
			}
		}
	}

	authz.Version++
	authz.SetEntityID(entityID)

	updatedData, err := json.Marshal(authz)
	if err != nil {
		return ErrOperationFailed{Operation: "update ACME authorization", Cause: err}
	}

	if err := d.storage.Put(ctx, EntityTypeACMEAuth, entityID, updatedData, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "update ACME authorization", Cause: err}
	}

	d.logger.Debug("ACME authorization updated",
		"id", authz.AuthorizationID,
		"version", authz.Version)

	return nil
}

// DeleteAuthorization removes an ACME authorization from storage.
// Returns ErrACMEAuthorizationNotFound if the authorization does not exist.
func (d *ACMEDAO) DeleteAuthorization(ctx context.Context, authzID string, tenantID string) error {
	if authzID == "" {
		return ErrInvalidInput{Field: "authorization_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	entityID := acmeIDToEntityID(authzID, tenantID)

	_, found, err := d.storage.Get(ctx, EntityTypeACMEAuth, entityID, DefaultShardID)
	if err != nil {
		return ErrOperationFailed{Operation: "delete ACME authorization", Cause: err}
	}
	if !found {
		return ErrACMEAuthorizationNotFound{AuthorizationID: authzID, TenantID: tenantID}
	}

	if err := d.storage.Delete(ctx, EntityTypeACMEAuth, entityID, DefaultShardID); err != nil {
		return ErrOperationFailed{Operation: "delete ACME authorization", Cause: err}
	}

	d.logger.Debug("ACME authorization deleted", "id", authzID)
	return nil
}

// ListAuthorizationsByOrder retrieves all authorizations for a given order.
func (d *ACMEDAO) ListAuthorizationsByOrder(ctx context.Context, orderID string, tenantID string) ([]*ACMEAuthorization, error) {
	if orderID == "" {
		return nil, ErrInvalidInput{Field: "order_id", Reason: "cannot be empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var authzs []*ACMEAuthorization
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeACMEAuth, 1000, pageToken, DefaultShardID)
		if err != nil {
			return nil, ErrOperationFailed{Operation: "list ACME authorizations", Cause: err}
		}

		for _, entity := range entities {
			var authz ACMEAuthorization
			if err := json.Unmarshal(entity.Data, &authz); err != nil {
				d.logger.Warn("Failed to deserialize ACME authorization",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by order and tenant
			if authz.OrderID == orderID && (tenantID == "" || authz.TenantID == tenantID) {
				authz.SetEntityID(entity.ID)
				authzs = append(authzs, &authz)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return authzs, nil
}

// CleanupExpiredAuthorizations removes expired ACME authorizations.
// Returns the number of authorizations deleted.
func (d *ACMEDAO) CleanupExpiredAuthorizations(ctx context.Context, tenantID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout*10)
	defer cancel()

	now := time.Now().UTC()
	var deletedCount int
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, EntityTypeACMEAuth, 1000, pageToken, DefaultShardID)
		if err != nil {
			return deletedCount, ErrOperationFailed{Operation: "cleanup expired authorizations", Cause: err}
		}

		for _, entity := range entities {
			var authz ACMEAuthorization
			if err := json.Unmarshal(entity.Data, &authz); err != nil {
				d.logger.Warn("Failed to deserialize ACME authorization during cleanup",
					"id", entity.ID,
					"error", err)
				continue
			}

			// Filter by tenant
			if tenantID != "" && authz.TenantID != tenantID {
				continue
			}

			// Delete if expired
			if authz.ExpiresAt.Before(now) {
				if err := d.storage.Delete(ctx, EntityTypeACMEAuth, entity.ID, DefaultShardID); err != nil {
					d.logger.Warn("Failed to delete expired authorization",
						"id", authz.AuthorizationID,
						"error", err)
					continue
				}
				deletedCount++
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return deletedCount, nil
}

// ============================================================================
// Count Operations
// ============================================================================

// CountAccounts returns the total number of ACME accounts for a tenant.
func (d *ACMEDAO) CountAccounts(ctx context.Context, tenantID string) (int, error) {
	return d.countEntities(ctx, EntityTypeACMEAccount, tenantID, func(data []byte) string {
		var account ACMEAccount
		if err := json.Unmarshal(data, &account); err != nil {
			return ""
		}
		return account.TenantID
	})
}

// CountOrders returns the total number of ACME orders for a tenant.
func (d *ACMEDAO) CountOrders(ctx context.Context, tenantID string) (int, error) {
	return d.countEntities(ctx, EntityTypeACMEOrder, tenantID, func(data []byte) string {
		var order ACMEOrder
		if err := json.Unmarshal(data, &order); err != nil {
			return ""
		}
		return order.TenantID
	})
}

// CountAuthorizations returns the total number of ACME authorizations for a tenant.
func (d *ACMEDAO) CountAuthorizations(ctx context.Context, tenantID string) (int, error) {
	return d.countEntities(ctx, EntityTypeACMEAuth, tenantID, func(data []byte) string {
		var authz ACMEAuthorization
		if err := json.Unmarshal(data, &authz); err != nil {
			return ""
		}
		return authz.TenantID
	})
}

// countEntities is a helper to count entities with tenant filtering.
func (d *ACMEDAO) countEntities(
	ctx context.Context,
	entityType string,
	tenantID string,
	getTenant func([]byte) string,
) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	count := 0
	pageToken := ""

	for {
		entities, nextToken, err := d.storage.List(ctx, entityType, 1000, pageToken, DefaultShardID)
		if err != nil {
			return 0, ErrOperationFailed{Operation: "count entities", Cause: err}
		}

		if tenantID == "" {
			count += len(entities)
		} else {
			for _, entity := range entities {
				if getTenant(entity.Data) == tenantID {
					count++
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return count, nil
}

// ============================================================================
// Helper Functions
// ============================================================================

// acmeIDToEntityID converts an ACME ID and tenant ID to a QuicBaaS entity ID.
// Uses FNV-1a hashing for fast, deterministic conversion.
// Combines ID and TenantID to ensure tenant isolation.
func acmeIDToEntityID(id, tenantID string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(tenantID))
	h.Write([]byte("/"))
	h.Write([]byte(id))
	return h.Sum64()
}
