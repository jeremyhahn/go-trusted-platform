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

package quota

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Enforcer validates and reserves quota before resource creation.
type Enforcer struct {
	store  QuotaStore
	logger *slog.Logger

	// pending holds reservations that have not yet been committed.
	// Key is reservation ID, value is *Reservation.
	pending sync.Map

	// reservationTTL is the time-to-live for reservations.
	reservationTTL time.Duration

	// clk is the enforcer's view of time. Reservation expiry is the only thing
	// this type derives from the clock, and it is the whole of what its tests
	// need to control. Fixed at construction and never mutated; production
	// always gets realQuotaClock.
	clk quotaClock
}

// quotaClock is the enforcer's entire view of time.
//
// One method, and identical in shape to pkg/sdn/bgp's dampeningClock (#284) —
// the first two consumers of this seam diverged, so a match is worth stating
// explicitly. Both are single-method because nothing in either package blocks on
// a computed interval; pkg/security/ratelimit needed a second method (After)
// precisely because its WaitN does.
type quotaClock interface {
	Now() time.Time
}

// realQuotaClock is the production clock: the standard library, unmodified.
type realQuotaClock struct{}

// Now returns the current wall-clock time.
func (realQuotaClock) Now() time.Time { return time.Now() }

// WithQuotaClock substitutes the enforcer's clock. It exists for tests, which
// advance a fake to expire a reservation instantly rather than sleeping out its
// TTL; passing nil leaves the production clock in place.
func WithQuotaClock(clk quotaClock) EnforcerOption {
	return func(e *Enforcer) {
		if clk != nil {
			e.clk = clk
		}
	}
}

// EnforcerOption is a functional option for configuring the Enforcer.
type EnforcerOption func(*Enforcer)

// WithReservationTTL sets the reservation time-to-live.
func WithReservationTTL(ttl time.Duration) EnforcerOption {
	return func(e *Enforcer) {
		e.reservationTTL = ttl
	}
}

// NewEnforcer creates a new quota enforcer.
func NewEnforcer(store QuotaStore, logger *slog.Logger, opts ...EnforcerOption) (*Enforcer, error) {
	if store == nil {
		return nil, ErrNilStore{}
	}
	if logger == nil {
		return nil, ErrNilLogger{}
	}

	e := &Enforcer{
		store:          store,
		logger:         logger,
		reservationTTL: DefaultReservationTTL,
		clk:            realQuotaClock{},
	}

	for _, opt := range opts {
		opt(e)
	}

	return e, nil
}

// expired reports whether r has passed its expiry according to THIS enforcer's
// clock.
//
// Reservation.IsExpired() answers the same question from the wall clock, which
// is correct for an external caller holding a reservation but unreachable from a
// test driving the enforcer: the predicate lives on the value type, and the
// clock lives on the manager. All four production callers are in this file, so
// routing them through the enforcer is enough — the exported method stays for
// callers who do want wall-clock semantics.
//
// entities.Invitation had the same split and could not take this shape, because
// its objects are reconstituted zero-valued from the datastore; it resolved it
// the other way, by taking now as a parameter on every method (#311).
func (e *Enforcer) expired(r *Reservation) bool {
	return e.clk.Now().After(r.ExpiresAt)
}

// getReservedAmount returns the current reserved amount for a tenant resource.
func (e *Enforcer) getReservedAmount(tenantID string, resource ResourceType) int64 {
	var total int64

	e.pending.Range(func(_, value any) bool {
		res := value.(*Reservation)
		if res.TenantID == tenantID && res.Resource == resource && !res.Committed && !e.expired(res) {
			total += res.Amount
		}
		return true
	})

	return total
}

// CheckQuota verifies if the request can be fulfilled.
func (e *Enforcer) CheckQuota(ctx context.Context, tenantID string, resource ResourceType, amount int64) error {
	if !resource.IsValid() {
		return ErrInvalidResource{Resource: resource}
	}
	if amount < 0 {
		return ErrInvalidAmount{Resource: resource, Amount: amount}
	}

	quotas, err := e.store.GetQuota(ctx, tenantID)
	if err != nil {
		return ErrStoreFailed{Operation: "GetQuota", Err: err}
	}
	if quotas == nil {
		return ErrTenantNotFound{TenantID: tenantID}
	}

	usage, err := e.store.GetUsage(ctx, tenantID)
	if err != nil {
		return ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	limit := quotas.GetLimit(resource)
	currentUsage := int64(0)
	if usage != nil {
		currentUsage = usage.GetUsage(resource)
	}
	reserved := e.getReservedAmount(tenantID, resource)

	available := limit - currentUsage - reserved
	if amount > available {
		return ErrQuotaExceeded{
			TenantID:  tenantID,
			Resource:  resource,
			Requested: amount,
			Available: available,
		}
	}

	return nil
}

// Reserve creates a temporary quota reservation.
func (e *Enforcer) Reserve(ctx context.Context, tenantID string, resource ResourceType, amount int64) (*Reservation, error) {
	if !resource.IsValid() {
		return nil, ErrInvalidResource{Resource: resource}
	}
	if amount <= 0 {
		return nil, ErrInvalidAmount{Resource: resource, Amount: amount}
	}

	// Check if quota is available before reserving.
	if err := e.CheckQuota(ctx, tenantID, resource, amount); err != nil {
		return nil, err
	}

	now := e.clk.Now()
	reservation := &Reservation{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		Resource:  resource,
		Amount:    amount,
		CreatedAt: now,
		ExpiresAt: now.Add(e.reservationTTL),
		Committed: false,
	}

	e.pending.Store(reservation.ID, reservation)

	e.logger.Debug("quota reservation created",
		slog.String("reservation_id", reservation.ID),
		slog.String("tenant_id", tenantID),
		slog.String("resource", string(resource)),
		slog.Int64("amount", amount),
	)

	return reservation, nil
}

// Commit finalizes a reservation, updating actual usage.
func (e *Enforcer) Commit(ctx context.Context, reservationID string) error {
	value, ok := e.pending.Load(reservationID)
	if !ok {
		return ErrReservationNotFound{ID: reservationID}
	}

	reservation := value.(*Reservation)

	if reservation.Committed {
		return ErrReservationAlreadyCommitted{ID: reservationID}
	}

	if e.expired(reservation) {
		e.pending.Delete(reservationID)
		return ErrReservationExpired{ID: reservationID}
	}

	// Get current usage.
	usage, err := e.store.GetUsage(ctx, reservation.TenantID)
	if err != nil {
		return ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	if usage == nil {
		usage = &TenantUsage{
			TenantID:  reservation.TenantID,
			Timestamp: e.clk.Now(),
		}
	}

	// Update usage.
	currentUsage := usage.GetUsage(reservation.Resource)
	usage.SetUsage(reservation.Resource, currentUsage+reservation.Amount)
	usage.Timestamp = e.clk.Now()

	if err := e.store.UpdateUsage(ctx, reservation.TenantID, usage); err != nil {
		return ErrStoreFailed{Operation: "UpdateUsage", Err: err}
	}

	// Mark reservation as committed and remove from pending.
	reservation.Committed = true
	e.pending.Delete(reservationID)

	e.logger.Debug("quota reservation committed",
		slog.String("reservation_id", reservationID),
		slog.String("tenant_id", reservation.TenantID),
		slog.String("resource", string(reservation.Resource)),
		slog.Int64("amount", reservation.Amount),
	)

	return nil
}

// Release cancels a reservation without updating usage.
func (e *Enforcer) Release(ctx context.Context, reservationID string) error {
	value, ok := e.pending.Load(reservationID)
	if !ok {
		return ErrReservationNotFound{ID: reservationID}
	}

	reservation := value.(*Reservation)

	if reservation.Committed {
		return ErrReservationAlreadyCommitted{ID: reservationID}
	}

	e.pending.Delete(reservationID)

	e.logger.Debug("quota reservation released",
		slog.String("reservation_id", reservationID),
		slog.String("tenant_id", reservation.TenantID),
		slog.String("resource", string(reservation.Resource)),
		slog.Int64("amount", reservation.Amount),
	)

	return nil
}

// ReleaseUsage directly releases used quota (for resource deletion).
func (e *Enforcer) ReleaseUsage(ctx context.Context, tenantID string, resource ResourceType, amount int64) error {
	if !resource.IsValid() {
		return ErrInvalidResource{Resource: resource}
	}
	if amount <= 0 {
		return ErrInvalidAmount{Resource: resource, Amount: amount}
	}

	usage, err := e.store.GetUsage(ctx, tenantID)
	if err != nil {
		return ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	if usage == nil {
		return ErrTenantNotFound{TenantID: tenantID}
	}

	currentUsage := usage.GetUsage(resource)
	newUsage := currentUsage - amount
	if newUsage < 0 {
		newUsage = 0
	}

	usage.SetUsage(resource, newUsage)
	usage.Timestamp = e.clk.Now()

	if err := e.store.UpdateUsage(ctx, tenantID, usage); err != nil {
		return ErrStoreFailed{Operation: "UpdateUsage", Err: err}
	}

	e.logger.Debug("quota usage released",
		slog.String("tenant_id", tenantID),
		slog.String("resource", string(resource)),
		slog.Int64("amount", amount),
		slog.Int64("new_usage", newUsage),
	)

	return nil
}

// GetAvailable returns available quota for a resource.
func (e *Enforcer) GetAvailable(ctx context.Context, tenantID string, resource ResourceType) (int64, error) {
	if !resource.IsValid() {
		return 0, ErrInvalidResource{Resource: resource}
	}

	quotas, err := e.store.GetQuota(ctx, tenantID)
	if err != nil {
		return 0, ErrStoreFailed{Operation: "GetQuota", Err: err}
	}
	if quotas == nil {
		return 0, ErrTenantNotFound{TenantID: tenantID}
	}

	usage, err := e.store.GetUsage(ctx, tenantID)
	if err != nil {
		return 0, ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	limit := quotas.GetLimit(resource)
	currentUsage := int64(0)
	if usage != nil {
		currentUsage = usage.GetUsage(resource)
	}
	reserved := e.getReservedAmount(tenantID, resource)

	available := limit - currentUsage - reserved
	if available < 0 {
		available = 0
	}

	return available, nil
}

// GetUtilization returns quota utilization percentage (0.0 to 1.0).
func (e *Enforcer) GetUtilization(ctx context.Context, tenantID string, resource ResourceType) (float64, error) {
	if !resource.IsValid() {
		return 0, ErrInvalidResource{Resource: resource}
	}

	quotas, err := e.store.GetQuota(ctx, tenantID)
	if err != nil {
		return 0, ErrStoreFailed{Operation: "GetQuota", Err: err}
	}
	if quotas == nil {
		return 0, ErrTenantNotFound{TenantID: tenantID}
	}

	usage, err := e.store.GetUsage(ctx, tenantID)
	if err != nil {
		return 0, ErrStoreFailed{Operation: "GetUsage", Err: err}
	}

	limit := quotas.GetLimit(resource)
	if limit == 0 {
		return 0, nil
	}

	currentUsage := int64(0)
	if usage != nil {
		currentUsage = usage.GetUsage(resource)
	}
	reserved := e.getReservedAmount(tenantID, resource)

	utilization := float64(currentUsage+reserved) / float64(limit)
	if utilization > 1.0 {
		utilization = 1.0
	}

	return utilization, nil
}

// CleanupExpiredReservations removes expired reservations.
func (e *Enforcer) CleanupExpiredReservations() int {
	count := 0

	e.pending.Range(func(key, value any) bool {
		reservation := value.(*Reservation)
		if e.expired(reservation) && !reservation.Committed {
			e.pending.Delete(key)
			count++

			e.logger.Debug("expired reservation cleaned up",
				slog.String("reservation_id", reservation.ID),
				slog.String("tenant_id", reservation.TenantID),
			)
		}
		return true
	})

	return count
}

// GetReservation returns a reservation by ID.
func (e *Enforcer) GetReservation(reservationID string) (*Reservation, error) {
	value, ok := e.pending.Load(reservationID)
	if !ok {
		return nil, ErrReservationNotFound{ID: reservationID}
	}

	return value.(*Reservation), nil
}

// GetPendingReservations returns all pending reservations for a tenant.
func (e *Enforcer) GetPendingReservations(tenantID string) []*Reservation {
	var reservations []*Reservation

	e.pending.Range(func(_, value any) bool {
		reservation := value.(*Reservation)
		if reservation.TenantID == tenantID && !reservation.Committed && !e.expired(reservation) {
			reservations = append(reservations, reservation)
		}
		return true
	})

	return reservations
}
