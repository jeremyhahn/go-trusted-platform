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
	"sync"
	"time"

	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// =============================================================================
// Fake InvitationServicer
// =============================================================================

// fakeInvitationServicer is a fully in-memory test double that satisfies
// platformservice.InvitationServicer. It records the last call so tests
// can assert delegation.
type fakeInvitationServicer struct {
	// mu guards invitationCalls: a transport's server goroutine records a
	// call while the test reads it, and a reply over a socket gives the race
	// detector no happens-before edge.
	mu sync.Mutex
	invitationCalls

	createResult *entities.Invitation
	createErr    error

	getByIDResult *entities.Invitation
	getByIDErr    error

	getByTokenResult *entities.Invitation
	getByTokenErr    error

	listResult []*entities.Invitation
	listErr    error

	revokeReturned error
	acceptReturned error
	deleteReturned error

	cleanupResult   int
	cleanupReturned error
}

// invitationCalls is what fakeInvitationServicer records of the calls it
// serves.
type invitationCalls struct {
	createCalls int
	createReq   *platformservice.CreateInvitationRequest

	getByIDCalls int
	getByIDID    uint64

	getByTokenCalls int
	getByTokenToken string

	listCalls   int
	listTenant  string
	listPending bool

	revokeCalls   int
	revokeID      uint64
	revokeRevoker uint64

	acceptCalls int
	acceptToken string
	acceptUser  uint64

	deleteCalls int
	deleteID    uint64

	cleanupCalls int
}

// calls returns a copy of the recorded calls, taken under the lock.
func (f *fakeInvitationServicer) calls() invitationCalls {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.invitationCalls
}

// record runs one call's bookkeeping under the lock.
func (f *fakeInvitationServicer) record(note func(*invitationCalls)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	note(&f.invitationCalls)
}

func (f *fakeInvitationServicer) Create(_ context.Context, req *platformservice.CreateInvitationRequest) (*entities.Invitation, error) {
	f.record(func(c *invitationCalls) {
		c.createCalls++
		c.createReq = req
	})
	return f.createResult, f.createErr
}

func (f *fakeInvitationServicer) GetByID(_ context.Context, id uint64) (*entities.Invitation, error) {
	f.record(func(c *invitationCalls) {
		c.getByIDCalls++
		c.getByIDID = id
	})
	return f.getByIDResult, f.getByIDErr
}

func (f *fakeInvitationServicer) GetByToken(_ context.Context, token string) (*entities.Invitation, error) {
	f.record(func(c *invitationCalls) {
		c.getByTokenCalls++
		c.getByTokenToken = token
	})
	return f.getByTokenResult, f.getByTokenErr
}

func (f *fakeInvitationServicer) Accept(_ context.Context, token string, userID uint64) error {
	f.record(func(c *invitationCalls) {
		c.acceptCalls++
		c.acceptToken = token
		c.acceptUser = userID
	})
	return f.acceptReturned
}

func (f *fakeInvitationServicer) Revoke(_ context.Context, id, revokerID uint64) error {
	f.record(func(c *invitationCalls) {
		c.revokeCalls++
		c.revokeID = id
		c.revokeRevoker = revokerID
	})
	return f.revokeReturned
}

func (f *fakeInvitationServicer) ListByTenant(_ context.Context, tenantID string) ([]*entities.Invitation, error) {
	f.record(func(c *invitationCalls) {
		c.listCalls++
		c.listTenant = tenantID
		c.listPending = false
	})
	return f.listResult, f.listErr
}

func (f *fakeInvitationServicer) ListPendingByTenant(_ context.Context, tenantID string) ([]*entities.Invitation, error) {
	f.record(func(c *invitationCalls) {
		c.listCalls++
		c.listTenant = tenantID
		c.listPending = true
	})
	return f.listResult, f.listErr
}

func (f *fakeInvitationServicer) CleanupExpired(_ context.Context) (int, error) {
	f.record(func(c *invitationCalls) { c.cleanupCalls++ })
	return f.cleanupResult, f.cleanupReturned
}

func (f *fakeInvitationServicer) Delete(_ context.Context, id uint64) error {
	f.record(func(c *invitationCalls) {
		c.deleteCalls++
		c.deleteID = id
	})
	return f.deleteReturned
}

// Compile-time assertion.
var _ platformservice.InvitationServicer = (*fakeInvitationServicer)(nil)

// =============================================================================
// Helpers
// =============================================================================

func newTestInvitation() *entities.Invitation {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return &entities.Invitation{
		ID:          42,
		Token:       "tok-1",
		TenantID:    "tenant-1",
		Email:       "alice@example.com",
		Role:        "member",
		Status:      entities.InvitationStatusPending,
		InvitedByID: 99,
		ExpiresAt:   now.Add(7 * 24 * time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}
