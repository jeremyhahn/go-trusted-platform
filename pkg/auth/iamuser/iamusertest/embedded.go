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

// Package iamusertest serves the pinned go-quicbaas SDK's embedded transport
// over an in-memory IAM store, so a test reaches IAM through exactly the
// method table platformd's embedded transport has (#646).
package iamusertest

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam"
	"github.com/jeremyhahn/go-quicbaas/pkg/service"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
)

// identityService is the one capability the embedded IAM handlers ask of
// the service: its identity store. Every other service.QuicBaaS method is
// left unimplemented, so a test that strays beyond IAM users panics.
type identityService struct {
	service.QuicBaaS
	store *iam.IdentityStore
}

func (s *identityService) GetIdentityStore(context.Context) (*iam.IdentityStore, error) {
	return s.store, nil
}

// Embedded is an IAM reached through the embedded transport.
type Embedded struct {
	// Client is the SDK IAM client over the embedded transport.
	Client sdkiam.Client
	// Store is the identity store behind it, for seeding users.
	Store *iam.IdentityStore
}

// NewEmbedded returns an empty IAM behind the pinned embedded transport.
func NewEmbedded(t testing.TB) *Embedded {
	t.Helper()
	memory := iam.NewMemoryStorage()
	store := iam.NewIdentityStore(iam.IdentityStoreOptions{
		UserStorage:  memory,
		GroupStorage: memory,
		RoleStorage:  memory,
	})
	transport, err := embedded.New(&identityService{store: store})
	if err != nil {
		t.Fatalf("iamusertest: embedded transport: %v", err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return &Embedded{Client: sdkiam.NewClient(transport), Store: store}
}

// AddUser creates a user in tenantID in the given lifecycle state and
// returns its IAM user id.
func (e *Embedded) AddUser(t testing.TB, tenantID, email, username string, lifecycle iam.Lifecycle, roles ...string) string {
	t.Helper()
	user, err := e.Store.CreateUser(context.Background(), tenantID, iam.CreateUserOptions{
		Email:     email,
		Username:  username,
		Lifecycle: iam.LifecycleActive,
		Roles:     roles,
	})
	if err != nil {
		t.Fatalf("iamusertest: create %s in %s: %v", email, tenantID, err)
	}
	if lifecycle != "" && lifecycle != iam.LifecycleActive {
		state := lifecycle
		if _, err := e.Store.UpdateUser(context.Background(), tenantID, user.ID, iam.UpdateUserOptions{Lifecycle: &state}); err != nil {
			t.Fatalf("iamusertest: move %s to %s: %v", email, lifecycle, err)
		}
	}
	return user.ID
}

// AddRole creates the role id in tenantID with the given permissions, so a
// user can be given it by AddUser.
func (e *Embedded) AddRole(t testing.TB, tenantID, id string, permissions ...string) {
	t.Helper()
	if _, err := e.Store.CreateRole(context.Background(), tenantID, iam.CreateRoleOptions{
		ID:          id,
		Name:        id,
		Permissions: permissions,
	}); err != nil {
		t.Fatalf("iamusertest: create role %s in %s: %v", id, tenantID, err)
	}
}
