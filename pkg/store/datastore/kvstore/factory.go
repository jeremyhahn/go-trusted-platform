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

package kvstore

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Factory implements datastore.Factory backed by a key-value store.
// It manages the lifecycle of the storage client and provides
// access to specialized DAOs for each entity type.
type Factory struct {
	storage Storage
	logger  *logging.Logger

	organizationDAO *OrganizationDAO
	userDAO         *UserDAO
	registrationDAO *RegistrationDAO
	invitationDAO   *InvitationDAO
	roleDAO         *RoleDAO
	webAuthnDAO     *WebAuthnDAO

	mu     sync.RWMutex
	closed atomic.Bool
}

// NewFactory creates a new key-value store backed datastore factory.
// The factory manages the storage client lifecycle.
func NewFactory(storage Storage, logger *logging.Logger) *Factory {
	return &Factory{
		storage: storage,
		logger:  logger,
	}
}

// Start initializes the storage client and makes the factory ready for use.
// This must be called before any DAO methods.
func (f *Factory) Start(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return ErrFactoryClosed{}
	}

	return f.storage.Start(ctx)
}

// Stop gracefully shuts down the storage client.
func (f *Factory) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil
	}

	f.closed.Store(true)
	return f.storage.Stop(ctx)
}

// OrganizationDAO returns the organization DAO, creating it lazily if needed.
func (f *Factory) OrganizationDAO() (datastore.OrganizationDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.organizationDAO == nil {
		f.organizationDAO = NewOrganizationDAO(f.storage, f.logger)
	}
	return f.organizationDAO, nil
}

// UserDAO returns the user DAO, creating it lazily if needed.
func (f *Factory) UserDAO() (datastore.UserDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.userDAO == nil {
		f.userDAO = NewUserDAO(f.storage, f.logger)
	}
	return f.userDAO, nil
}

// RegistrationDAO returns the registration DAO, creating it lazily if needed.
func (f *Factory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.registrationDAO == nil {
		f.registrationDAO = NewRegistrationDAO(f.storage, f.logger)
	}
	return f.registrationDAO, nil
}

// InvitationDAO returns the invitation DAO, creating it lazily if needed.
func (f *Factory) InvitationDAO() (datastore.InvitationDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.invitationDAO == nil {
		f.invitationDAO = NewInvitationDAO(f.storage, f.logger)
	}
	return f.invitationDAO, nil
}

// RoleDAO returns the role DAO, creating it lazily if needed.
func (f *Factory) RoleDAO() (datastore.RoleDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.roleDAO == nil {
		f.roleDAO = NewRoleDAO(f.storage, f.logger)
	}
	return f.roleDAO, nil
}

// WebAuthnDAO returns the WebAuthn DAO, creating it lazily if needed.
func (f *Factory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed.Load() {
		return nil, ErrFactoryClosed{}
	}

	if f.webAuthnDAO == nil {
		f.webAuthnDAO = NewWebAuthnDAO(f.storage, f.logger)
	}
	return f.webAuthnDAO, nil
}

// SerializerType returns the serializer type used by this factory.
// The kvstore stores data as JSON internally.
func (f *Factory) SerializerType() serializer.SerializerType {
	return serializer.SERIALIZER_JSON
}

// Storage returns the underlying storage client.
// This is useful for advanced operations or testing.
func (f *Factory) Storage() Storage {
	return f.storage
}

// IsStarted returns true if the factory has been started.
func (f *Factory) IsStarted() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.storage.IsStarted()
}

// IsClosed returns true if the factory has been closed.
func (f *Factory) IsClosed() bool {
	return f.closed.Load()
}

// Compile-time interface satisfaction checks
var (
	_ datastore.Factory          = (*Factory)(nil)
	_ datastore.LifecycleFactory = (*Factory)(nil)
)
