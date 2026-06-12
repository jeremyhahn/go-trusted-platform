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

package quicbaas

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	dnsdao "github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// MockClient implements ClientInterface for testing purposes.
// It provides configurable behavior for all client operations.
type MockClient struct {
	mu       sync.RWMutex
	data     map[string]map[uint64][]byte // entityType -> id -> data
	started  bool
	closed   bool
	embedded bool

	// Entity type discovery
	entityTypes []string

	// Error injection for testing error paths
	StartError           error
	StopError            error
	PutError             error
	GetError             error
	DeleteError          error
	ListError            error
	QueryError           error
	ListEntityTypesError error
}

// NewMockClient creates a new mock QuicBaaS client for testing.
func NewMockClient() *MockClient {
	return &MockClient{
		data:        make(map[string]map[uint64][]byte),
		entityTypes: []string{},
		embedded:    true, // Default to embedded mode for mocks
	}
}

// Start simulates starting the client.
// For mock client, this is equivalent to StartWithService with nil service.
func (m *MockClient) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StartError != nil {
		return m.StartError
	}
	m.started = true
	return nil
}

// StartWithService simulates starting the client with an embedded service.
// The service parameter is ignored in the mock implementation.
func (m *MockClient) StartWithService(ctx context.Context, svc service.QuicBaaS) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StartError != nil {
		return m.StartError
	}
	m.started = true
	m.embedded = true
	return nil
}

// Stop simulates stopping the client.
func (m *MockClient) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StopError != nil {
		return m.StopError
	}
	m.started = false
	m.closed = true
	return nil
}

// IsStarted returns true if the mock client has been started.
func (m *MockClient) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// IsClosed returns true if the mock client has been closed.
func (m *MockClient) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// IsEmbedded returns true if using embedded transport mode.
// For mock client, this is configurable but defaults to true.
func (m *MockClient) IsEmbedded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.embedded
}

// SetEmbedded sets whether the mock client simulates embedded mode.
func (m *MockClient) SetEmbedded(embedded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.embedded = embedded
}

// Put stores data in the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockClient) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.PutError != nil {
		return m.PutError
	}

	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
		m.entityTypes = append(m.entityTypes, entityType)
	}
	m.data[entityType][id] = data
	return nil
}

// Get retrieves data from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockClient) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.GetError != nil {
		return nil, false, m.GetError
	}

	if entityData, ok := m.data[entityType]; ok {
		if data, found := entityData[id]; found {
			return data, true, nil
		}
	}
	return nil, false, nil
}

// Delete removes data from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockClient) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.DeleteError != nil {
		return m.DeleteError
	}

	if entityData, ok := m.data[entityType]; ok {
		delete(entityData, id)
	}
	return nil
}

// List returns paginated entities from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockClient) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ListError != nil {
		return nil, "", m.ListError
	}

	var entities []*service.Entity
	if entityData, ok := m.data[entityType]; ok {
		for id, data := range entityData {
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: data,
			})
		}
	}
	return entities, "", nil
}

// Query searches the mock storage by index field.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockClient) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.QueryError != nil {
		return nil, m.QueryError
	}

	// For testing, just return all entities of the type
	var entities []*service.Entity
	if entityData, ok := m.data[entityType]; ok {
		for id, data := range entityData {
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: data,
			})
		}
	}
	return entities, nil
}

// ListEntityTypes returns all entity types in the mock storage.
func (m *MockClient) ListEntityTypes(ctx context.Context, pageSize int, pageToken string) ([]string, string, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ListEntityTypesError != nil {
		return nil, "", 0, m.ListEntityTypesError
	}

	return m.entityTypes, "", len(m.entityTypes), nil
}

// Service returns nil for mock client (no real QuicBaaS service available).
func (m *MockClient) Service() service.QuicBaaS {
	return nil
}

// SetEntityTypes sets the entity types returned by ListEntityTypes.
func (m *MockClient) SetEntityTypes(types []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entityTypes = types
}

// SetData pre-populates data in the mock storage.
func (m *MockClient) SetData(entityType string, id uint64, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
		m.entityTypes = append(m.entityTypes, entityType)
	}
	m.data[entityType][id] = data
}

// Reset clears all data and resets state.
func (m *MockClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = make(map[string]map[uint64][]byte)
	m.entityTypes = []string{}
	m.started = false
	m.closed = false
	m.embedded = true
	m.StartError = nil
	m.StopError = nil
	m.PutError = nil
	m.GetError = nil
	m.DeleteError = nil
	m.ListError = nil
	m.QueryError = nil
	m.ListEntityTypesError = nil
}

// Verify MockClient implements ClientInterface
var _ ClientInterface = (*MockClient)(nil)

// MockFactory implements FactoryInterface for testing purposes.
// It wraps a MockClient and provides mock DAO implementations.
type MockFactory struct {
	client  *MockClient
	dataDir string
	started bool
	closed  bool
	mu      sync.RWMutex

	// Error injection
	StartError error
	StopError  error

	// Mock DAOs
	userDAO          datastore.UserDAO
	registrationDAO  datastore.RegistrationDAO
	invitationDAO    datastore.InvitationDAO
	roleDAO          datastore.RoleDAO
	webAuthnDAO      datastore.WebAuthnDAO
	deviceDAO        devicedao.DeviceDAO
	deviceProfileDAO devicedao.DeviceProfileDAO
	zoneDAO          dnsdao.ZoneDAO
}

// NewMockFactory creates a new mock QuicBaaS factory for testing.
func NewMockFactory() *MockFactory {
	return &MockFactory{
		client:  NewMockClient(),
		dataDir: "/tmp/mock-quicbaas",
	}
}

// NewMockFactoryWithClient creates a mock factory with a specific mock client.
func NewMockFactoryWithClient(client *MockClient) *MockFactory {
	return &MockFactory{
		client:  client,
		dataDir: "/tmp/mock-quicbaas",
	}
}

// Start simulates starting the factory.
func (m *MockFactory) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StartError != nil {
		return m.StartError
	}

	if err := m.client.Start(ctx); err != nil {
		return err
	}

	m.started = true
	return nil
}

// Stop simulates stopping the factory.
func (m *MockFactory) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StopError != nil {
		return m.StopError
	}

	if err := m.client.Stop(ctx); err != nil {
		return err
	}

	m.started = false
	m.closed = true
	return nil
}

// IsStarted returns true if the mock factory has been started.
func (m *MockFactory) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// IsClosed returns true if the mock factory has been closed.
func (m *MockFactory) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// QuicBaaSClient returns the mock client as ClientInterface.
func (m *MockFactory) QuicBaaSClient() ClientInterface {
	return m.client
}

// MockClient returns the underlying MockClient for test configuration.
func (m *MockFactory) MockClient() *MockClient {
	return m.client
}

// DataDir returns the mock data directory path.
func (m *MockFactory) DataDir() string {
	return m.dataDir
}

// SetDataDir sets the mock data directory path.
func (m *MockFactory) SetDataDir(dir string) {
	m.dataDir = dir
}

// UserDAO returns the mock user DAO.
func (m *MockFactory) UserDAO() (datastore.UserDAO, error) {
	return m.userDAO, nil
}

// SetUserDAO sets the mock user DAO.
func (m *MockFactory) SetUserDAO(dao datastore.UserDAO) {
	m.userDAO = dao
}

// RegistrationDAO returns the mock registration DAO.
func (m *MockFactory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	return m.registrationDAO, nil
}

// SetRegistrationDAO sets the mock registration DAO.
func (m *MockFactory) SetRegistrationDAO(dao datastore.RegistrationDAO) {
	m.registrationDAO = dao
}

// InvitationDAO returns the mock invitation DAO.
func (m *MockFactory) InvitationDAO() (datastore.InvitationDAO, error) {
	return m.invitationDAO, nil
}

// SetInvitationDAO sets the mock invitation DAO.
func (m *MockFactory) SetInvitationDAO(dao datastore.InvitationDAO) {
	m.invitationDAO = dao
}

// RoleDAO returns the mock role DAO.
func (m *MockFactory) RoleDAO() (datastore.RoleDAO, error) {
	return m.roleDAO, nil
}

// SetRoleDAO sets the mock role DAO.
func (m *MockFactory) SetRoleDAO(dao datastore.RoleDAO) {
	m.roleDAO = dao
}

// WebAuthnDAO returns the mock WebAuthn DAO.
func (m *MockFactory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	return m.webAuthnDAO, nil
}

// SetWebAuthnDAO sets the mock WebAuthn DAO.
func (m *MockFactory) SetWebAuthnDAO(dao datastore.WebAuthnDAO) {
	m.webAuthnDAO = dao
}

// DeviceDAO returns the mock device DAO.
func (m *MockFactory) DeviceDAO() (devicedao.DeviceDAO, error) {
	return m.deviceDAO, nil
}

// SetDeviceDAO sets the mock device DAO.
func (m *MockFactory) SetDeviceDAO(dao devicedao.DeviceDAO) {
	m.deviceDAO = dao
}

// DeviceProfileDAO returns the mock device profile DAO.
func (m *MockFactory) DeviceProfileDAO() (devicedao.DeviceProfileDAO, error) {
	return m.deviceProfileDAO, nil
}

// SetDeviceProfileDAO sets the mock device profile DAO.
func (m *MockFactory) SetDeviceProfileDAO(dao devicedao.DeviceProfileDAO) {
	m.deviceProfileDAO = dao
}

// ZoneDAO returns the mock zone DAO.
func (m *MockFactory) ZoneDAO() (dnsdao.ZoneDAO, error) {
	return m.zoneDAO, nil
}

// SetZoneDAO sets the mock zone DAO.
func (m *MockFactory) SetZoneDAO(dao dnsdao.ZoneDAO) {
	m.zoneDAO = dao
}

// SerializerType returns JSON serializer type.
func (m *MockFactory) SerializerType() serializer.SerializerType {
	return serializer.SERIALIZER_JSON
}

// Verify MockFactory implements FactoryInterface
var _ FactoryInterface = (*MockFactory)(nil)
