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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	dnsdao "github.com/jeremyhahn/go-trusted-platform/pkg/dns/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Factory implements datastore.Factory backed by QuicBaaS.
// It manages the lifecycle of the QuicBaaS client and provides
// access to specialized DAOs for each entity type.
//
// The Factory supports two modes of operation:
// 1. Embedded mode (default): Manages an embedded QuicBaaS server
// 2. Remote mode: Connects to an external QuicBaaS server via SDK
//
// All modes use the SDK-based Storage interface for DAO operations,
// providing a unified abstraction over embedded and remote transports.
type Factory struct {
	// Embedded server manager (embedded mode only)
	embeddedServer *EmbeddedServer

	// SDK-based client for all modes
	client *Client

	// SDK client wrapper for advanced operations
	sdkClient *SDKClient

	// Storage interface for DAO operations (SDK-based for all modes)
	storage Storage

	logger *logging.Logger
	config *Config

	// Lazy-initialized DAOs
	organizationDAO  *OrganizationDAO
	userDAO          *UserDAO
	registrationDAO  *RegistrationDAO
	invitationDAO    *InvitationDAO
	roleDAO          *RoleDAO
	webAuthnDAO      *WebAuthnDAO
	deviceDAO        *DeviceDAO
	deviceProfileDAO *DeviceProfileDAO
	zoneDAO          *ZoneDAO

	mu     sync.RWMutex
	closed bool
}

// NewFactory creates a new QuicBaaS-backed datastore factory.
// The factory manages the QuicBaaS client lifecycle.
//
// For embedded mode (default), this creates and manages an embedded QuicBaaS server.
// For remote modes, this creates an SDK client connected to an external server.
//
// The optional ca parameter injects an external Certificate Authority into the
// embedded QuicBaaS server. When provided, QuicBaaS skips its internal CA
// bootstrap and uses the given CA for TLS certificate operations. The CA must
// have already been initialized (Load or Init called) before being passed here.
// Pass nil when no external CA is needed or in remote transport modes.
func NewFactory(config *Config, logger *logging.Logger, ca xkmssdk.XKMSCA) (*Factory, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	factory := &Factory{
		config: config,
		logger: logger,
	}

	// Create client for all modes
	client, err := NewClient(config, logger)
	if err != nil {
		return nil, err
	}
	factory.client = client

	// For embedded mode, create the embedded server manager
	if config.IsEmbedded() {
		if ca != nil {
			embeddedServer, err := NewEmbeddedServerWithCA(config, logger, ca)
			if err != nil {
				return nil, err
			}
			factory.embeddedServer = embeddedServer
		} else {
			embeddedServer, err := NewEmbeddedServer(config, logger)
			if err != nil {
				return nil, err
			}
			factory.embeddedServer = embeddedServer
		}
	}

	return factory, nil
}

// Start initializes the QuicBaaS client and makes the factory ready for use.
// This must be called before any DAO methods.
//
// For embedded mode, this starts the embedded QuicBaaS server and creates
// an SDK client wrapping the embedded service.
// For remote modes, this creates the SDK client connection.
//
// All modes use SDK-based storage for DAO operations, providing a unified
// abstraction that supports all transports (embedded, Unix, gRPC, REST, QUIC).
func (f *Factory) Start(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return ErrFactoryClosed{}
	}

	// For embedded mode, start the embedded server first
	if f.config.IsEmbedded() {
		if err := f.embeddedServer.Start(ctx); err != nil {
			return err
		}

		// Start client with embedded service
		if err := f.client.StartWithService(ctx, f.embeddedServer.Service()); err != nil {
			// Stop the embedded server on client start failure
			stopCtx := context.Background()
			f.embeddedServer.Stop(stopCtx)
			return err
		}

		// Create SDK client wrapper for additional functionality
		sdkClient, err := NewSDKClient(f.config, f.embeddedServer.Service())
		if err != nil {
			// Clean up on failure
			stopCtx := context.Background()
			f.client.Stop(stopCtx)
			f.embeddedServer.Stop(stopCtx)
			return err
		}
		f.sdkClient = sdkClient
	} else {
		// For remote modes, start client directly
		if err := f.client.Start(ctx); err != nil {
			return err
		}

		// Create SDK client wrapper for remote transport
		sdkClient, err := NewSDKClient(f.config, nil)
		if err != nil {
			// Clean up on failure
			stopCtx := context.Background()
			f.client.Stop(stopCtx)
			return err
		}
		f.sdkClient = sdkClient
	}

	// Create SDK-based storage for DAO operations (all modes use SDK)
	sdkStorage, err := NewSDKStorage(f.sdkClient.Client())
	if err != nil {
		// Clean up on storage creation failure
		if f.sdkClient != nil {
			f.sdkClient.Close()
		}
		stopCtx := context.Background()
		f.client.Stop(stopCtx)
		if f.config.IsEmbedded() && f.embeddedServer != nil {
			f.embeddedServer.Stop(stopCtx)
		}
		return err
	}

	// Start the SDK storage
	if err := sdkStorage.Start(ctx); err != nil {
		if f.sdkClient != nil {
			f.sdkClient.Close()
		}
		stopCtx := context.Background()
		f.client.Stop(stopCtx)
		if f.config.IsEmbedded() && f.embeddedServer != nil {
			f.embeddedServer.Stop(stopCtx)
		}
		return err
	}

	f.storage = sdkStorage
	return nil
}

// Stop gracefully shuts down the QuicBaaS client.
func (f *Factory) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}

	f.closed = true

	// Stop SDK storage first
	if f.storage != nil {
		if err := f.storage.Stop(ctx); err != nil {
			f.logger.Warn("SDK storage stop error", "error", err)
		}
	}

	// Close SDK client wrapper
	if f.sdkClient != nil {
		if err := f.sdkClient.Close(); err != nil {
			f.logger.Warn("SDK client close error", "error", err)
		}
	}

	// Stop the client
	if f.client != nil {
		if err := f.client.Stop(ctx); err != nil {
			f.logger.Warn("Client stop error", "error", err)
		}
	}

	// For embedded mode, stop the embedded server
	if f.config.IsEmbedded() && f.embeddedServer != nil {
		return f.embeddedServer.Stop(ctx)
	}

	return nil
}

// OrganizationDAO returns the organization DAO, creating it lazily if needed.
func (f *Factory) OrganizationDAO() (datastore.OrganizationDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
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

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
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

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
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

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
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

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
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

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
	}

	if f.webAuthnDAO == nil {
		f.webAuthnDAO = NewWebAuthnDAO(f.storage, f.logger)
	}
	return f.webAuthnDAO, nil
}

// DeviceDAO returns the device DAO, creating it lazily if needed.
func (f *Factory) DeviceDAO() (devicedao.DeviceDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
	}

	if f.deviceDAO == nil {
		f.deviceDAO = NewDeviceDAO(f.storage, f.logger)
	}
	return f.deviceDAO, nil
}

// DeviceProfileDAO returns the device profile DAO, creating it lazily if needed.
func (f *Factory) DeviceProfileDAO() (devicedao.DeviceProfileDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
	}

	if f.deviceProfileDAO == nil {
		f.deviceProfileDAO = NewDeviceProfileDAO(f.storage, f.logger)
	}
	return f.deviceProfileDAO, nil
}

// ZoneDAO returns the zone DAO, creating it lazily if needed.
func (f *Factory) ZoneDAO() (dnsdao.ZoneDAO, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil, ErrFactoryClosed{}
	}

	if f.storage == nil {
		return nil, ErrStorageNotStarted{}
	}

	if f.zoneDAO == nil {
		f.zoneDAO = NewZoneDAO(f.storage, f.logger)
	}
	return f.zoneDAO, nil
}

// SerializerType returns the serializer type used by this factory.
// QuicBaaS stores data as JSON internally.
func (f *Factory) SerializerType() serializer.SerializerType {
	return serializer.SERIALIZER_JSON
}

// Client returns the underlying QuicBaaS client.
// This is useful for advanced operations or testing.
func (f *Factory) Client() *Client {
	return f.client
}

// QuicBaaSClient returns the QuicBaaS client as an interface.
// This method satisfies FactoryInterface and enables mocking in tests.
func (f *Factory) QuicBaaSClient() ClientInterface {
	return f.client
}

// SDK returns the underlying go-quicbaas SDK client.
// This provides access to all 28 QuicBaaS services via the unified SDK interface.
// Returns nil if the factory has not been started.
func (f *Factory) SDK() quicbaas.Client {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.sdkClient == nil {
		return nil
	}
	return f.sdkClient.Client()
}

// SDKClient returns the SDKClient wrapper.
// This provides access to the SDK client with additional helper methods.
func (f *Factory) SDKClient() *SDKClient {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.sdkClient
}

// EmbeddedServer returns the embedded server manager.
// Returns nil for remote transport modes.
func (f *Factory) EmbeddedServer() *EmbeddedServer {
	return f.embeddedServer
}

// Transport returns the transport type being used.
func (f *Factory) Transport() Transport {
	return f.config.Transport
}

// IsEmbedded returns true if the factory is using embedded mode.
func (f *Factory) IsEmbedded() bool {
	return f.config.IsEmbedded()
}

// DataDir returns the database directory path from the client configuration.
func (f *Factory) DataDir() string {
	return f.config.DataDir
}

// IsStarted returns true if the factory has been started.
func (f *Factory) IsStarted() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	// Check if storage is ready (all modes use SDK-based storage)
	return f.storage != nil && f.storage.IsStarted()
}

// Storage returns the SDK-based storage interface used by DAOs.
// This provides unified access to QuicBaaS via the SDK for all transport modes.
func (f *Factory) Storage() Storage {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.storage
}

// IsClosed returns true if the factory has been closed.
func (f *Factory) IsClosed() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.closed
}

// Config returns the configuration used to create this factory.
func (f *Factory) Config() *Config {
	return f.config
}
