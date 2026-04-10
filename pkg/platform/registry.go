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

// Package platform provides the unified service registry for go-trusted-platform.
//
// The registry provides access to all platform services through a unified interface:
//   - Native services (TPM, vTPM, Attestation, Device, SDN, DNS, etc.) - ALWAYS embedded
//   - SDK-wrapped services (QuicBaaS, CA, XKMS) - configurable embedded or remote
//
// This package serves as the central access point for all platform functionality,
// abstracting the underlying service implementations and providing a consistent API.
package platform

import (
	"context"
	"sync"
	"sync/atomic"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/internal/ca"
	"github.com/jeremyhahn/go-trusted-platform/internal/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Registry provides unified access to all platform services.
// It manages the lifecycle of SDK adapters and provides access to both
// native platform services and SDK-wrapped external services.
//
// Services are categorized as:
//   - Native: Always embedded in go-trusted-platform (TPM, vTPM, DNS, SDN, etc.)
//   - SDK-Wrapped: Access external SDKs through adapters (QuicBaaS, CA, XKMS)
type Registry struct {
	logger *logging.Logger
	config *RegistryConfig

	// SDK Adapters (SDK-wrapped services)
	quicbaasAdapter *quicbaas.Adapter
	caAdapter       *ca.Adapter
	xkmsAdapter     *xkms.Adapter

	// Native Services (always embedded)
	deviceService *device.Service
	dnsService    *dns.Service
	// Additional native services can be added here:
	// tpmService, vtpmService, attestationService, sdnService, etc.

	// State management
	started atomic.Bool
	closed  atomic.Bool
	mu      sync.RWMutex
}

// RegistryConfig holds configuration for creating a Registry.
type RegistryConfig struct {
	// Logger for the registry
	Logger *logging.Logger

	// SDK Adapter Configurations (nil = not configured)
	QuicBaaSConfig *quicbaas.Config
	CAConfig       *ca.Config
	XKMSConfig     *xkms.Config

	// Native Service References (passed in from app initialization)
	DeviceService *device.Service
	DNSService    *dns.Service
}

// NewRegistry creates a new platform service registry.
// The registry is not started until Start() is called.
func NewRegistry(config *RegistryConfig) (*Registry, error) {
	if config == nil {
		return nil, ErrNilConfig
	}
	if config.Logger == nil {
		return nil, ErrNilLogger
	}

	registry := &Registry{
		logger:        config.Logger,
		config:        config,
		deviceService: config.DeviceService,
		dnsService:    config.DNSService,
	}

	// Create SDK adapters if configured
	if config.QuicBaaSConfig != nil {
		adapter, err := quicbaas.NewAdapter(config.QuicBaaSConfig, config.Logger)
		if err != nil {
			return nil, ErrAdapterCreationFailed{Adapter: "QuicBaaS", Cause: err}
		}
		registry.quicbaasAdapter = adapter
	}

	if config.CAConfig != nil {
		adapter, err := ca.NewAdapter(config.CAConfig, config.Logger)
		if err != nil {
			return nil, ErrAdapterCreationFailed{Adapter: "CA", Cause: err}
		}
		registry.caAdapter = adapter
	}

	if config.XKMSConfig != nil {
		adapter, err := xkms.NewAdapter(config.XKMSConfig, config.Logger)
		if err != nil {
			return nil, ErrAdapterCreationFailed{Adapter: "XKMS", Cause: err}
		}
		registry.xkmsAdapter = adapter
	}

	return registry, nil
}

// StartParams holds optional embedded services for starting the registry.
// For embedded mode, provide the relevant service implementations.
// For remote modes, these can be nil.
type StartParams struct {
	// QuicBaaSService is the embedded QuicBaaS service (for embedded transport mode)
	QuicBaaSService baasservice.QuicBaaS

	// CAService is the embedded CA service (for embedded transport mode)
	CAService ca.CertificateAuthority

	// XKMSService is the embedded XKMS service (for embedded transport mode)
	XKMSService xkms.XKMSServicer
}

// Start initializes all configured SDK adapters.
// This must be called before accessing SDK services.
// For embedded services, provide the appropriate services in params.
// params can be nil if all adapters are in remote mode.
func (r *Registry) Start(ctx context.Context, params *StartParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return ErrRegistryClosed{}
	}
	if r.started.Load() {
		return nil // Already started
	}

	// Handle nil params
	if params == nil {
		params = &StartParams{}
	}

	// Start QuicBaaS adapter
	if r.quicbaasAdapter != nil {
		if err := r.quicbaasAdapter.Start(ctx, params.QuicBaaSService); err != nil {
			return ErrAdapterStartFailed{Adapter: "QuicBaaS", Cause: err}
		}
	}

	// Start CA adapter
	if r.caAdapter != nil {
		if err := r.caAdapter.Start(ctx, params.CAService); err != nil {
			// Cleanup QuicBaaS on failure
			if r.quicbaasAdapter != nil {
				_ = r.quicbaasAdapter.Stop(ctx)
			}
			return ErrAdapterStartFailed{Adapter: "CA", Cause: err}
		}
	}

	// Start XKMS adapter
	if r.xkmsAdapter != nil {
		if err := r.xkmsAdapter.Start(ctx, params.XKMSService); err != nil {
			// Cleanup on failure
			if r.caAdapter != nil {
				_ = r.caAdapter.Stop(ctx)
			}
			if r.quicbaasAdapter != nil {
				_ = r.quicbaasAdapter.Stop(ctx)
			}
			return ErrAdapterStartFailed{Adapter: "XKMS", Cause: err}
		}
	}

	r.started.Store(true)
	r.logger.Info("Platform registry started")
	return nil
}

// Stop gracefully shuts down all SDK adapters.
func (r *Registry) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return nil
	}
	r.closed.Store(true)

	var firstErr error

	// Stop in reverse order of start
	if r.xkmsAdapter != nil {
		if err := r.xkmsAdapter.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
			r.logger.Warn("XKMS adapter stop error", "error", err)
		}
	}

	if r.caAdapter != nil {
		if err := r.caAdapter.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
			r.logger.Warn("CA adapter stop error", "error", err)
		}
	}

	if r.quicbaasAdapter != nil {
		if err := r.quicbaasAdapter.Stop(ctx); err != nil && firstErr == nil {
			firstErr = err
			r.logger.Warn("QuicBaaS adapter stop error", "error", err)
		}
	}

	r.started.Store(false)
	r.logger.Info("Platform registry stopped")
	return firstErr
}

// IsStarted returns true if the registry has been started.
func (r *Registry) IsStarted() bool {
	return r.started.Load()
}

// IsClosed returns true if the registry has been closed.
func (r *Registry) IsClosed() bool {
	return r.closed.Load()
}

// ============================================================================
// SDK-Wrapped Service Accessors
// ============================================================================

// QuicBaaS returns the QuicBaaS adapter for accessing all 28 QuicBaaS SDK services.
// Returns nil if QuicBaaS was not configured.
func (r *Registry) QuicBaaS() *quicbaas.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.quicbaasAdapter
}

// CA returns the CA adapter for certificate authority operations.
// Returns nil if CA was not configured.
func (r *Registry) CA() *ca.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.caAdapter
}

// XKMS returns the XKMS adapter for key management operations.
// Returns nil if XKMS was not configured.
func (r *Registry) XKMS() *xkms.Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.xkmsAdapter
}

// ============================================================================
// Convenience Accessors for QuicBaaS Services
// ============================================================================

// KV returns the QuicBaaS KV service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) KV() quicbaassdk.KVClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.KV()
	}
	return nil
}

// KMS returns the QuicBaaS KMS service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) KMS() quicbaassdk.KMSClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.KMS()
	}
	return nil
}

// Secrets returns the QuicBaaS Secrets service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) Secrets() quicbaassdk.SecretsClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.Secrets()
	}
	return nil
}

// IAM returns the QuicBaaS IAM service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) IAM() quicbaassdk.IAMClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.IAM()
	}
	return nil
}

// Crypto returns the QuicBaaS Crypto service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) Crypto() quicbaassdk.CryptoClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.Crypto()
	}
	return nil
}

// Vector returns the QuicBaaS Vector service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) Vector() quicbaassdk.VectorClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.Vector()
	}
	return nil
}

// TimeSeries returns the QuicBaaS TimeSeries service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) TimeSeries() quicbaassdk.TimeSeriesClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.TimeSeries()
	}
	return nil
}

// Scheduler returns the QuicBaaS Scheduler service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) Scheduler() quicbaassdk.SchedulerClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.Scheduler()
	}
	return nil
}

// Messaging returns the QuicBaaS Messaging service client.
// Returns nil if QuicBaaS is not configured or not started.
func (r *Registry) Messaging() quicbaassdk.MessagingClient {
	if adapter := r.QuicBaaS(); adapter != nil {
		return adapter.Messaging()
	}
	return nil
}

// ============================================================================
// Native Service Accessors
// ============================================================================

// DeviceService returns the device management service.
// This is a native platform service (always embedded).
func (r *Registry) DeviceService() *device.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.deviceService
}

// DNSService returns the DNS service.
// This is a native platform service (always embedded).
func (r *Registry) DNSService() *dns.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dnsService
}

// SetDeviceService sets the device service reference.
// This is useful when the device service is initialized after the registry.
func (r *Registry) SetDeviceService(svc *device.Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deviceService = svc
}

// SetDNSService sets the DNS service reference.
// This is useful when the DNS service is initialized after the registry.
func (r *Registry) SetDNSService(svc *dns.Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dnsService = svc
}
