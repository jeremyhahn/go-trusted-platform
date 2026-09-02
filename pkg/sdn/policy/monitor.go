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

package policy

import (
	"context"
	"sync"
	"time"
)

// CertificateMonitor monitors certificate lifecycle events
type CertificateMonitor struct {
	mu               sync.RWMutex
	running          bool
	cancelFunc       context.CancelFunc
	engine           *Engine
	checkInterval    time.Duration
	expiryThreshold  time.Duration
	expiryCallbacks  []ExpiryCallback
	revokedCallbacks []RevokedCallback
	wg               sync.WaitGroup
}

// ExpiryCallback is called when a certificate expires or is about to expire
type ExpiryCallback func(portID string, cert interface{}, timeUntilExpiry time.Duration)

// RevokedCallback is called when a certificate is revoked
type RevokedCallback func(portID string, cert interface{})

// MonitorConfig configures the certificate monitor
type MonitorConfig struct {
	// CheckInterval is how often to check certificate status
	CheckInterval time.Duration

	// ExpiryThreshold triggers callbacks when certificates expire within this duration
	ExpiryThreshold time.Duration
}

// NewCertificateMonitor creates a new certificate monitor
func NewCertificateMonitor(engine *Engine, config MonitorConfig) *CertificateMonitor {
	if config.CheckInterval == 0 {
		config.CheckInterval = 5 * time.Minute
	}
	if config.ExpiryThreshold == 0 {
		config.ExpiryThreshold = 24 * time.Hour
	}

	return &CertificateMonitor{
		engine:           engine,
		checkInterval:    config.CheckInterval,
		expiryThreshold:  config.ExpiryThreshold,
		expiryCallbacks:  make([]ExpiryCallback, 0),
		revokedCallbacks: make([]RevokedCallback, 0),
	}
}

// Start begins monitoring certificate lifecycle
func (m *CertificateMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return ErrEngineAlreadyRunning
	}

	monitorCtx, cancel := context.WithCancel(ctx)
	m.cancelFunc = cancel
	m.running = true

	m.wg.Add(1)
	go m.monitorLoop(monitorCtx)

	return nil
}

// Stop stops the certificate monitor
func (m *CertificateMonitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return ErrEngineNotRunning
	}

	m.cancelFunc()
	m.running = false
	m.mu.Unlock()

	m.wg.Wait()

	return nil
}

// OnExpiry registers a callback for certificate expiry events.
//
// The monitor invokes callbacks concurrently: each one runs in its own
// goroutine, and it is re-invoked on every tick for as long as the certificate
// stays within the expiry threshold, so a callback may overlap with itself. A
// callback must be safe for concurrent use, must not write unsynchronized
// shared state, and must not block indefinitely.
func (m *CertificateMonitor) OnExpiry(callback ExpiryCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.expiryCallbacks = append(m.expiryCallbacks, callback)
}

// OnRevoked registers a callback for certificate revocation events.
//
// The monitor invokes callbacks concurrently: each one runs in its own
// goroutine, and it is re-invoked on every tick for as long as the certificate
// stays revoked, so a callback may overlap with itself. A callback must be safe
// for concurrent use, must not write unsynchronized shared state, and must not
// block indefinitely.
func (m *CertificateMonitor) OnRevoked(callback RevokedCallback) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.revokedCallbacks = append(m.revokedCallbacks, callback)
}

// monitorLoop is the main monitoring loop
func (m *CertificateMonitor) monitorLoop(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			m.checkCertificates()
		}
	}
}

// checkCertificates checks all port certificates for expiry and revocation
func (m *CertificateMonitor) checkCertificates() {
	ports := m.engine.stateMachine.ListPorts()

	for _, portID := range ports {
		info, err := m.engine.stateMachine.GetInfo(portID)
		if err != nil {
			continue
		}

		// Skip ports without policies
		if info.Policy == nil || info.Policy.Certificate == nil {
			continue
		}

		// Check for expiry
		m.checkExpiry(portID, info.Policy)

		// Check for revocation
		m.checkRevocation(portID, info.Policy)
	}
}

// checkExpiry checks if a certificate is expired or about to expire
func (m *CertificateMonitor) checkExpiry(portID string, policy *PortPolicy) {
	now := time.Now()
	timeUntilExpiry := policy.ExpiresAt.Sub(now)

	// Certificate has expired
	if timeUntilExpiry <= 0 {
		m.handleExpiry(portID, policy, timeUntilExpiry)
		return
	}

	// Certificate will expire soon
	if timeUntilExpiry <= m.expiryThreshold {
		m.notifyExpiry(portID, policy.Certificate, timeUntilExpiry)
	}
}

// checkRevocation checks if a certificate has been revoked
func (m *CertificateMonitor) checkRevocation(portID string, policy *PortPolicy) {
	if m.engine.validator == nil {
		return
	}

	revoked, err := m.engine.validator.IsRevoked(policy.Certificate)
	if err != nil {
		return
	}

	if revoked {
		m.handleRevocation(portID, policy)
	}
}

// handleExpiry handles an expired certificate
func (m *CertificateMonitor) handleExpiry(portID string, policy *PortPolicy, timeUntilExpiry time.Duration) {
	// Notify callbacks
	m.notifyExpiry(portID, policy.Certificate, timeUntilExpiry)

	// Block the port
	if err := m.engine.OnCertificateExpired(portID); err != nil {
		// Log error but continue
		return
	}
}

// handleRevocation handles a revoked certificate
func (m *CertificateMonitor) handleRevocation(portID string, policy *PortPolicy) {
	// Notify callbacks
	m.notifyRevoked(portID, policy.Certificate)

	// Block the port
	if err := m.engine.OnCertificateRevoked(portID); err != nil {
		// Log error but continue
		return
	}
}

// notifyExpiry notifies all registered expiry callbacks
func (m *CertificateMonitor) notifyExpiry(portID string, cert interface{}, timeUntilExpiry time.Duration) {
	m.mu.RLock()
	callbacks := make([]ExpiryCallback, len(m.expiryCallbacks))
	copy(callbacks, m.expiryCallbacks)
	m.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(portID, cert, timeUntilExpiry)
	}
}

// notifyRevoked notifies all registered revocation callbacks
func (m *CertificateMonitor) notifyRevoked(portID string, cert interface{}) {
	m.mu.RLock()
	callbacks := make([]RevokedCallback, len(m.revokedCallbacks))
	copy(callbacks, m.revokedCallbacks)
	m.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(portID, cert)
	}
}

// IsRunning returns whether the monitor is currently running
func (m *CertificateMonitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.running
}
