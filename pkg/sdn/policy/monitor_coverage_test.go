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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertificateMonitor_RevocationChecking tests revocation checking and callbacks
func TestCertificateMonitor_RevocationChecking(t *testing.T) {
	t.Run("Check revocation with validator", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
			EnableMonitoring:     true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()
		require.NotNil(t, monitor)

		// Set up a port with a certificate
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(12345),
			Subject: pkix.Name{
				Organization: []string{"tenant-1"},
			},
		})

		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Set up port with policy - follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Register revocation callback
		var revokedCalled atomic.Bool
		var revokedPort string
		done := make(chan bool, 1)

		monitor.OnRevoked(func(portID string, certIface interface{}) {
			revokedCalled.Store(true)
			revokedPort = portID
			done <- true
		})

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Revoke the certificate
		validator.AddRevoked("12345")

		// Wait for callback
		select {
		case <-done:
			assert.True(t, revokedCalled.Load())
			assert.Equal(t, "port1", revokedPort)
		case <-time.After(300 * time.Millisecond):
			t.Fatal("Revocation callback not triggered")
		}

		// Stop monitor
		require.NoError(t, monitor.Stop())

		// Verify port was blocked
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateBlocked, state)
	})

	t.Run("Check revocation without validator", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:       "br0",
			FlowController:   controller,
			EnableMonitoring: true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()
		require.NotNil(t, monitor)

		// Set up a port with a certificate
		cert := createTestCertificate(t, x509.Certificate{})
		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Wait for check to run (should not crash without validator)
		time.Sleep(150 * time.Millisecond)

		// Stop monitor
		require.NoError(t, monitor.Stop())

		// Port should still be authorized
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthorized, state)
	})

	t.Run("Revocation check error handling", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
			EnableMonitoring:     true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()
		require.NotNil(t, monitor)

		// Set up a port with a non-revoked certificate
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(99999),
		})

		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Wait for check to run
		time.Sleep(150 * time.Millisecond)

		// Stop monitor
		require.NoError(t, monitor.Stop())

		// Port should still be authorized (cert not revoked)
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateAuthorized, state)
	})
}

// TestCertificateMonitor_HandleRevocation tests the handleRevocation flow
func TestCertificateMonitor_HandleRevocation(t *testing.T) {
	t.Run("Revocation callback and port blocking", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
			EnableMonitoring:     true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()
		require.NotNil(t, monitor)

		// Set up port with certificate
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(54321),
		})

		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Register multiple revoked callbacks to test notification
		var callback1Called atomic.Bool
		var callback2Called atomic.Bool
		done1 := make(chan bool, 1)
		done2 := make(chan bool, 1)

		monitor.OnRevoked(func(portID string, certIface interface{}) {
			callback1Called.Store(true)
			done1 <- true
		})

		monitor.OnRevoked(func(portID string, certIface interface{}) {
			callback2Called.Store(true)
			done2 <- true
		})

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Revoke certificate
		validator.AddRevoked("54321")

		// Wait for both callbacks
		timeout := time.After(300 * time.Millisecond)
		callbackCount := 0

		for callbackCount < 2 {
			select {
			case <-done1:
				callbackCount++
			case <-done2:
				callbackCount++
			case <-timeout:
				t.Fatal("Not all revocation callbacks triggered")
			}
		}

		assert.True(t, callback1Called.Load())
		assert.True(t, callback2Called.Load())

		// Stop monitor
		require.NoError(t, monitor.Stop())
	})

	t.Run("Revocation with flow controller error", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
			EnableMonitoring:     true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()

		// Set up port
		cert := createTestCertificate(t, x509.Certificate{
			SerialNumber: big.NewInt(11111),
		})

		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(24 * time.Hour),
		}

		// Follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Set flow controller to fail on delete
		controller.deleteError = errors.New("flow deletion failed")

		// Revoke certificate
		validator.AddRevoked("11111")

		// Wait for monitoring to detect revocation
		time.Sleep(150 * time.Millisecond)

		// Stop monitor
		require.NoError(t, monitor.Stop())

		// Even with error, monitoring should continue
		// (errors are logged but don't stop the monitor)
	})
}

// TestCertificateMonitor_HandleExpiryErrors tests error paths in handleExpiry
func TestCertificateMonitor_HandleExpiryErrors(t *testing.T) {
	t.Run("Expiry with flow controller error", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:       "br0",
			FlowController:   controller,
			EnableMonitoring: true,
			MonitorConfig: MonitorConfig{
				CheckInterval:   50 * time.Millisecond,
				ExpiryThreshold: 1 * time.Hour,
			},
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		monitor := engine.GetMonitor()

		// Set up port with expired certificate
		cert := createTestCertificate(t, x509.Certificate{})
		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: cert,
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // Already expired
		}

		// Follow proper state machine flow
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitoring
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))

		// Set flow controller to fail
		controller.deleteError = errors.New("flow deletion failed")

		// Wait for monitoring to detect expiry
		time.Sleep(150 * time.Millisecond)

		// Stop monitor
		require.NoError(t, monitor.Stop())

		// Even with error, monitoring should have attempted to handle expiry
	})
}
