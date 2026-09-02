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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertificateMonitor(t *testing.T) {
	engine := createTestEngine(t)

	t.Run("Default config", func(t *testing.T) {
		monitor := NewCertificateMonitor(engine, MonitorConfig{})
		assert.NotNil(t, monitor)
		assert.Equal(t, 5*time.Minute, monitor.checkInterval)
		assert.Equal(t, 24*time.Hour, monitor.expiryThreshold)
	})

	t.Run("Custom config", func(t *testing.T) {
		config := MonitorConfig{
			CheckInterval:   1 * time.Minute,
			ExpiryThreshold: 12 * time.Hour,
		}
		monitor := NewCertificateMonitor(engine, config)
		assert.Equal(t, config.CheckInterval, monitor.checkInterval)
		assert.Equal(t, config.ExpiryThreshold, monitor.expiryThreshold)
	})
}

func TestCertificateMonitor_StartStop(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   100 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	t.Run("Start monitor", func(t *testing.T) {
		ctx := context.Background()
		err := monitor.Start(ctx)
		assert.NoError(t, err)
		assert.True(t, monitor.IsRunning())
	})

	t.Run("Start already running", func(t *testing.T) {
		err := monitor.Start(context.Background())
		assert.ErrorIs(t, err, ErrEngineAlreadyRunning)
	})

	t.Run("Stop monitor", func(t *testing.T) {
		err := monitor.Stop()
		assert.NoError(t, err)
		assert.False(t, monitor.IsRunning())
	})

	t.Run("Stop not running", func(t *testing.T) {
		err := monitor.Stop()
		assert.ErrorIs(t, err, ErrEngineNotRunning)
	})
}

func TestCertificateMonitor_ExpiryCallbacks(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   50 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	t.Run("Register and trigger callback", func(t *testing.T) {
		var callbackCount atomic.Int32
		done := make(chan bool, 1)

		// The monitor re-invokes the callback on every tick while the
		// certificate stays within the expiry threshold, so signal without
		// blocking: a blocking send would strand every later invocation.
		monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
			callbackCount.Add(1)
			assert.Equal(t, "port1", portID)
			assert.NotNil(t, cert)
			select {
			case done <- true:
			default:
			}
		})

		// Create a port with an expiring certificate
		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: createTestCertificate(t, x509.Certificate{}),
			ExpiresAt:   time.Now().Add(30 * time.Minute), // Within threshold
		}
		// Follow proper state machine flow: unconnected -> provisioning -> authenticating -> authorized
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitor
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))
		defer func() {
			if err := monitor.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Wait for callback
		select {
		case <-done:
			assert.Greater(t, callbackCount.Load(), int32(0))
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Callback not triggered within timeout")
		}
	})

	t.Run("Multiple callbacks", func(t *testing.T) {
		var count1, count2 atomic.Int32

		monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
			count1.Add(1)
		})

		monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
			count2.Add(1)
		})

		assert.Len(t, monitor.expiryCallbacks, 3) // 1 from previous test + 2 new
	})
}

func TestCertificateMonitor_RevokedCallbacks(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   50 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	t.Run("Register callback", func(t *testing.T) {
		var callbackCount atomic.Int32

		monitor.OnRevoked(func(portID string, cert interface{}) {
			callbackCount.Add(1)
		})

		assert.Len(t, monitor.revokedCallbacks, 1)
	})
}

func TestCertificateMonitor_CheckExpiry(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   50 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	t.Run("Expired certificate", func(t *testing.T) {
		var expiryTriggered atomic.Bool
		var revokedTriggered atomic.Bool

		monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
			expiryTriggered.Store(true)
		})

		// Create a port with expired certificate
		policy := &PortPolicy{
			TenantID:    "tenant-1",
			VLAN:        100,
			Certificate: createTestCertificate(t, x509.Certificate{}),
			ExpiresAt:   time.Now().Add(-1 * time.Hour), // Expired
		}
		// Follow proper state machine flow: unconnected -> provisioning -> authenticating -> authorized
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port1", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port1", policy))

		// Start monitor
		ctx := context.Background()
		require.NoError(t, monitor.Start(ctx))
		defer func() {
			if err := monitor.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Wait for processing
		time.Sleep(200 * time.Millisecond)

		assert.True(t, expiryTriggered.Load())
		assert.False(t, revokedTriggered.Load())

		// Verify port was blocked
		state, err := engine.GetPortState("port1")
		require.NoError(t, err)
		assert.Equal(t, PortStateBlocked, state)
	})

	t.Run("Certificate expiring soon", func(t *testing.T) {
		var callbackTriggered atomic.Bool
		done := make(chan bool, 1)

		newMonitor := NewCertificateMonitor(engine, MonitorConfig{
			CheckInterval:   50 * time.Millisecond,
			ExpiryThreshold: 1 * time.Hour,
		})

		newMonitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
			callbackTriggered.Store(true)
			select {
			case done <- true:
			default:
			}
		})

		// Create a port with certificate expiring within threshold
		policy := &PortPolicy{
			TenantID:    "tenant-2",
			VLAN:        200,
			Certificate: createTestCertificate(t, x509.Certificate{}),
			ExpiresAt:   time.Now().Add(30 * time.Minute),
		}
		// Follow proper state machine flow: unconnected -> provisioning -> authenticating -> authorized
		require.NoError(t, engine.stateMachine.SetState("port2", PortStateProvisioning))
		require.NoError(t, engine.stateMachine.SetState("port2", PortStateAuthenticating))
		require.NoError(t, engine.stateMachine.SetState("port2", PortStateAuthorized))
		require.NoError(t, engine.stateMachine.SetPolicy("port2", policy))

		ctx := context.Background()
		require.NoError(t, newMonitor.Start(ctx))
		defer func() {
			if err := newMonitor.Stop(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		select {
		case <-done:
			assert.True(t, callbackTriggered.Load())
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Expiry callback not triggered")
		}
	})
}

func TestCertificateMonitor_ContextCancellation(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   100 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	ctx, cancel := context.WithCancel(context.Background())

	require.NoError(t, monitor.Start(ctx))
	assert.True(t, monitor.IsRunning())

	// Cancel context
	cancel()
	time.Sleep(200 * time.Millisecond)

	// Monitor should still be marked as running until Stop is called
	// but the loop should have exited
	assert.True(t, monitor.IsRunning())

	// Proper shutdown
	require.NoError(t, monitor.Stop())
	assert.False(t, monitor.IsRunning())
}

func TestCertificateMonitor_NoPolicy(t *testing.T) {
	engine := createTestEngine(t)
	config := MonitorConfig{
		CheckInterval:   50 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	}
	monitor := NewCertificateMonitor(engine, config)

	var callbackTriggered atomic.Bool
	monitor.OnExpiry(func(portID string, cert interface{}, timeUntilExpiry time.Duration) {
		callbackTriggered.Store(true)
	})

	// Create port without policy
	// Follow proper state machine flow: unconnected -> provisioning -> unauthorized
	require.NoError(t, engine.stateMachine.SetState("port1", PortStateProvisioning))
	require.NoError(t, engine.stateMachine.SetState("port1", PortStateUnauthorized))

	ctx := context.Background()
	require.NoError(t, monitor.Start(ctx))
	defer func() {
		if err := monitor.Stop(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Wait for several check cycles
	time.Sleep(200 * time.Millisecond)

	// Callback should not be triggered for ports without policy
	assert.False(t, callbackTriggered.Load())
}

func TestCertificateMonitor_IsRunning(t *testing.T) {
	engine := createTestEngine(t)
	monitor := NewCertificateMonitor(engine, MonitorConfig{})

	assert.False(t, monitor.IsRunning())

	ctx := context.Background()
	require.NoError(t, monitor.Start(ctx))
	assert.True(t, monitor.IsRunning())

	require.NoError(t, monitor.Stop())
	assert.False(t, monitor.IsRunning())
}

// TestCertificateMonitor_CallbacksDispatchConcurrently pins the contract that
// OnExpiry and OnRevoked document: each callback runs in its own goroutine, so
// one that blocks cannot hold up the others or the monitor loop.
//
// This is the property that made the old revocation test wrong — it assumed
// serialised dispatch and wrote unsynchronized shared state from a callback —
// so it is worth asserting rather than leaving to the doc comment. Serialising
// dispatch to "fix" a future callback race would break this test, which is the
// intent: the answer is to make the callback safe, not to slow the monitor.
func TestCertificateMonitor_CallbacksDispatchConcurrently(t *testing.T) {
	engine := createTestEngine(t)
	monitor := NewCertificateMonitor(engine, MonitorConfig{
		CheckInterval:   50 * time.Millisecond,
		ExpiryThreshold: 1 * time.Hour,
	})

	release := make(chan struct{})
	blocked := make(chan struct{}, 1)
	progressed := make(chan struct{}, 1)

	// The first callback blocks until the test releases it.
	monitor.OnRevoked(func(portID string, cert interface{}) {
		select {
		case blocked <- struct{}{}:
		default:
		}
		<-release
	})

	// The second must still run while the first is stuck.
	monitor.OnRevoked(func(portID string, cert interface{}) {
		select {
		case progressed <- struct{}{}:
		default:
		}
	})

	// Dispatch from a goroutine: if a regression serialised it, notifyRevoked
	// would block on the stuck callback, and driving it from the test goroutine
	// would hang the package until the test binary timed out instead of
	// failing here in a couple of seconds.
	go monitor.notifyRevoked("port1", nil)

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("first callback never ran")
	}

	select {
	case <-progressed:
		// Dispatch is concurrent: the blocked callback did not gate this one.
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("second callback was gated by the blocked one; dispatch is no longer concurrent")
	}

	close(release)
}
