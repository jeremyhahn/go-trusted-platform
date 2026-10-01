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
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngine_FlowInstallationErrors tests error paths during flow installation
func TestEngine_FlowInstallationErrors(t *testing.T) {
	t.Run("Flow installation fails during ApplyPolicy", func(t *testing.T) {
		controller := newMockFlowController()
		controller.installError = errors.New("flow installation failed")

		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		err = engine.ApplyPolicy("port1", policy)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)

		// Verify rollback: port should be in unauthorized state
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)

		// Policy should not be stored
		_, err = engine.GetPolicy("port1")
		assert.ErrorIs(t, err, ErrPolicyNotFound)
	})

	t.Run("Flow installation fails during SetPortState unauthorized", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Transition to provisioning first
		require.NoError(t, engine.SetPortState("port1", PortStateProvisioning))

		// Set error after engine creation
		controller.installError = errors.New("flow installation failed")

		err = engine.SetPortState("port1", PortStateUnauthorized)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})

	t.Run("Flow installation fails during SetPortState blocked", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Set error after engine creation
		controller.installError = errors.New("flow installation failed")

		err = engine.SetPortState("port1", PortStateBlocked)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})

	t.Run("Flow deletion fails during RemovePolicy", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// First apply a policy successfully
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		require.NoError(t, engine.ApplyPolicy("port1", policy))

		// Now set delete error
		controller.deleteError = errors.New("flow deletion failed")

		err = engine.RemovePolicy("port1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowDeleteFailed)
	})

	t.Run("Flow deletion fails during OnCertificateExpired", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Set up a port with policy
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		require.NoError(t, engine.ApplyPolicy("port1", policy))

		// Set delete error
		controller.deleteError = errors.New("flow deletion failed")

		err = engine.OnCertificateExpired("port1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowDeleteFailed)
	})
}

// TestEngine_AuthenticatePortErrorPaths tests error handling in AuthenticatePort
func TestEngine_AuthenticatePortErrorPaths(t *testing.T) {
	t.Run("Certificate validation fails", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Create an expired certificate — validation fails before extraction
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-1"},
			},
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})

		err = engine.AuthenticatePort("port1", cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate validation failed")

		// Port should be in unauthorized state
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})

	t.Run("Policy extraction fails", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Create cert with no Organization and no CommonName → ErrMissingTenantID
		cert := createTestCertificate(t, x509.Certificate{})

		err = engine.AuthenticatePort("port1", cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy extraction failed")

		// Port should be in unauthorized state
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})

	t.Run("Policy application fails after extraction", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}
		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Cert with tenant but without zone extension and without VLAN.
		// ExtractPolicy succeeds (tenant extracted), validatePolicy fails
		// (Zone="" and VLAN=0) → "policy application failed: invalid VLAN ID".
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-1"},
			},
		})

		err = engine.AuthenticatePort("port1", cert)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "policy application failed")

		// Port should be in unauthorized state
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})
}

// TestEngine_ApplyPolicyRollback tests rollback scenarios in ApplyPolicy
func TestEngine_ApplyPolicyRollback(t *testing.T) {
	t.Run("Rollback on flow installation failure", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}

		// Apply policy successfully first time
		require.NoError(t, engine.ApplyPolicy("port1", policy))

		// Now cause a failure by using flow errors
		controller.installError = errors.New("flow installation failed")

		err = engine.ApplyPolicy("port2", policy)
		assert.Error(t, err)

		// Verify port2 rolled back to unauthorized
		state, err := engine.GetPortState("port2")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})
}

// TestEngine_OnCertificateExpiredFlowErrors tests error paths in OnCertificateExpired
func TestEngine_OnCertificateExpiredFlowErrors(t *testing.T) {
	t.Run("Block flow installation fails after deletion succeeds", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Set up a port with policy
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		require.NoError(t, engine.ApplyPolicy("port1", policy))

		// Set install error (which will affect block flow installation)
		controller.installError = errors.New("flow installation failed")

		err = engine.OnCertificateExpired("port1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrFlowInstallFailed)
	})
}

// TestEngine_RemovePolicyErrors tests error paths in RemovePolicy
func TestEngine_RemovePolicyErrors(t *testing.T) {
	t.Run("Remove policy successfully", func(t *testing.T) {
		controller := newMockFlowController()
		config := Config{
			BridgeName:     "br0",
			FlowController: controller,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Apply policy first
		policy := &PortPolicy{
			TenantID: "tenant-1",
			VLAN:     100,
		}
		require.NoError(t, engine.ApplyPolicy("port1", policy))

		// Remove policy should succeed
		err = engine.RemovePolicy("port1")
		assert.NoError(t, err)

		// Verify state is unauthorized
		state, err := engine.GetPortState("port1")
		assert.NoError(t, err)
		assert.Equal(t, PortStateUnauthorized, state)
	})
}

// TestEngine_AuthenticatePortStateRecording tests error recording in state machine
func TestEngine_AuthenticatePortStateRecording(t *testing.T) {
	t.Run("Error recorded in state machine on validation failure", func(t *testing.T) {
		controller := newMockFlowController()
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()
		validator := NewDefaultCertificateValidator(roots, intermediates)

		config := Config{
			BridgeName:           "br0",
			FlowController:       controller,
			CertificateValidator: validator,
		}

		engine, err := NewEngine(config)
		require.NoError(t, err)

		// Create an expired certificate — validation fails before extraction
		cert := createTestCertificate(t, x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"tenant-1"},
			},
			NotBefore: time.Now().Add(-48 * time.Hour),
			NotAfter:  time.Now().Add(-24 * time.Hour),
		})

		err = engine.AuthenticatePort("port1", cert)
		assert.Error(t, err)

		// Verify error was recorded in state machine
		info, err := engine.GetPortInfo("port1")
		require.NoError(t, err)
		assert.NotNil(t, info.LastError)
	})

	t.Run("Auth attempts incremented", func(t *testing.T) {
		// Create valid cert with zone extension for Z3-compatible authentication
		cert := createZoneCert(t, "tenant-1", "control-plane")

		// Authenticate successfully using zone-aware engine
		engineWithZones := createTestEngineWithZones(t)
		require.NoError(t, engineWithZones.AuthenticatePort("port1", cert))

		// Check auth attempts
		info, err := engineWithZones.GetPortInfo("port1")
		require.NoError(t, err)
		assert.Equal(t, 1, info.AuthAttempts)
	})
}
