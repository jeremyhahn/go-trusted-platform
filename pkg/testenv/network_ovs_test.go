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

//go:build linux

// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultOVSNetworkOptions(t *testing.T) {
	opts := DefaultOVSNetworkOptions()
	require.NotNil(t, opts)

	assert.Equal(t, DefaultOVSSocketPath, opts.SocketPath)
	assert.Equal(t, uint16(0), opts.ServerVLAN)
	assert.Equal(t, uint16(0), opts.ClientVLAN)
	assert.False(t, opts.EnableFlowControl)
	assert.Equal(t, uint16(100), opts.ProvisioningVLAN)
	assert.Equal(t, uint16(200), opts.TrustedVLAN)
	assert.Equal(t, uint16(300), opts.QuarantineVLAN)
}

func TestNewOVSIsolatedNetwork_NilConfig(t *testing.T) {
	// Test with nil config - should use defaults
	// If OVS is available, this will succeed; otherwise it should error
	net, err := NewOVSIsolatedNetwork(nil, nil)
	if IsOVSAvailable() {
		// OVS is running, so connection should succeed
		assert.NoError(t, err)
		assert.NotNil(t, net)
	} else {
		// OVS is not running, so should error
		assert.Error(t, err)
		// Verify the error message is appropriate
		assert.Contains(t, err.Error(), "OVS socket not found")
	}
}

func TestNewOVSIsolatedNetwork_InvalidSocketPath(t *testing.T) {
	cfg := DefaultNetworkConfig()
	opts := &OVSNetworkOptions{
		SocketPath: "/nonexistent/socket.sock",
	}

	_, err := NewOVSIsolatedNetwork(cfg, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OVS socket not found")
}

func TestIsOVSAvailable(t *testing.T) {
	// Just test that the function runs without panic
	// Result depends on whether OVS is installed
	available := IsOVSAvailable()
	t.Logf("OVS available: %v", available)

	// Test when socket doesn't exist
	if _, err := os.Stat(DefaultOVSSocketPath); err != nil {
		assert.False(t, available)
	}
}

func TestOVSIsolatedNetworkInterface(t *testing.T) {
	// Verify OVSIsolatedNetwork implements IsolatedNetwork interface
	var _ IsolatedNetwork = (*OVSIsolatedNetwork)(nil)
}

func TestMaskSize(t *testing.T) {
	tests := []struct {
		name     string
		cidr     string
		expected int
	}{
		{"28-bit mask", "10.0.0.0/28", 28},
		{"24-bit mask", "10.0.0.0/24", 24},
		{"16-bit mask", "10.0.0.0/16", 16},
		{"8-bit mask", "10.0.0.0/8", 8},
		{"32-bit mask", "10.0.0.0/32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, subnet, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)
			result := maskSize(subnet.Mask)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultOVSSocketPath(t *testing.T) {
	assert.Equal(t, "/var/run/openvswitch/db.sock", DefaultOVSSocketPath)
}

func TestOVSNetworkOptions_CustomValues(t *testing.T) {
	opts := &OVSNetworkOptions{
		SocketPath:        "/custom/path/db.sock",
		ServerVLAN:        100,
		ClientVLAN:        200,
		EnableFlowControl: true,
		ProvisioningVLAN:  10,
		TrustedVLAN:       20,
		QuarantineVLAN:    30,
	}

	assert.Equal(t, "/custom/path/db.sock", opts.SocketPath)
	assert.Equal(t, uint16(100), opts.ServerVLAN)
	assert.Equal(t, uint16(200), opts.ClientVLAN)
	assert.True(t, opts.EnableFlowControl)
	assert.Equal(t, uint16(10), opts.ProvisioningVLAN)
	assert.Equal(t, uint16(20), opts.TrustedVLAN)
	assert.Equal(t, uint16(30), opts.QuarantineVLAN)
}

func TestNewOVSIsolatedNetwork_NilOptions(t *testing.T) {
	cfg := DefaultNetworkConfig()

	// Create OVS network with nil options
	// Should use default options
	net, err := NewOVSIsolatedNetwork(cfg, nil)
	if IsOVSAvailable() {
		// OVS is running, so connection should succeed
		assert.NoError(t, err)
		assert.NotNil(t, net)
	} else {
		// OVS is not running, so should error on socket check
		assert.Error(t, err)
	}
}

func TestNewOVSIsolatedNetwork_BothNil(t *testing.T) {
	// Both config and options nil - should use defaults
	net, err := NewOVSIsolatedNetwork(nil, nil)
	if IsOVSAvailable() {
		// OVS is running, so connection should succeed
		assert.NoError(t, err)
		assert.NotNil(t, net)
	} else {
		// OVS is not running, so should error
		assert.Error(t, err)
	}
}

// TestNewOVSIsolatedNetwork_Success tests successful creation when OVS is available
func TestNewOVSIsolatedNetwork_Success(t *testing.T) {
	if !IsOVSAvailable() {
		// When OVS is not available, verify proper error handling
		cfg := DefaultNetworkConfig()
		opts := DefaultOVSNetworkOptions()

		ovsNet, err := NewOVSIsolatedNetwork(cfg, opts)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	opts := DefaultOVSNetworkOptions()

	ovsNet, err := NewOVSIsolatedNetwork(cfg, opts)
	require.NoError(t, err)
	require.NotNil(t, ovsNet)
	assert.Equal(t, cfg, ovsNet.config)
	assert.NotNil(t, ovsNet.ovsClient)
}

// TestOVSIsolatedNetwork_Config tests the Config method
func TestOVSIsolatedNetwork_Config(t *testing.T) {
	if !IsOVSAvailable() {
		// When OVS is not available, verify the network can't be created
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	gotCfg := ovsNet.Config()
	assert.Equal(t, cfg, gotCfg)
	assert.Equal(t, "tp-br", gotCfg.BridgeName)
}

// TestOVSIsolatedNetwork_ServerTapName tests the ServerTapName method
func TestOVSIsolatedNetwork_ServerTapName(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		cfg.ServerTapName = "custom-ovs-server"
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	cfg.ServerTapName = "custom-ovs-server"

	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, "custom-ovs-server", ovsNet.ServerTapName())
}

// TestOVSIsolatedNetwork_ClientTapName tests the ClientTapName method
func TestOVSIsolatedNetwork_ClientTapName(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		cfg.ClientTapName = "custom-ovs-client"
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	cfg.ClientTapName = "custom-ovs-client"

	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	assert.Equal(t, "custom-ovs-client", ovsNet.ClientTapName())
}

// TestOVSIsolatedNetwork_SetServerVLAN tests VLAN setting error handling
func TestOVSIsolatedNetwork_SetServerVLAN(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	// serverTap not created yet
	ctx := context.Background()
	err = ovsNet.SetServerVLAN(ctx, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server TAP not created")
}

// TestOVSIsolatedNetwork_SetClientVLAN tests VLAN setting error handling
func TestOVSIsolatedNetwork_SetClientVLAN(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	// clientTap not created yet
	ctx := context.Background()
	err = ovsNet.SetClientVLAN(ctx, 200)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "client TAP not created")
}

// TestOVSIsolatedNetwork_Setup_InvalidConfig tests setup with invalid config
func TestOVSIsolatedNetwork_Setup_InvalidConfig(t *testing.T) {
	if !IsOVSAvailable() {
		// Create invalid config
		cfg := &NetworkConfig{
			BridgeName: "", // Invalid - empty bridge name
		}
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		// OVS not available - we expect socket error first
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	// Create invalid config
	cfg := &NetworkConfig{
		BridgeName: "", // Invalid - empty bridge name
	}

	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	if err != nil {
		// May fail during creation if config is validated early
		return
	}

	err = ovsNet.Setup()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network config")
}

// TestOVSIsolatedNetwork_EnsureRules tests rule ensuring without setup
func TestOVSIsolatedNetwork_EnsureRules(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	// Should fail because network isn't set up
	err = ovsNet.EnsureRules()
	// Will fail due to lack of setup or permissions
	if os.Geteuid() != 0 {
		assert.Error(t, err)
	}
}

// TestOVSIsolatedNetwork_OVSClient tests the OVSClient accessor
func TestOVSIsolatedNetwork_OVSClient(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	client := ovsNet.OVSClient()
	assert.NotNil(t, client)
}

// Phase Management Tests

func TestOVSIsolatedNetwork_GetPhase_NotFound(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	phase := ovsNet.GetPhase("nonexistent-port")
	assert.Equal(t, NetworkPhaseUnconnected, phase)
}

func TestOVSIsolatedNetwork_GetPhaseInfo_NotFound(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	info, err := ovsNet.GetPhaseInfo("nonexistent-port")
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not found")
}

func TestOVSIsolatedNetwork_SetPhase_EmptyPortID(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.SetPhase("", NetworkPhaseProvisioning)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port ID cannot be empty")
}

func TestOVSIsolatedNetwork_QuarantinePort_EmptyPortID(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.QuarantinePort("", "test reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port ID cannot be empty")
}

func TestOVSIsolatedNetwork_UnquarantinePort_NotFound(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.UnquarantinePort("nonexistent-port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestOVSIsolatedNetwork_BlockPort_EmptyPortID(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.BlockPort("", "test reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port ID cannot be empty")
}

func TestOVSIsolatedNetwork_UnblockPort_NotFound(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.UnblockPort("nonexistent-port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestOVSIsolatedNetwork_TransitionToTrusted_EmptyPortID(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	// Create a dummy certificate
	cert := generateTestCertificate(t)

	err = ovsNet.TransitionToTrusted("", cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port ID cannot be empty")
}

func TestOVSIsolatedNetwork_TransitionToTrusted_NilCert(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	err = ovsNet.TransitionToTrusted("test-port", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate cannot be nil")
}

func TestOVSIsolatedNetwork_TransitionToTrusted_NotFound(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	ovsNet, err := NewOVSIsolatedNetwork(cfg, nil)
	require.NoError(t, err)

	cert := generateTestCertificate(t)

	err = ovsNet.TransitionToTrusted("nonexistent-port", cert)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// Helper function to generate a test certificate
func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestOVSIsolatedNetwork_PhaseTracking_Initialization(t *testing.T) {
	if !IsOVSAvailable() {
		cfg := DefaultNetworkConfig()
		opts := DefaultOVSNetworkOptions()
		ovsNet, err := NewOVSIsolatedNetwork(cfg, opts)
		assert.Error(t, err)
		assert.Nil(t, ovsNet)
		return
	}

	cfg := DefaultNetworkConfig()
	opts := DefaultOVSNetworkOptions()

	ovsNet, err := NewOVSIsolatedNetwork(cfg, opts)
	require.NoError(t, err)

	// Verify phase tracking is initialized
	assert.NotNil(t, ovsNet.portPhases)
	assert.NotNil(t, ovsNet.provFlowGen)
	assert.NotNil(t, ovsNet.quarFlowGen)
}

// Tests for NetworkPhase string representation
func TestNetworkPhase_String(t *testing.T) {
	tests := []struct {
		phase    NetworkPhase
		expected string
	}{
		{NetworkPhaseUnconnected, "unconnected"},
		{NetworkPhaseProvisioning, "provisioning"},
		{NetworkPhaseTrusted, "trusted"},
		{NetworkPhaseQuarantine, "quarantine"},
		{NetworkPhaseBlocked, "blocked"},
		{NetworkPhase(999), "unknown(999)"}, // Unknown phase
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.phase.String())
		})
	}
}
