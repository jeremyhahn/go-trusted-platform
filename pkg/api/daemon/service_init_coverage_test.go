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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SDNListPolicies Coverage Tests
// =============================================================================

// mockPolicyEngineForSDNListCoverage implements policy.PolicyEngine for SDNListPolicies testing
type mockPolicyEngineForSDNListCoverage struct {
	policy.PolicyEngine
	policies          map[string]*policy.PortPolicy
	portStates        map[string]policy.PortState
	shouldErrorPolicy bool
	shouldErrorState  bool
}

func newMockPolicyEngineForSDNListCoverage() *mockPolicyEngineForSDNListCoverage {
	return &mockPolicyEngineForSDNListCoverage{
		policies:   make(map[string]*policy.PortPolicy),
		portStates: make(map[string]policy.PortState),
	}
}

func (m *mockPolicyEngineForSDNListCoverage) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.shouldErrorPolicy {
		return nil, errors.New("policy not found")
	}
	if p, ok := m.policies[portID]; ok {
		return p, nil
	}
	return nil, errors.New("policy not found")
}

func (m *mockPolicyEngineForSDNListCoverage) GetPortState(portID string) (policy.PortState, error) {
	if m.shouldErrorState {
		return 0, errors.New("port state not found")
	}
	if s, ok := m.portStates[portID]; ok {
		return s, nil
	}
	return policy.PortStateUnconnected, nil
}

func (m *mockPolicyEngineForSDNListCoverage) SetPortState(portID string, state policy.PortState) error {
	m.portStates[portID] = state
	return nil
}

func (m *mockPolicyEngineForSDNListCoverage) ApplyPolicy(portID string, portPolicy *policy.PortPolicy) error {
	m.policies[portID] = portPolicy
	return nil
}

func (m *mockPolicyEngineForSDNListCoverage) GetPortInfo(portID string) (*policy.PortInfo, error) {
	return &policy.PortInfo{
		PortID:          portID,
		State:           policy.PortStateAuthorized,
		LastStateChange: time.Now(),
		AuthAttempts:    1,
		ErrorCount:      0,
	}, nil
}

// =============================================================================
// SDNListPolicies Tests
// =============================================================================

func TestMCPSDNListPolicies_NilPolicyEngine(t *testing.T) {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	ctx := context.Background()
	result, err := provider.SDNListPolicies(ctx)

	require.Error(t, err)
	require.Nil(t, result)
	assert.IsType(t, ErrSDNPolicyEngineNotConfigured{}, err)
}

func TestMCPSDNListPolicies_EmptyPolicies(t *testing.T) {
	mockEngine := newMockPolicyEngineForSDNListCoverage()

	sdnService := &SDNService{
		bridges: make(map[string]*bridgeResource),
		ports:   make(map[string]*portResource),
	}

	provider := &MCPServiceProvider{
		policyEngine: mockEngine,
		sdnService:   sdnService,
		logger:       slog.Default(),
	}

	ctx := context.Background()
	result, err := provider.SDNListPolicies(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

func TestMCPSDNListPolicies_NoSDNService(t *testing.T) {
	mockEngine := newMockPolicyEngineForSDNListCoverage()

	provider := &MCPServiceProvider{
		policyEngine: mockEngine,
		sdnService:   nil,
		logger:       slog.Default(),
	}

	ctx := context.Background()
	result, err := provider.SDNListPolicies(ctx)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result)
}

// =============================================================================
// SetTPM2Service Additional Coverage Tests
// =============================================================================

func TestMCPSetTPM2Service_WithValidService(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Initially nil
	assert.Nil(t, provider.tpm2Service)

	// Set the service
	provider.SetTPM2Service(mockTPM)

	// Should now be set
	assert.NotNil(t, provider.tpm2Service)
	assert.Equal(t, mockTPM, provider.tpm2Service)
}

func TestMCPSetTPM2Service_OverwriteExisting(t *testing.T) {
	mockTPM1 := &mockTPM2MCPService{}
	mockTPM2 := &mockTPM2MCPService{}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Set first service
	provider.SetTPM2Service(mockTPM1)
	assert.Equal(t, mockTPM1, provider.tpm2Service)

	// Overwrite with second service
	provider.SetTPM2Service(mockTPM2)
	assert.Equal(t, mockTPM2, provider.tpm2Service)
}

// =============================================================================
// KMSService Additional Coverage Tests
// =============================================================================

func TestKMSService_StartStopCoverage(t *testing.T) {
	service := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	err := service.Start(ctx)
	require.NoError(t, err)
	assert.True(t, service.IsRunning())

	// Start again should be no-op
	err = service.Start(ctx)
	require.NoError(t, err)

	// Stop
	err = service.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, service.IsRunning())

	// Stop again should be no-op
	err = service.Stop(ctx)
	require.NoError(t, err)
}

func TestKMSService_Servers_NotInitializedCoverage(t *testing.T) {
	service := &KMSService{}

	// All server getters should return nil before initialization
	assert.Nil(t, service.KMSServer())
	assert.Nil(t, service.SecretsServer())
	assert.Nil(t, service.CryptoServer())
	assert.Nil(t, service.DEKServer())
}

// =============================================================================
// IAMService Additional Coverage Tests
// =============================================================================

func TestIAMService_StartStopCoverage(t *testing.T) {
	service := &IAMService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	err := service.Start(ctx)
	require.NoError(t, err)
	assert.True(t, service.IsRunning())

	// Start again should be no-op
	err = service.Start(ctx)
	require.NoError(t, err)

	// Stop
	err = service.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, service.IsRunning())

	// Stop again should be no-op
	err = service.Stop(ctx)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Coverage Tests
// =============================================================================

func TestErrTPM2ServiceNotAvailable_ErrorCoverage(t *testing.T) {
	err := ErrTPM2ServiceNotAvailable{}
	assert.Equal(t, "TPM2 service not available", err.Error())
}

func TestErrTPM2OperationFailed_ErrorCoverage(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrTPM2OperationFailed{Operation: "test op", Cause: cause}
	assert.Contains(t, err.Error(), "test op")
	assert.Contains(t, err.Error(), "underlying error")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrIDevIDCertificateNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIDevIDCertificateNotFound{}
	assert.Equal(t, "IDevID certificate not installed", err.Error())
}

func TestErrIAKCertificateNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIAKCertificateNotFound{}
	assert.Equal(t, "IAK certificate not installed", err.Error())
}

func TestErrInvalidCertificatePEM_ErrorCoverage(t *testing.T) {
	err := ErrInvalidCertificatePEM{}
	assert.Equal(t, "invalid PEM-encoded certificate", err.Error())
}

func TestErrIDevIDNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIDevIDNotFound{}
	assert.Equal(t, "IDevID not found in TPM", err.Error())
}

func TestErrIAKNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIAKNotFound{}
	assert.Equal(t, "IAK not found in TPM", err.Error())
}

func TestErrSDNPolicyEngineNotConfigured_ErrorCoverage(t *testing.T) {
	err := ErrSDNPolicyEngineNotConfigured{}
	assert.Equal(t, "SDN policy engine not configured", err.Error())
}

// =============================================================================
// MCPServiceProvider Constructor Coverage Tests
// =============================================================================

func TestNewMCPServiceProvider_WithAllServices(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}

	config := &MCPServiceProviderConfig{
		Logger:      slog.Default(),
		TPM2Service: mockTPM,
	}

	provider := NewMCPServiceProvider(config)

	require.NotNil(t, provider)
	assert.NotNil(t, provider.logger)
	assert.Equal(t, mockTPM, provider.tpm2Service)
}

func TestNewMCPServiceProvider_NilLogger(t *testing.T) {
	config := &MCPServiceProviderConfig{
		Logger: nil,
	}

	provider := NewMCPServiceProvider(config)

	require.NotNil(t, provider)
	assert.NotNil(t, provider.logger) // Should use slog.Default()
}

// =============================================================================
// Daemon SetTPM2Service Coverage Tests
// =============================================================================

func TestDaemon_SetTPM2Service_NilService(t *testing.T) {
	d := &Daemon{
		logger: logging.NewLogger(slog.LevelDebug, nil),
	}

	// Setting nil should return early
	d.SetTPM2Service(nil)

	assert.Nil(t, d.tpm2Service)
}

func TestDaemon_SetTPM2Service_WithService(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	mockProvider := &MCPServiceProvider{
		logger: logging.NewLogger(slog.LevelDebug, nil).Slog(),
	}

	d := &Daemon{
		logger:      logging.NewLogger(slog.LevelDebug, nil),
		mcpProvider: mockProvider,
	}

	d.SetTPM2Service(mockTPM)

	assert.Equal(t, mockTPM, d.tpm2Service)
	assert.Equal(t, mockTPM, mockProvider.tpm2Service)
}

func TestDaemon_TPM2Service_Getter(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	d := &Daemon{
		tpm2Service: mockTPM,
	}

	result := d.TPM2Service()
	assert.Equal(t, mockTPM, result)
}
