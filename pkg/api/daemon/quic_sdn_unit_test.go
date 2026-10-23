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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Policy Engine for Unit Testing
// =============================================================================

// MockSDNPolicyEngine implements policy.PolicyEngine for unit testing
type MockSDNPolicyEngine struct {
	mu sync.RWMutex

	// State
	portStates   map[string]policy.PortState
	portPolicies map[string]*policy.PortPolicy
	portVLANs    map[string]uint16
	portInfos    map[string]*policy.PortInfo

	// Error injection
	setPortStateErr error
	getPortStateErr error
	getPortInfoErr  error
	applyPolicyErr  error
	removePolicyErr error
	getPolicyErr    error
	setPortVLANErr  error
	getPortVLANErr  error
	blockPortErr    error
	unblockPortErr  error
	getOFPortErr    error
	authPortErr     error
	onExpiredErr    error
	onRevokedErr    error
}

// NewMockSDNPolicyEngine creates a new mock policy engine
func NewMockSDNPolicyEngine() *MockSDNPolicyEngine {
	return &MockSDNPolicyEngine{
		portStates:   make(map[string]policy.PortState),
		portPolicies: make(map[string]*policy.PortPolicy),
		portVLANs:    make(map[string]uint16),
		portInfos:    make(map[string]*policy.PortInfo),
	}
}

func (m *MockSDNPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	if m.setPortStateErr != nil {
		return m.setPortStateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = state
	return nil
}

func (m *MockSDNPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.getPortStateErr != nil {
		return policy.PortStateUnconnected, m.getPortStateErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.portStates[portID]
	if !ok {
		return policy.PortStateUnconnected, errors.New("port not found")
	}
	return state, nil
}

func (m *MockSDNPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	if m.getPortInfoErr != nil {
		return nil, m.getPortInfoErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.portInfos[portID]
	if !ok {
		return nil, errors.New("port info not found")
	}
	return info, nil
}

func (m *MockSDNPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	if m.applyPolicyErr != nil {
		return m.applyPolicyErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portPolicies[portID] = pol
	m.portStates[portID] = policy.PortStateAuthorized
	if pol != nil {
		m.portVLANs[portID] = pol.VLAN
	}
	return nil
}

func (m *MockSDNPolicyEngine) RemovePolicy(portID string) error {
	if m.removePolicyErr != nil {
		return m.removePolicyErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.portPolicies, portID)
	m.portStates[portID] = policy.PortStateUnauthorized
	return nil
}

func (m *MockSDNPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.getPolicyErr != nil {
		return nil, m.getPolicyErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	pol, ok := m.portPolicies[portID]
	if !ok {
		return nil, errors.New("policy not found")
	}
	return pol, nil
}

func (m *MockSDNPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	if m.setPortVLANErr != nil {
		return m.setPortVLANErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portVLANs[portID] = vlan
	return nil
}

func (m *MockSDNPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	if m.getPortVLANErr != nil {
		return 0, m.getPortVLANErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	vlan, ok := m.portVLANs[portID]
	if !ok {
		return 0, errors.New("vlan not found")
	}
	return vlan, nil
}

func (m *MockSDNPolicyEngine) BlockPort(portID string) error {
	if m.blockPortErr != nil {
		return m.blockPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *MockSDNPolicyEngine) UnblockPort(portID string) error {
	if m.unblockPortErr != nil {
		return m.unblockPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = policy.PortStateProvisioning
	return nil
}

func (m *MockSDNPolicyEngine) GetOFPort(portID string) (int32, error) {
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	return 1, nil
}

func (m *MockSDNPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	if m.authPortErr != nil {
		return m.authPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *MockSDNPolicyEngine) OnCertificateExpired(portID string) error {
	if m.onExpiredErr != nil {
		return m.onExpiredErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *MockSDNPolicyEngine) OnCertificateRevoked(portID string) error {
	if m.onRevokedErr != nil {
		return m.onRevokedErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *MockSDNPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// Test helper methods for error injection
func (m *MockSDNPolicyEngine) SetSetPortStateError(err error) { m.setPortStateErr = err }
func (m *MockSDNPolicyEngine) SetGetPortStateError(err error) { m.getPortStateErr = err }
func (m *MockSDNPolicyEngine) SetGetPortInfoError(err error)  { m.getPortInfoErr = err }
func (m *MockSDNPolicyEngine) SetApplyPolicyError(err error)  { m.applyPolicyErr = err }
func (m *MockSDNPolicyEngine) SetRemovePolicyError(err error) { m.removePolicyErr = err }
func (m *MockSDNPolicyEngine) SetGetPolicyError(err error)    { m.getPolicyErr = err }
func (m *MockSDNPolicyEngine) SetSetPortVLANError(err error)  { m.setPortVLANErr = err }
func (m *MockSDNPolicyEngine) SetGetPortVLANError(err error)  { m.getPortVLANErr = err }
func (m *MockSDNPolicyEngine) SetBlockPortError(err error)    { m.blockPortErr = err }
func (m *MockSDNPolicyEngine) SetUnblockPortError(err error)  { m.unblockPortErr = err }
func (m *MockSDNPolicyEngine) SetGetOFPortError(err error)    { m.getOFPortErr = err }
func (m *MockSDNPolicyEngine) SetAuthPortError(err error)     { m.authPortErr = err }
func (m *MockSDNPolicyEngine) SetOnExpiredError(err error)    { m.onExpiredErr = err }
func (m *MockSDNPolicyEngine) SetOnRevokedError(err error)    { m.onRevokedErr = err }

// AddPortState adds a port state to the mock
func (m *MockSDNPolicyEngine) AddPortState(portID string, state policy.PortState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portStates[portID] = state
}

// AddPortPolicy adds a port policy to the mock
func (m *MockSDNPolicyEngine) AddPortPolicy(portID string, pol *policy.PortPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.portPolicies[portID] = pol
	if pol != nil {
		m.portVLANs[portID] = pol.VLAN
	}
}

// Compile-time interface check
var _ policy.PolicyEngine = (*MockSDNPolicyEngine)(nil)

// =============================================================================
// Test Helper: Create Handler with Mock Dependencies
// =============================================================================

// stubOVSClient is a minimal OVS client stub for unit tests that only need
// SDNService-level operations (policy, port state) without real OVS calls.
type stubOVSClient struct{}

func (s *stubOVSClient) Connect(_ context.Context) error { return nil }
func (s *stubOVSClient) AddBond(_ context.Context, _, _ string, _ []string, _, _ string) (*ovs.Port, error) {
	return nil, nil
}
func (s *stubOVSClient) Disconnect() error { return nil }
func (s *stubOVSClient) CreateBridge(_ context.Context, name string) (*ovs.Bridge, error) {
	return &ovs.Bridge{UUID: "stub-" + name, Name: name}, nil
}
func (s *stubOVSClient) DeleteBridge(_ context.Context, _ string) error { return nil }
func (s *stubOVSClient) GetBridge(_ context.Context, name string) (*ovs.Bridge, error) {
	return &ovs.Bridge{UUID: "stub-" + name, Name: name}, nil
}
func (s *stubOVSClient) ListBridges(_ context.Context) ([]*ovs.Bridge, error)   { return nil, nil }
func (s *stubOVSClient) SetBridgeFailMode(_ context.Context, _, _ string) error { return nil }
func (s *stubOVSClient) SetBridgeProtocols(_ context.Context, _ string, _ []string) error {
	return nil
}
func (s *stubOVSClient) AddPort(_ context.Context, _, name string) (*ovs.Port, error) {
	return &ovs.Port{UUID: "stub-" + name, Name: name}, nil
}
func (s *stubOVSClient) DeletePort(_ context.Context, _, _ string) error { return nil }
func (s *stubOVSClient) GetPort(_ context.Context, name string) (*ovs.Port, error) {
	return &ovs.Port{UUID: "stub-" + name, Name: name}, nil
}
func (s *stubOVSClient) ListPorts(_ context.Context, _ string) ([]*ovs.Port, error) {
	return nil, nil
}
func (s *stubOVSClient) SetPortVLAN(_ context.Context, _ string, _ int64) error { return nil }
func (s *stubOVSClient) SetPortState(_ context.Context, _ string, _ ovs.PortState) error {
	return nil
}
func (s *stubOVSClient) SetIngressPolicing(_ context.Context, _ string, _, _ uint64) error {
	return nil
}

func (s *stubOVSClient) SetEgressShaping(_ context.Context, _ string, _, _ uint64) error {
	return nil
}
func (s *stubOVSClient) GetInterface(_ context.Context, name string) (*ovs.Interface, error) {
	return &ovs.Interface{Name: name}, nil
}
func (s *stubOVSClient) AddFlow(_ context.Context, _ string, _ *ovs.FlowMod) error { return nil }
func (s *stubOVSClient) AddFlows(_ context.Context, _ string, _ []*ovs.FlowMod) error {
	return nil
}
func (s *stubOVSClient) DeleteFlow(_ context.Context, _, _ string) error  { return nil }
func (s *stubOVSClient) DeleteAllFlows(_ context.Context, _ string) error { return nil }
func (s *stubOVSClient) DeleteFlowsByCookie(_ context.Context, _ string, _, _ uint64) error {
	return nil
}
func (s *stubOVSClient) DeleteFlowStrict(_ context.Context, _ string, _ *ovs.FlowMod) error {
	return nil
}
func (s *stubOVSClient) SetBridgeExternalIDs(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *stubOVSClient) GetBridgeExternalIDs(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{}, nil
}
func (s *stubOVSClient) ListFlows(_ context.Context, _ string) ([]*ovs.Flow, error) {
	return nil, nil
}
func (s *stubOVSClient) GetFlowStats(_ context.Context, _, _ string) ([]*ovs.Flow, error) {
	return nil, nil
}

func (s *stubOVSClient) IsConnected() bool { return true }
func (s *stubOVSClient) Close() error      { return nil }
func (s *stubOVSClient) UpdateBridge(_ context.Context, _ string, _ map[string]interface{}) error {
	return nil
}
func (s *stubOVSClient) UpdatePort(_ context.Context, _ string, _ map[string]interface{}) error {
	return nil
}
func (s *stubOVSClient) SetPortTrunks(_ context.Context, _ string, _ []int64) error { return nil }
func (s *stubOVSClient) GetOFPort(_ context.Context, _ string) (int32, error)       { return 0, nil }
func (s *stubOVSClient) GetInterfaceOptions(_ context.Context, _ string) (map[string]string, error) {
	return nil, nil
}
func (s *stubOVSClient) CreateBridgeWithOptions(_ context.Context, name string, _ *ovs.BridgeOptions) (*ovs.Bridge, error) {
	return &ovs.Bridge{UUID: "stub-" + name, Name: name}, nil
}
func (s *stubOVSClient) SetBridgeDatapath(_ context.Context, _, _ string) error { return nil }
func (s *stubOVSClient) SetBridgeOtherConfig(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *stubOVSClient) SetInterfaceType(_ context.Context, _, _ string) error { return nil }
func (s *stubOVSClient) SetInterfaceOptions(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *stubOVSClient) SetInterfaceOtherConfig(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *stubOVSClient) SetOVSOtherConfig(_ context.Context, _ map[string]string) error { return nil }
func (s *stubOVSClient) GetOVSOtherConfig(_ context.Context) (map[string]string, error) {
	return nil, nil
}
func (s *stubOVSClient) DeleteOVSOtherConfig(_ context.Context, _ []string) error { return nil }
func (s *stubOVSClient) AddVXLANPort(_ context.Context, _ string, _ *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	return nil, nil
}
func (s *stubOVSClient) AddVXLANPortWithName(_ context.Context, _, _ string, _ *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	return nil, nil
}
func (s *stubOVSClient) DeleteVXLANPort(_ context.Context, _, _ string) error { return nil }
func (s *stubOVSClient) ListVXLANPorts(_ context.Context, _ string) ([]*ovs.VXLANPort, error) {
	return nil, nil
}
func (s *stubOVSClient) GetVXLANPort(_ context.Context, _, _ string) (*ovs.VXLANPort, error) {
	return nil, nil
}
func (s *stubOVSClient) GetVXLANPortWithOptions(_ context.Context, _, _ string) (*ovs.VXLANPort, error) {
	return nil, nil
}
func (s *stubOVSClient) UpdateVXLANPort(_ context.Context, _, _ string, _ *ovs.VXLANPortConfig) error {
	return nil
}
func (s *stubOVSClient) ModifyFlow(_ context.Context, _ string, _ *ovs.FlowMod) error { return nil }
func (s *stubOVSClient) ListDatabases(_ context.Context) ([]string, error)            { return nil, nil }
func (s *stubOVSClient) GetSchema(_ context.Context) (*ovs.GetSchemaResult, error)    { return nil, nil }
func (s *stubOVSClient) Echo(_ context.Context, data []interface{}) ([]interface{}, error) {
	return data, nil
}
func (s *stubOVSClient) Transact(_ context.Context, _ ...ovs.Operation) (ovs.TransactResponse, error) {
	return nil, nil
}
func (s *stubOVSClient) Select(_ context.Context, _ string, _ []ovs.Condition, _ []string) ([]map[string]interface{}, error) {
	return nil, nil
}

// Compile-time check that stubOVSClient implements ovs.ClientInterface
var _ ovs.ClientInterface = (*stubOVSClient)(nil)

// testSDNHandlerWithMocks is a helper struct for testing with mocks
type testSDNHandlerWithMocks struct {
	handler    *QUICServiceHandler
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// newTestSDNHandlerWithMocks creates a test handler with mock dependencies
func newTestSDNHandlerWithMocks(t *testing.T) *testSDNHandlerWithMocks {
	t.Helper()
	logger := logging.DefaultLogger()

	// Create handler with SDN service using a stub OVS client
	sdnSvc, err := NewSDNService("", WithOVSClient(&stubOVSClient{}))
	require.NoError(t, err)
	handler := newTestQUICServiceHandler(logger,
		WithQUICSDNService(sdnSvc),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	return &testSDNHandlerWithMocks{
		handler:    handler,
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

func (th *testSDNHandlerWithMocks) cleanup() {
	th.cancelFunc()
}

// =============================================================================
// SDN Handler Unit Tests - Policy Engine Path (No SDN Client Required)
// =============================================================================

func TestQUICSDN_GetPortState_WithSDNService(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	// First create a bridge and port so FindPortBridge can find it
	_, bridgeErr := th.handler.sdnService.CreateBridge(th.ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: "br0"},
	})
	require.NoError(t, bridgeErr)
	_, portErr := th.handler.sdnService.AddPort(th.ctx, &platformv1.AddPortRequest{
		BridgeId: "br0",
		Config:   &platformv1.PortConfig{Name: "eth0"},
	})
	require.NoError(t, portErr)

	getReq := &SDNGetPortStateRequest{
		PortName: "eth0",
	}
	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPortState,
		Payload: payload,
	}

	resp := th.handler.handleSDNGetPortState(th.ctx, req)
	assert.Equal(t, quicwire.StatusOK, resp.Status)
}

func TestQUICSDN_ApplyPolicy_DecodingErrorUnit(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNApplyPolicy,
		Payload: []byte{0xFF, 0xFE}, // Invalid payload
	}

	resp := th.handler.handleSDNApplyPolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestQUICSDN_DeletePolicy_MissingPolicyID(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	deleteReq := &SDNDeletePolicyRequest{
		PolicyID: "",
	}

	payload, err := quicwire.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNDeletePolicy,
		Payload: payload,
	}

	resp := th.handler.handleSDNDeletePolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestQUICSDN_DeletePolicy_NotFound(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	deleteReq := &SDNDeletePolicyRequest{
		PolicyID: "nonexistent-policy",
	}

	payload, err := quicwire.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNDeletePolicy,
		Payload: payload,
	}

	resp := th.handler.handleSDNDeletePolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	assert.Contains(t, string(resp.Payload), "nonexistent-policy", "the error names the policy, not a port")
}

func TestQUICSDN_GetPolicy_NotFound(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	getReq := &SDNGetPolicyRequest{
		PolicyID: "nonexistent",
	}

	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPolicy,
		Payload: payload,
	}

	resp := th.handler.handleSDNGetPolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	assert.Equal(t, ErrSDNPolicyNotFound{PolicyID: "nonexistent"}.Error(), string(resp.Payload),
		"the error names the policy, not a port")
}

func TestSDNPolicyError_NotFoundNamesPolicy(t *testing.T) {
	err := sdnPolicyError("SDNGetPolicy", "policy-7", status.Error(codes.NotFound, "policy not found"))

	var notFound ErrSDNPolicyNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "policy-7", notFound.PolicyID)
}

func TestSDNPolicyError_OtherFailureIsNotNotFound(t *testing.T) {
	cause := status.Error(codes.Internal, "store unavailable")

	err := sdnPolicyError("SDNGetPolicy", "policy-7", cause)

	var failed ErrQUICOperationFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, "SDNGetPolicy", failed.Op)
	assert.ErrorIs(t, err, cause)
	var notFound ErrSDNPolicyNotFound
	assert.False(t, errors.As(err, &notFound), "a store failure is not reported as a missing policy")
}

func TestQUICSDN_GetPolicy_MissingPolicyID(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	getReq := &SDNGetPolicyRequest{
		PolicyID: "",
	}

	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPolicy,
		Payload: payload,
	}

	resp := th.handler.handleSDNGetPolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestQUICSDN_ListPolicies_NilSDNService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)

	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNListPolicies,
		Payload: nil,
	}

	// Route through handleSDNOperation which checks sdnService nil
	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// =============================================================================
// SDN Handler Unit Tests - Decoding Error Paths
// =============================================================================

func TestQUICSDN_ApplyPolicy_DecodingError(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNApplyPolicy,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
	}

	resp := th.handler.handleSDNApplyPolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestQUICSDN_DeletePolicy_DecodingError(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNDeletePolicy,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
	}

	resp := th.handler.handleSDNDeletePolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestQUICSDN_GetPolicy_DecodingError(t *testing.T) {
	th := newTestSDNHandlerWithMocks(t)
	defer th.cleanup()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPolicy,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
	}

	resp := th.handler.handleSDNGetPolicy(th.ctx, req)
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

func TestQUICSDN_DeletePolicy_NilSDNService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)

	ctx := context.Background()

	deleteReq := &SDNDeletePolicyRequest{
		PolicyID: "eth0",
	}

	payload, err := quicwire.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNDeletePolicy,
		Payload: payload,
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestQUICSDN_GetPolicy_NilSDNService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)

	ctx := context.Background()

	getReq := &SDNGetPolicyRequest{
		PolicyID: "eth0",
	}

	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPolicy,
		Payload: payload,
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// =============================================================================
// SDN Type Conversion Tests - Additional Coverage
// =============================================================================

// Mock Policy Engine Interface Verification Test
// =============================================================================

func TestMockSDNPolicyEngine_ImplementsInterface(t *testing.T) {
	mock := NewMockSDNPolicyEngine()

	// Test port state operations
	err := mock.SetPortState("eth0", policy.PortStateAuthorized)
	require.NoError(t, err)

	state, err := mock.GetPortState("eth0")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateAuthorized, state)

	// Test policy operations
	testPolicy := &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
	}
	err = mock.ApplyPolicy("eth0", testPolicy)
	require.NoError(t, err)

	retrievedPolicy, err := mock.GetPolicy("eth0")
	require.NoError(t, err)
	assert.Equal(t, "tenant1", retrievedPolicy.TenantID)

	err = mock.RemovePolicy("eth0")
	require.NoError(t, err)

	// Test VLAN operations
	err = mock.SetPortVLAN("eth1", 200)
	require.NoError(t, err)

	vlan, err := mock.GetPortVLAN("eth1")
	require.NoError(t, err)
	assert.Equal(t, uint16(200), vlan)

	// Test block/unblock
	err = mock.BlockPort("eth0")
	require.NoError(t, err)
	state, err = mock.GetPortState("eth0")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateBlocked, state)

	err = mock.UnblockPort("eth0")
	require.NoError(t, err)
	state, err = mock.GetPortState("eth0")
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateProvisioning, state)

	// Test certificate operations
	err = mock.AuthenticatePort("eth0", nil)
	require.NoError(t, err)

	err = mock.OnCertificateExpired("eth0")
	require.NoError(t, err)

	err = mock.OnCertificateRevoked("eth0")
	require.NoError(t, err)

	// Test GetOFPort
	ofPort, err := mock.GetOFPort("eth0")
	require.NoError(t, err)
	assert.Equal(t, int32(1), ofPort)

	// Test GetMonitor
	assert.Nil(t, mock.GetMonitor())
}

func TestMockSDNPolicyEngine_ErrorInjection(t *testing.T) {
	mock := NewMockSDNPolicyEngine()
	testErr := errors.New("injected error")

	t.Run("SetPortState_Error", func(t *testing.T) {
		mock.SetSetPortStateError(testErr)
		err := mock.SetPortState("eth0", policy.PortStateAuthorized)
		assert.Equal(t, testErr, err)
		mock.SetSetPortStateError(nil)
	})

	t.Run("GetPortState_Error", func(t *testing.T) {
		mock.SetGetPortStateError(testErr)
		_, err := mock.GetPortState("eth0")
		assert.Equal(t, testErr, err)
		mock.SetGetPortStateError(nil)
	})

	t.Run("ApplyPolicy_Error", func(t *testing.T) {
		mock.SetApplyPolicyError(testErr)
		err := mock.ApplyPolicy("eth0", &policy.PortPolicy{})
		assert.Equal(t, testErr, err)
		mock.SetApplyPolicyError(nil)
	})

	t.Run("RemovePolicy_Error", func(t *testing.T) {
		mock.SetRemovePolicyError(testErr)
		err := mock.RemovePolicy("eth0")
		assert.Equal(t, testErr, err)
		mock.SetRemovePolicyError(nil)
	})

	t.Run("GetPolicy_Error", func(t *testing.T) {
		mock.SetGetPolicyError(testErr)
		_, err := mock.GetPolicy("eth0")
		assert.Equal(t, testErr, err)
		mock.SetGetPolicyError(nil)
	})

	t.Run("SetPortVLAN_Error", func(t *testing.T) {
		mock.SetSetPortVLANError(testErr)
		err := mock.SetPortVLAN("eth0", 100)
		assert.Equal(t, testErr, err)
		mock.SetSetPortVLANError(nil)
	})

	t.Run("GetPortVLAN_Error", func(t *testing.T) {
		mock.SetGetPortVLANError(testErr)
		_, err := mock.GetPortVLAN("eth0")
		assert.Equal(t, testErr, err)
		mock.SetGetPortVLANError(nil)
	})

	t.Run("BlockPort_Error", func(t *testing.T) {
		mock.SetBlockPortError(testErr)
		err := mock.BlockPort("eth0")
		assert.Equal(t, testErr, err)
		mock.SetBlockPortError(nil)
	})

	t.Run("UnblockPort_Error", func(t *testing.T) {
		mock.SetUnblockPortError(testErr)
		err := mock.UnblockPort("eth0")
		assert.Equal(t, testErr, err)
		mock.SetUnblockPortError(nil)
	})

	t.Run("GetOFPort_Error", func(t *testing.T) {
		mock.SetGetOFPortError(testErr)
		_, err := mock.GetOFPort("eth0")
		assert.Equal(t, testErr, err)
		mock.SetGetOFPortError(nil)
	})
}

// =============================================================================
// Additional SDN Request Validation Tests
// =============================================================================
