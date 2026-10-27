package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOPAServer serves a fixed OPA decision for every evaluation.
func newOPAServer(t *testing.T, allow bool, vlan uint16) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := opaResponse{Result: &OPAResult{Allow: allow, AssignedVLAN: vlan}}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// newFlowService builds an initialized service whose OPA endpoint is
// opaServer (when non-nil) and whose flow manager drives controller.
func newFlowService(t *testing.T, verifier AttestationVerifier, opaServer *httptest.Server, controller *mockFlowController) NetworkAuthService {
	t.Helper()
	ctx := context.Background()

	// A nil controller leaves the flow manager without one, for callers
	// that authenticate concurrently: mockFlowController is not synchronized.
	var flowOpts []FlowManagerOption
	if controller != nil {
		flowOpts = append(flowOpts, WithFlowController(controller))
	}
	flows := NewFlowManager(flowOpts...)
	require.NoError(t, flows.Initialize(ctx, &FlowConfig{BridgeName: "br0"}))

	opts := []NetworkAuthServiceOption{WithFlowManager(flows)}
	if verifier != nil {
		opts = append(opts, WithAttestationVerifier(verifier))
	}
	service := NewNetworkAuthService(opts...)

	config := &AuthConfig{
		QuarantineVLAN:     1,
		ProductionVLAN:     100,
		BridgeName:         "br0",
		RequireAttestation: verifier != nil,
	}
	if opaServer != nil {
		config.RequirePolicyEvaluation = true
		config.OPAEndpoint = opaServer.URL
		config.OPAPolicyPath = "network/auth"
	}
	require.NoError(t, service.Initialize(ctx, config))
	t.Cleanup(func() { require.NoError(t, service.Close()) })
	return service
}

// TestNetworkAuthService_FullFlow drives one port through authentication with
// attestation and policy, re-attestation and revocation.
func TestNetworkAuthService_FullFlow(t *testing.T) {
	ctx := context.Background()
	controller := &mockFlowController{}
	service := newFlowService(t, &mockAttestationVerifier{shouldVerify: true}, newOPAServer(t, true, 100), controller)

	result, err := service.Authenticate(ctx, &PortAuthRequest{
		PortID:      "port-001",
		Certificate: createTestCertificate(t),
		Nonce:       []byte("nonce-1"),
	})
	require.NoError(t, err)
	assert.Equal(t, AuthStateAuthorized, result.State)
	assert.Equal(t, uint16(100), result.VLAN)
	assert.NotEmpty(t, result.SessionID)
	assert.True(t, result.AttestationVerified)
	assert.True(t, result.PolicyEvaluated)
	assert.True(t, result.PolicyDecision)
	assert.True(t, result.FlowRulesInstalled)
	assert.True(t, controller.addFlowCalled)

	authorized, err := service.GetPortState(ctx, "port-001")
	require.NoError(t, err)
	assert.Equal(t, AuthStateAuthorized, authorized.AuthState)
	assert.Equal(t, uint16(100), authorized.VLAN)

	ports, err := service.GetAllPorts(ctx)
	require.NoError(t, err)
	assert.Len(t, ports, 1)

	reattest, err := service.Reattest(ctx, "port-001", []byte("nonce-2"))
	require.NoError(t, err)
	assert.True(t, reattest.AttestationVerified)
	assert.Equal(t, AuthStateAuthorized, reattest.State)

	require.NoError(t, service.Revoke(ctx, "port-001", "test revocation"))
	state, err := service.GetPortState(ctx, "port-001")
	require.NoError(t, err)
	assert.Equal(t, AuthStateRevoked, state.AuthState)
	assert.Equal(t, uint16(1), state.VLAN)
}

// TestNetworkAuthService_FailureLeavesPortInQuarantine checks that every
// rejected authentication returns a quarantine-state result.
func TestNetworkAuthService_FailureLeavesPortInQuarantine(t *testing.T) {
	ctx := context.Background()

	t.Run("policy denied", func(t *testing.T) {
		service := newFlowService(t, nil, newOPAServer(t, false, 0), &mockFlowController{})
		result, err := service.Authenticate(ctx, &PortAuthRequest{PortID: "port-denied", Certificate: createTestCertificate(t)})
		var policyErr ErrPolicyViolation
		require.ErrorAs(t, err, &policyErr)
		assert.Equal(t, AuthStateQuarantine, result.State)
		assert.Equal(t, uint16(1), result.VLAN)
	})

	t.Run("attestation failed", func(t *testing.T) {
		service := newFlowService(t, &mockAttestationVerifier{shouldVerify: false}, nil, &mockFlowController{})
		result, err := service.Authenticate(ctx, &PortAuthRequest{PortID: "port-attest", Certificate: createTestCertificate(t)})
		var attestErr ErrAttestFailed
		require.ErrorAs(t, err, &attestErr)
		assert.Equal(t, AuthStateQuarantine, result.State)
	})

	t.Run("certificate expired", func(t *testing.T) {
		service := newFlowService(t, nil, nil, &mockFlowController{})
		result, err := service.Authenticate(ctx, &PortAuthRequest{PortID: "port-expired", Certificate: createExpiredCertificate(t)})
		var certErr ErrCertInvalid
		require.ErrorAs(t, err, &certErr)
		assert.Equal(t, AuthStateQuarantine, result.State)
	})
}

// TestNetworkAuthService_ConcurrentAuthentication authenticates many ports at
// once and checks every one succeeds and is tracked.
func TestNetworkAuthService_ConcurrentAuthentication(t *testing.T) {
	ctx := context.Background()
	service := newFlowService(t, &mockAttestationVerifier{shouldVerify: true}, newOPAServer(t, true, 100), nil)

	const numConcurrent = 50
	requests := make([]*PortAuthRequest, numConcurrent)
	for i := range requests {
		requests[i] = &PortAuthRequest{
			PortID:      fmt.Sprintf("port-%d", i),
			Certificate: createTestCertificate(t),
			Nonce:       []byte(fmt.Sprintf("nonce-%d", i)),
		}
	}

	results := make(chan error, numConcurrent)
	for _, request := range requests {
		go func(request *PortAuthRequest) {
			_, err := service.Authenticate(ctx, request)
			results <- err
		}(request)
	}
	for range requests {
		assert.NoError(t, <-results)
	}

	ports, err := service.GetAllPorts(ctx)
	require.NoError(t, err)
	assert.Len(t, ports, numConcurrent)
}

// TestNetworkAuthService_PolicyVLANReachesFlowController checks that the
// policy-assigned VLAN, not the configured production VLAN, is programmed on
// the port, and that revocation programs the quarantine VLAN.
func TestNetworkAuthService_PolicyVLANReachesFlowController(t *testing.T) {
	ctx := context.Background()
	controller := &mockFlowController{}
	service := newFlowService(t, nil, newOPAServer(t, true, 200), controller)

	result, err := service.Authenticate(ctx, &PortAuthRequest{PortID: "port-vlan", Certificate: createTestCertificate(t)})
	require.NoError(t, err)
	assert.Equal(t, uint16(200), result.VLAN)
	assert.Equal(t, uint16(200), controller.lastVLAN)

	require.NoError(t, service.Revoke(ctx, "port-vlan", "vlan transition test"))
	state, err := service.GetPortState(ctx, "port-vlan")
	require.NoError(t, err)
	assert.Equal(t, uint16(1), state.VLAN)
	assert.Equal(t, uint16(1), controller.lastVLAN)
}
