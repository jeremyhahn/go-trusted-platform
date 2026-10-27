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
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time proofs that the production consolidated orchestrator
// (container.ComputeOrchestrator) satisfies every capability interface the
// daemon RPC layer type-asserts on the compute.Orchestrator value. If any
// of these break, AttestContainer / the adapter
// forwarding silently degrade to Unimplemented in production.
var (
	_ containerAttester        = (*container.ComputeOrchestrator)(nil)
	_ containerLogStreamer     = (*container.ComputeOrchestrator)(nil)
	_ containerAttestVerifier  = (*container.ComputeOrchestrator)(nil)
	_ containerPolicyEvaluator = (*container.ComputeOrchestrator)(nil)
	_ containerImagePuller     = (*container.ComputeOrchestrator)(nil)
	_ containerImageVerifier   = (*container.ComputeOrchestrator)(nil)
)

// richCapableMockOrchestrator extends grpcMockOrchestrator with the full set
// of rich container capability verbs the consolidated
// container.ComputeOrchestrator exposes.
type richCapableMockOrchestrator struct {
	*grpcMockOrchestrator
	logsFunc       func(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error)
	attestFunc     func(ctx context.Context, id string) (*container.AttestationReport, error)
	verifyFunc     func(ctx context.Context, id string, evidence []byte) error
	evaluateFunc   func(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error)
	pullFunc       func(ctx context.Context, ref string, opts container.PullOptions) error
	verifyImgFunc  func(ctx context.Context, ref string) (*container.ImageVerification, error)
	logsCalls      int
	attestCalls    int
	verifyCalls    int
	evaluateCalls  int
	pullCalls      int
	verifyImgCalls int
}

func newRichCapableMockOrchestrator() *richCapableMockOrchestrator {
	return &richCapableMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
}

func (m *richCapableMockOrchestrator) Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
	m.logsCalls++
	if m.logsFunc != nil {
		return m.logsFunc(ctx, id, opts)
	}
	return io.NopCloser(strings.NewReader("container log line\n")), nil
}

func (m *richCapableMockOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	m.attestCalls++
	if m.attestFunc != nil {
		return m.attestFunc(ctx, id)
	}
	return &container.AttestationReport{
		ContainerID:   id,
		ContainerName: "rich-container",
		Timestamp:     time.Now(),
		Quote:         []byte("quote"),
		Signature:     []byte("signature"),
		ImageDigest:   "image-digest",
		ConfigDigest:  "config-digest",
		Verified:      true,
		PCRValues:     map[int][]byte{14: []byte("pcr-14")},
	}, nil
}

func (m *richCapableMockOrchestrator) VerifyAttestation(ctx context.Context, id string, evidence []byte) error {
	m.verifyCalls++
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, id, evidence)
	}
	return nil
}

func (m *richCapableMockOrchestrator) EvaluatePolicy(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.PolicyDecision, error) {
	m.evaluateCalls++
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, spec)
	}
	return &container.PolicyDecision{Allowed: true, Timestamp: time.Now()}, nil
}

func (m *richCapableMockOrchestrator) PullImage(ctx context.Context, ref string, opts container.PullOptions) error {
	m.pullCalls++
	if m.pullFunc != nil {
		return m.pullFunc(ctx, ref, opts)
	}
	return nil
}

func (m *richCapableMockOrchestrator) VerifyImage(ctx context.Context, ref string) (*container.ImageVerification, error) {
	m.verifyImgCalls++
	if m.verifyImgFunc != nil {
		return m.verifyImgFunc(ctx, ref)
	}
	return &container.ImageVerification{ImageRef: ref, Verified: true, Timestamp: time.Now()}, nil
}

// =============================================================================
// OrchestratorAdapter capability forwarding
// =============================================================================

func TestOrchestratorAdapter_CapabilityForwarding(t *testing.T) {
	ctx := context.Background()

	t.Run("forwards rich capabilities to capable orchestrator", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		adapter, err := NewOrchestratorAdapter(orchestrator)
		require.NoError(t, err)

		reader, err := adapter.Logs(ctx, "container-1", container.LogOptions{Stdout: true})
		require.NoError(t, err)
		reader.Close()
		assert.Equal(t, 1, orchestrator.logsCalls)

		report, err := adapter.Attest(ctx, "container-1")
		require.NoError(t, err)
		assert.Equal(t, "container-1", report.ContainerID)
		assert.Equal(t, 1, orchestrator.attestCalls)

		require.NoError(t, adapter.VerifyAttestation(ctx, "container-1", []byte("evidence")))
		assert.Equal(t, 1, orchestrator.verifyCalls)

		decision, err := adapter.EvaluatePolicy(ctx, &container.OrchestratorContainerSpec{Name: "c", Image: "img"})
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
		assert.Equal(t, 1, orchestrator.evaluateCalls)

		require.NoError(t, adapter.PullImage(ctx, "busybox:latest", container.PullOptions{}))
		assert.Equal(t, 1, orchestrator.pullCalls)

		verification, err := adapter.VerifyImage(ctx, "busybox:latest")
		require.NoError(t, err)
		assert.True(t, verification.Verified)
		assert.Equal(t, 1, orchestrator.verifyImgCalls)
	})

	t.Run("returns typed capability errors for plain orchestrator", func(t *testing.T) {
		adapter, err := NewOrchestratorAdapter(newGRPCMockOrchestrator())
		require.NoError(t, err)

		_, err = adapter.Logs(ctx, "container-1", container.LogOptions{})
		assert.ErrorAs(t, err, &ErrLogsNotSupported{})

		_, err = adapter.Attest(ctx, "container-1")
		assert.ErrorAs(t, err, &ErrAttestNotSupported{})

		err = adapter.VerifyAttestation(ctx, "container-1", nil)
		assert.ErrorAs(t, err, &ErrVerifyAttestationNotSupported{})

		_, err = adapter.EvaluatePolicy(ctx, &container.OrchestratorContainerSpec{Name: "c", Image: "img"})
		assert.ErrorAs(t, err, &ErrEvaluatePolicyNotSupported{})

		err = adapter.PullImage(ctx, "busybox:latest", container.PullOptions{})
		assert.ErrorAs(t, err, &ErrPullImageNotSupported{})

		_, err = adapter.VerifyImage(ctx, "busybox:latest")
		assert.ErrorAs(t, err, &ErrVerifyImageNotSupported{})
	})

	t.Run("validates arguments before forwarding", func(t *testing.T) {
		adapter, err := NewOrchestratorAdapter(newRichCapableMockOrchestrator())
		require.NoError(t, err)

		_, err = adapter.Logs(ctx, "", container.LogOptions{})
		assert.ErrorIs(t, err, container.ErrInvalidContainerID)

		_, err = adapter.Attest(ctx, "")
		assert.ErrorIs(t, err, container.ErrInvalidContainerID)

		err = adapter.PullImage(ctx, "", container.PullOptions{})
		assert.ErrorIs(t, err, container.ErrInvalidImage)
	})
}

// =============================================================================
// MCP provider container attest
// =============================================================================

func TestMCPServiceProvider_ContainerAttest(t *testing.T) {
	ctx := context.Background()

	t.Run("returns hex-encoded attestation report", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: orchestrator})

		result, err := provider.ContainerAttest(ctx, "container-1")

		require.NoError(t, err)
		report, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "container-1", report["container_id"])
		assert.Equal(t, "rich-container", report["container_name"])
		assert.Equal(t, encodeHex([]byte("quote")), report["quote"])
		assert.Equal(t, true, report["verified"])
		pcrValues, ok := report["pcr_values"].(map[string]string)
		require.True(t, ok)
		assert.Equal(t, encodeHex([]byte("pcr-14")), pcrValues["14"])
		assert.Equal(t, 1, orchestrator.attestCalls)
	})

	t.Run("returns error when orchestrator missing", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

		_, err := provider.ContainerAttest(ctx, "container-1")

		assert.ErrorAs(t, err, &ErrContainerServiceNotAvailable{})
	})

	t.Run("requires container ID", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: newRichCapableMockOrchestrator()})

		_, err := provider.ContainerAttest(ctx, "")

		var target ErrContainerInvalidParameter
		assert.ErrorAs(t, err, &target)
	})

	t.Run("returns typed error when orchestrator lacks attest capability", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: newGRPCMockOrchestrator()})

		_, err := provider.ContainerAttest(ctx, "container-1")

		assert.ErrorAs(t, err, &ErrContainerAttestNotSupported{})
	})

	t.Run("wraps orchestrator attest failure", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		orchestrator.attestFunc = func(ctx context.Context, id string) (*container.AttestationReport, error) {
			return nil, errors.New("attest failed")
		}
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: orchestrator})

		_, err := provider.ContainerAttest(ctx, "container-1")

		var target ErrContainerOperationFailed
		assert.ErrorAs(t, err, &target)
	})
}

// =============================================================================
// QUIC compute extended category container sub-opcode routing
// =============================================================================

func TestQUICComputeExtendedCategory_ContainerSubOpcodes(t *testing.T) {
	ctx := context.Background()

	newHandlerWithContainers := func(t *testing.T) (*QUICServiceHandler, *richCapableMockOrchestrator) {
		t.Helper()
		orchestrator := newRichCapableMockOrchestrator()
		adapter, err := NewOrchestratorAdapter(orchestrator)
		require.NoError(t, err)

		handler := newTestQUICServiceHandler(logging.DefaultLogger())
		handler.SetContainerOrchestrator(adapter)
		return handler, orchestrator
	}

	t.Run("routes container attest sub-opcode to container handler", func(t *testing.T) {
		handler, orchestrator := newHandlerWithContainers(t)

		inner, err := quicwire.EncodePayload(&quic.ContainerAttestRequest{ID: "container-1"})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: append([]byte{quicwire.OpContainerAttest}, inner...),
		})

		require.NotNil(t, resp)
		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, 1, orchestrator.attestCalls)

		var attestResp quic.ContainerAttestResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &attestResp))
		assert.Equal(t, "container-1", attestResp.ContainerID)
		assert.True(t, attestResp.Verified)
	})

	t.Run("returns unavailable when container handler missing", func(t *testing.T) {
		handler := newTestQUICServiceHandler(logging.DefaultLogger())

		inner, err := quicwire.EncodePayload(&quic.ContainerAttestRequest{ID: "container-1"})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: append([]byte{quicwire.OpContainerAttest}, inner...),
		})

		require.NotNil(t, resp)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})

	t.Run("non-container sub-opcodes route to the VM path", func(t *testing.T) {
		handler, _ := newHandlerWithContainers(t)

		// OpVMRestart (0xB6) is a VM sub-opcode. With no compute service
		// wired, the dispatcher must report the VM service unavailable
		// rather than routing to the container handler.
		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: []byte{quicwire.OpVMRestart},
		})

		require.NotNil(t, resp)
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
	})
}

func TestIsContainerSubOpcode(t *testing.T) {
	t.Run("accepts all container opcodes", func(t *testing.T) {
		for _, op := range []byte{
			quicwire.OpContainerCreate, quicwire.OpContainerStart, quicwire.OpContainerStop,
			quicwire.OpContainerRemove, quicwire.OpContainerGet, quicwire.OpContainerList,
			quicwire.OpContainerAttest,
		} {
			assert.True(t, quic.IsContainerSubOpcode(op), "opcode 0x%02X", op)
		}
	})

	t.Run("rejects VM extended sub-opcodes", func(t *testing.T) {
		assert.False(t, quic.IsContainerSubOpcode(quicwire.OpVMRestart))
		assert.False(t, quic.IsContainerSubOpcode(quicwire.OpVMMetrics))
	})
}
