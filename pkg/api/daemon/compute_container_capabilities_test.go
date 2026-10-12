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
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Compile-time proofs that the production consolidated orchestrator
// (container.ComputeOrchestrator) satisfies every capability interface the
// daemon RPC layer type-asserts on the compute.Orchestrator value. If any
// of these break, AttestContainer / GetContainerLogs / the adapter
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

// mockLogEntryStream is a mock gRPC server stream for LogEntry messages.
type mockLogEntryStream struct {
	grpc.ServerStream
	ctx     context.Context
	entries []*platformv1.LogEntry
	sendErr error
}

func newMockLogEntryStream(ctx context.Context) *mockLogEntryStream {
	return &mockLogEntryStream{ctx: ctx}
}

func (s *mockLogEntryStream) Context() context.Context {
	return s.ctx
}

func (s *mockLogEntryStream) Send(entry *platformv1.LogEntry) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.entries = append(s.entries, entry)
	return nil
}

// =============================================================================
// gRPC GetContainerLogs streaming
// =============================================================================

func TestComputeGRPCService_GetContainerLogs(t *testing.T) {
	ctx := context.Background()

	t.Run("streams log entries from rich orchestrator", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)
		stream := newMockLogEntryStream(ctx)

		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "container-1"}, stream)

		require.NoError(t, err)
		require.Len(t, stream.entries, 1)
		assert.Equal(t, "container log line\n", stream.entries[0].GetMessage())
		assert.Equal(t, "container-1", stream.entries[0].GetSource())
		assert.Equal(t, 1, orchestrator.logsCalls)
	})

	t.Run("defaults to both stdout and stderr", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		var captured container.LogOptions
		orchestrator.logsFunc = func(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
			captured = opts
			return io.NopCloser(bytes.NewReader(nil)), nil
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "container-1"}, newMockLogEntryStream(ctx))

		require.NoError(t, err)
		assert.True(t, captured.Stdout)
		assert.True(t, captured.Stderr)
	})

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "container-1"}, newMockLogEntryStream(ctx))

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("maps not-found error", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		orchestrator.logsFunc = func(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
			return nil, container.ErrContainerNotFound
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "missing"}, newMockLogEntryStream(ctx))

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})

	t.Run("maps stream send failure to internal error", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)
		stream := newMockLogEntryStream(ctx)
		stream.sendErr = errors.New("stream broken")

		err := svc.GetContainerLogs(&platformv1.GetContainerLogsRequest{Id: "container-1"}, stream)

		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
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
// MCP provider container logs + attest
// =============================================================================

func TestMCPServiceProvider_ContainerLogs(t *testing.T) {
	ctx := context.Background()

	t.Run("returns log snapshot from rich orchestrator", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: orchestrator})

		logs, err := provider.ContainerLogs(ctx, "container-1", false, true, true, "", false)

		require.NoError(t, err)
		assert.Equal(t, "container log line\n", logs)
		assert.Equal(t, 1, orchestrator.logsCalls)
	})

	t.Run("returns error when orchestrator missing", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

		_, err := provider.ContainerLogs(ctx, "container-1", false, true, true, "", false)

		assert.ErrorAs(t, err, &ErrContainerServiceNotAvailable{})
	})

	t.Run("requires container ID", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: newRichCapableMockOrchestrator()})

		_, err := provider.ContainerLogs(ctx, "", false, true, true, "", false)

		var target ErrContainerInvalidParameter
		assert.ErrorAs(t, err, &target)
	})

	t.Run("returns typed error when orchestrator lacks log capability", func(t *testing.T) {
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: newGRPCMockOrchestrator()})

		_, err := provider.ContainerLogs(ctx, "container-1", false, true, true, "", false)

		assert.ErrorAs(t, err, &ErrContainerLogsNotSupported{})
	})

	t.Run("wraps orchestrator log failure", func(t *testing.T) {
		orchestrator := newRichCapableMockOrchestrator()
		orchestrator.logsFunc = func(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error) {
			return nil, errors.New("logs failed")
		}
		provider := NewMCPServiceProvider(&MCPServiceProviderConfig{ComputeOrchestrator: orchestrator})

		_, err := provider.ContainerLogs(ctx, "container-1", false, true, true, "", false)

		var target ErrContainerOperationFailed
		assert.ErrorAs(t, err, &target)
	})
}

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

	t.Run("routes container logs sub-opcode to container handler", func(t *testing.T) {
		handler, orchestrator := newHandlerWithContainers(t)

		inner, err := quicwire.EncodePayload(&quic.ContainerLogsRequest{ID: "container-1", Stdout: true, Stderr: true})
		require.NoError(t, err)

		resp := handler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  quicwire.OpVMExtendedCategory,
			Payload: append([]byte{quicwire.OpContainerLogs}, inner...),
		})

		require.NotNil(t, resp)
		assert.Equal(t, quicwire.StatusOK, resp.Status)
		assert.Equal(t, 1, orchestrator.logsCalls)

		var logsResp quic.ContainerLogsResponse
		require.NoError(t, quicwire.DecodePayload(resp.Payload, &logsResp))
		assert.Equal(t, "container log line\n", string(logsResp.Logs))
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

	t.Run("non-container sub-opcodes fall through to VM handler", func(t *testing.T) {
		handler, _ := newHandlerWithContainers(t)

		// OpVMRestart (0xB6) is a VM extended sub-opcode. With no VM
		// handler configured, the dispatcher must report the VM service
		// unavailable rather than routing to the container handler.
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
			quicwire.OpContainerLogs, quicwire.OpContainerAttest,
		} {
			assert.True(t, quic.IsContainerSubOpcode(op), "opcode 0x%02X", op)
		}
	})

	t.Run("rejects VM extended sub-opcodes", func(t *testing.T) {
		assert.False(t, quic.IsContainerSubOpcode(quicwire.OpVMRestart))
		assert.False(t, quic.IsContainerSubOpcode(quicwire.OpVMSnapshotList))
	})
}
