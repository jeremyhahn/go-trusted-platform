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
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// vmCapableMockOrchestrator extends grpcMockOrchestrator with the canonical
// VM snapshot and attestation capabilities.
type vmCapableMockOrchestrator struct {
	*grpcMockOrchestrator

	createSnapshotErr error
	restoreErr        error
	deleteErr         error
	listErr           error
	attestErr         error
	verifyErr         error

	snapshots []*compute.VMSnapshot

	// mu guards the recorded call arguments below: the QUIC transport
	// records them on its server goroutine while the test reads them.
	mu              sync.Mutex
	lastAttestNonce []byte
	lastAttestPCRs  []int
	lastEvidence    *compute.VMAttestationEvidence
}

var (
	_ compute.VMSnapshotter = (*vmCapableMockOrchestrator)(nil)
	_ compute.VMAttester    = (*vmCapableMockOrchestrator)(nil)
)

func newVMCapableMockOrchestrator() *vmCapableMockOrchestrator {
	return &vmCapableMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
}

func (m *vmCapableMockOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*compute.VMSnapshot, error) {
	if m.createSnapshotErr != nil {
		return nil, m.createSnapshotErr
	}
	snapshot := &compute.VMSnapshot{
		Name:      snapshotName,
		VMID:      instanceID,
		CreatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		SizeBytes: 4096,
	}
	m.snapshots = append(m.snapshots, snapshot)
	return snapshot, nil
}

func (m *vmCapableMockOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	return m.restoreErr
}

func (m *vmCapableMockOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	return m.deleteErr
}

func (m *vmCapableMockOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*compute.VMSnapshot, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.snapshots, nil
}

func (m *vmCapableMockOrchestrator) AttestVM(ctx context.Context, instanceID string, nonce []byte, pcrIndices []int) (*compute.VMAttestationReport, error) {
	if m.attestErr != nil {
		return nil, m.attestErr
	}
	m.mu.Lock()
	m.lastAttestNonce = nonce
	m.lastAttestPCRs = pcrIndices
	m.mu.Unlock()
	return &compute.VMAttestationReport{
		VMID:      instanceID,
		VMName:    "test-vm",
		Timestamp: time.Now(),
		Nonce:     nonce,
		PCRValues: map[int][]byte{
			0: {0x01},
			7: {0x07},
		},
		Quote:              []byte("quote-bytes"),
		Signature:          []byte("signature-bytes"),
		SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		AKPublicKey:        []byte("ak-public"),
	}, nil
}

func (m *vmCapableMockOrchestrator) VerifyVMAttestation(ctx context.Context, instanceID string, evidence *compute.VMAttestationEvidence) (*compute.VMVerificationResult, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	m.mu.Lock()
	m.lastEvidence = evidence
	m.mu.Unlock()
	return &compute.VMVerificationResult{
		Verified:       true,
		SignatureValid: true,
		NonceValid:     true,
		PCRsValid:      true,
		Message:        "attestation verified",
		ActualPCRs:     map[int][]byte{0: {0x01}},
	}, nil
}

// recordedAttestNonce returns the nonce of the last AttestVM call.
func (m *vmCapableMockOrchestrator) recordedAttestNonce() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastAttestNonce
}

// recordedAttestPCRs returns the PCR indices of the last AttestVM call.
func (m *vmCapableMockOrchestrator) recordedAttestPCRs() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastAttestPCRs
}

// recordedEvidence returns the evidence of the last VerifyVMAttestation call.
func (m *vmCapableMockOrchestrator) recordedEvidence() *compute.VMAttestationEvidence {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastEvidence
}

func newVMCapableComputeService() (*ComputeGRPCService, *vmCapableMockOrchestrator) {
	orchestrator := newVMCapableMockOrchestrator()
	return NewComputeGRPCService(logging.DefaultLogger(), orchestrator), orchestrator
}

func assertStatusCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, code, st.Code())
}

// =============================================================================
// CreateSnapshot
// =============================================================================

func TestComputeGRPCService_CreateSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("nil orchestrator", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("orchestrator without snapshot capability", func(t *testing.T) {
		svc := createTestComputeService(t)
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId:   "vm1",
			Config: &platformv1.SnapshotConfig{Name: "snap1"},
		})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			Config: &platformv1.SnapshotConfig{Name: "snap1"},
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("missing snapshot name", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("partial snapshot flags rejected", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId: "vm1",
			Config: &platformv1.SnapshotConfig{
				Name:         "snap1",
				DiskSnapshot: true, // memory_snapshot false
			},
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		resp, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId: "vm1",
			Config: &platformv1.SnapshotConfig{
				Name:           "snap1",
				Description:    "test snapshot",
				MemorySnapshot: true,
				DiskSnapshot:   true,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, "snap1", resp.GetSnapshot().GetId())
		assert.Equal(t, "vm1", resp.GetSnapshot().GetVmId())
		assert.Equal(t, uint64(4096), resp.GetSnapshot().GetSizeBytes())
		assert.True(t, resp.GetSnapshot().GetConfig().GetMemorySnapshot())
		assert.True(t, resp.GetSnapshot().GetConfig().GetDiskSnapshot())
		assert.Equal(t, "test snapshot", resp.GetSnapshot().GetConfig().GetDescription())
		require.Len(t, orchestrator.snapshots, 1)
	})

	t.Run("stopped VM maps to FailedPrecondition", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.createSnapshotErr = compute.ErrInstanceNotRunning
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId:   "vm1",
			Config: &platformv1.SnapshotConfig{Name: "snap1"},
		})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("non-qcow2 disk maps to FailedPrecondition", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.createSnapshotErr = compute.ErrUnsupportedDiskFormat
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId:   "vm1",
			Config: &platformv1.SnapshotConfig{Name: "snap1"},
		})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("invalid snapshot name maps to InvalidArgument", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.createSnapshotErr = compute.ErrInvalidSnapshotName
		_, err := svc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{
			VmId:   "vm1",
			Config: &platformv1.SnapshotConfig{Name: "snap1"},
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})
}

// =============================================================================
// RestoreSnapshot / DeleteSnapshot / ListSnapshots
// =============================================================================

func TestComputeGRPCService_RestoreSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		resp, err := svc.RestoreSnapshot(ctx, &platformv1.RestoreSnapshotRequest{
			VmId:       "vm1",
			SnapshotId: "snap1",
		})
		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("missing snapshot ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.RestoreSnapshot(ctx, &platformv1.RestoreSnapshotRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("snapshot not found maps to NotFound", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.restoreErr = compute.ErrSnapshotNotFound
		_, err := svc.RestoreSnapshot(ctx, &platformv1.RestoreSnapshotRequest{
			VmId:       "vm1",
			SnapshotId: "missing",
		})
		assertStatusCode(t, err, codes.NotFound)
	})

	t.Run("capability missing", func(t *testing.T) {
		svc := createTestComputeService(t)
		_, err := svc.RestoreSnapshot(ctx, &platformv1.RestoreSnapshotRequest{
			VmId:       "vm1",
			SnapshotId: "snap1",
		})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})
}

func TestComputeGRPCService_DeleteSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		resp, err := svc.DeleteSnapshot(ctx, &platformv1.DeleteSnapshotRequest{
			VmId:       "vm1",
			SnapshotId: "snap1",
		})
		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.DeleteSnapshot(ctx, &platformv1.DeleteSnapshotRequest{SnapshotId: "snap1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("VM not found maps to NotFound", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.deleteErr = compute.ErrInstanceNotFound
		_, err := svc.DeleteSnapshot(ctx, &platformv1.DeleteSnapshotRequest{
			VmId:       "missing",
			SnapshotId: "snap1",
		})
		assertStatusCode(t, err, codes.NotFound)
	})
}

func TestComputeGRPCService_ListSnapshots(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.snapshots = []*compute.VMSnapshot{
			{Name: "snap1", VMID: "vm1", SizeBytes: 100},
			{Name: "snap2", VMID: "vm1", SizeBytes: 200},
		}

		resp, err := svc.ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{VmId: "vm1"})
		require.NoError(t, err)
		require.Len(t, resp.GetSnapshots(), 2)
		assert.Equal(t, "snap1", resp.GetSnapshots()[0].GetId())
		assert.Equal(t, "snap2", resp.GetSnapshots()[1].GetId())
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("stopped VM maps to FailedPrecondition", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.listErr = compute.ErrInstanceNotRunning
		_, err := svc.ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})
}

func TestComputeGRPCService_GetSnapshot(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.snapshots = []*compute.VMSnapshot{
			{Name: "snap1", VMID: "vm1", SizeBytes: 100},
			{Name: "snap2", VMID: "vm1", SizeBytes: 200, Description: "nightly"},
		}

		resp, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{VmId: "vm1", SnapshotId: "snap2"})
		require.NoError(t, err)
		assert.Equal(t, "snap2", resp.GetSnapshot().GetId())
		assert.Equal(t, uint64(200), resp.GetSnapshot().GetSizeBytes())
		assert.Equal(t, "nightly", resp.GetSnapshot().GetConfig().GetDescription())
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{SnapshotId: "snap1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("missing snapshot ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("unknown snapshot maps to NotFound", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.snapshots = []*compute.VMSnapshot{{Name: "snap1", VMID: "vm1"}}
		_, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{VmId: "vm1", SnapshotId: "snap9"})
		require.ErrorAs(t, err, &ErrVMSnapshotNotFound{})
		assertStatusCode(t, err, codes.NotFound)
	})

	t.Run("list failure keeps its class", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.listErr = compute.ErrInstanceNotRunning
		_, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{VmId: "vm1", SnapshotId: "snap1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("nil orchestrator", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)
		_, err := svc.GetSnapshot(ctx, &platformv1.GetSnapshotRequest{VmId: "vm1", SnapshotId: "snap1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})
}

// =============================================================================
// AttestVM / VerifyVMAttestation
// =============================================================================

func TestComputeGRPCService_AttestVM(t *testing.T) {
	ctx := context.Background()

	t.Run("nil orchestrator", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("orchestrator without attest capability", func(t *testing.T) {
		svc := createTestComputeService(t)
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("unsupported PCR bank rejected", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{
			VmId:    "vm1",
			PcrBank: platformv1.PCRBank_PCR_BANK_SHA1,
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("PCR index out of range rejected", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{
			VmId:       "vm1",
			PcrIndices: []uint32{24},
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("success", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		resp, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{
			VmId:       "vm1",
			Nonce:      []byte("nonce"),
			PcrIndices: []uint32{0, 7},
			PcrBank:    platformv1.PCRBank_PCR_BANK_SHA256,
		})
		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, []byte("quote-bytes"), resp.GetQuote())
		assert.Equal(t, []byte("signature-bytes"), resp.GetSignature())
		assert.Equal(t, x509.SHA256WithRSAPSS.String(), resp.GetSignatureAlgorithm())
		assert.Equal(t, []byte("ak-public"), resp.GetAkPublic())
		require.Len(t, resp.GetPcrValues(), 2)
		assert.Equal(t, uint32(0), resp.GetPcrValues()[0].GetIndex())
		assert.Equal(t, platformv1.PCRBank_PCR_BANK_SHA256, resp.GetPcrValues()[0].GetBank())
		assert.Equal(t, []byte("nonce"), orchestrator.recordedAttestNonce())
		assert.Equal(t, []int{0, 7}, orchestrator.recordedAttestPCRs())
	})

	t.Run("TPM-less instance maps to FailedPrecondition", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.attestErr = compute.ErrVTPMNotAvailable
		_, err := svc.AttestVM(ctx, &platformv1.AttestVMRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})
}

func TestComputeGRPCService_VerifyVMAttestation(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		resp, err := svc.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{
			VmId:               "vm1",
			Quote:              []byte("quote"),
			Signature:          []byte("signature"),
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
			Nonce:              []byte("nonce"),
			ExpectedPcrs: []*platformv1.PCRValue{
				{Index: 0, Bank: platformv1.PCRBank_PCR_BANK_SHA256, Value: []byte{0x01}},
			},
		})
		require.NoError(t, err)
		assert.True(t, resp.GetVerified())
		assert.Equal(t, "attestation verified", resp.GetMessage())
		require.Len(t, resp.GetActualPcrs(), 1)

		require.NotNil(t, orchestrator.recordedEvidence())
		assert.Equal(t, []byte("quote"), orchestrator.recordedEvidence().Quote)
		assert.Equal(t, x509.SHA256WithRSAPSS.String(), orchestrator.recordedEvidence().SignatureAlgorithm)
		assert.Equal(t, []byte{0x01}, orchestrator.recordedEvidence().ExpectedPCRs[0])
	})

	t.Run("missing VM ID", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("unsupported expected PCR bank rejected", func(t *testing.T) {
		svc, _ := newVMCapableComputeService()
		_, err := svc.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{
			VmId: "vm1",
			ExpectedPcrs: []*platformv1.PCRValue{
				{Index: 0, Bank: platformv1.PCRBank_PCR_BANK_SHA1, Value: []byte{0x01}},
			},
		})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("invalid evidence maps to InvalidArgument", func(t *testing.T) {
		svc, orchestrator := newVMCapableComputeService()
		orchestrator.verifyErr = compute.ErrInvalidAttestationEvidence
		_, err := svc.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("capability missing", func(t *testing.T) {
		svc := createTestComputeService(t)
		_, err := svc.VerifyVMAttestation(ctx, &platformv1.VerifyVMAttestationRequest{VmId: "vm1"})
		assertStatusCode(t, err, codes.FailedPrecondition)
	})
}
