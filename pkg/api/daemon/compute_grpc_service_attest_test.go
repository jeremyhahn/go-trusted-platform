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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// attestingMockOrchestrator extends grpcMockOrchestrator with the Attest verb
// so tests can exercise the containerAttester capability path.
type attestingMockOrchestrator struct {
	*grpcMockOrchestrator
	attestFunc  func(ctx context.Context, id string) (*container.AttestationReport, error)
	attestCalls int
}

func (m *attestingMockOrchestrator) Attest(ctx context.Context, id string) (*container.AttestationReport, error) {
	m.attestCalls++
	if m.attestFunc != nil {
		return m.attestFunc(ctx, id)
	}
	return &container.AttestationReport{
		ContainerID:   id,
		ContainerName: "test-container",
		Timestamp:     time.Now(),
		Quote:         []byte("test-quote"),
		Signature:     []byte("test-signature"),
		ConfigDigest:  "config-digest",
		Verified:      true,
		PCRValues: map[int][]byte{
			14: []byte("pcr-14-value"),
		},
	}, nil
}

func TestComputeGRPCService_AttestContainer(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when orchestrator not initialized", func(t *testing.T) {
		svc := createTestComputeServiceNoOrchestrator(t)

		resp, err := svc.AttestContainer(ctx, &platformv1.AttestContainerRequest{Id: "container-1"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("returns error when container ID missing", func(t *testing.T) {
		svc := createTestComputeService(t)

		resp, err := svc.AttestContainer(ctx, &platformv1.AttestContainerRequest{})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("returns unimplemented when orchestrator lacks attest capability", func(t *testing.T) {
		svc := NewComputeGRPCService(logging.DefaultLogger(), newGRPCMockOrchestrator())

		resp, err := svc.AttestContainer(ctx, &platformv1.AttestContainerRequest{Id: "container-1"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("returns quote-based report from attesting orchestrator", func(t *testing.T) {
		orchestrator := &attestingMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		resp, err := svc.AttestContainer(ctx, &platformv1.AttestContainerRequest{
			Id:      "container-1",
			PcrBank: platformv1.PCRBank_PCR_BANK_SHA256,
		})

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, 1, orchestrator.attestCalls)
		assert.Equal(t, "container-1", resp.GetContainerId())
		assert.Equal(t, "test-container", resp.GetContainerName())
		assert.Equal(t, []byte("test-quote"), resp.GetQuote())
		assert.Equal(t, []byte("test-signature"), resp.GetSignature())
		assert.Equal(t, []byte("config-digest"), resp.GetConfigDigest())
		assert.True(t, resp.GetVerified())
		require.Len(t, resp.GetPcrValues(), 1)
		assert.Equal(t, uint32(14), resp.GetPcrValues()[0].GetIndex())
		assert.Equal(t, platformv1.PCRBank_PCR_BANK_SHA256, resp.GetPcrValues()[0].GetBank())
	})

	t.Run("maps orchestrator attest failure to internal error", func(t *testing.T) {
		orchestrator := &attestingMockOrchestrator{
			grpcMockOrchestrator: newGRPCMockOrchestrator(),
			attestFunc: func(ctx context.Context, id string) (*container.AttestationReport, error) {
				return nil, errors.New("attest failed")
			},
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		resp, err := svc.AttestContainer(ctx, &platformv1.AttestContainerRequest{Id: "container-1"})

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
	})
}

func TestComputeGRPCService_CreateContainerAttestOnCreate(t *testing.T) {
	ctx := context.Background()

	validReq := func(attest bool) *platformv1.CreateContainerRequest {
		return &platformv1.CreateContainerRequest{
			Config: &platformv1.ContainerConfig{
				Name:  "attested",
				Image: "alpine:latest",
			},
			AttestOnCreate: attest,
		}
	}

	t.Run("attests container after creation when requested", func(t *testing.T) {
		orchestrator := &attestingMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		resp, err := svc.CreateContainer(ctx, validReq(true))

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, 1, orchestrator.attestCalls)
	})

	t.Run("does not attest when not requested", func(t *testing.T) {
		orchestrator := &attestingMockOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		resp, err := svc.CreateContainer(ctx, validReq(false))

		require.NoError(t, err)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, 0, orchestrator.attestCalls)
	})

	t.Run("returns unimplemented when orchestrator lacks attest capability", func(t *testing.T) {
		svc := NewComputeGRPCService(logging.DefaultLogger(), newGRPCMockOrchestrator())

		resp, err := svc.CreateContainer(ctx, validReq(true))

		assert.Nil(t, resp)
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unimplemented, st.Code())
	})

	t.Run("reports attestation failure in status", func(t *testing.T) {
		orchestrator := &attestingMockOrchestrator{
			grpcMockOrchestrator: newGRPCMockOrchestrator(),
			attestFunc: func(ctx context.Context, id string) (*container.AttestationReport, error) {
				return nil, errors.New("attest failed")
			},
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		resp, err := svc.CreateContainer(ctx, validReq(true))

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.False(t, resp.GetStatus().GetSuccess())
		assert.Contains(t, resp.GetStatus().GetMessage(), "attestation failed")
		assert.NotNil(t, resp.GetContainer())
	})
}

func TestComputeGRPCService_ListContainersNameFilter(t *testing.T) {
	ctx := context.Background()

	t.Run("passes name filter to instance filter", func(t *testing.T) {
		orchestrator := newGRPCMockOrchestrator()
		var captured *compute.InstanceFilter
		orchestrator.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
			captured = filter
			return nil, nil
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		_, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{NameFilter: "web"})

		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, "web", captured.Name)
		require.NotNil(t, captured.Type)
		assert.Equal(t, compute.ComputeTypeContainer, *captured.Type)
	})

	t.Run("leaves name filter empty when not provided", func(t *testing.T) {
		orchestrator := newGRPCMockOrchestrator()
		var captured *compute.InstanceFilter
		orchestrator.listFunc = func(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
			captured = filter
			return nil, nil
		}
		svc := NewComputeGRPCService(logging.DefaultLogger(), orchestrator)

		_, err := svc.ListContainers(ctx, &platformv1.ListContainersRequest{})

		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Empty(t, captured.Name)
	})
}
