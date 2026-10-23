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

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	gatewaysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// fakeGatewayStatusController answers status and mode calls from fixed
// state and records the last mode bitmask it was given.
type fakeGatewayStatusController struct {
	status    *platformv1.GatewayStatus
	err       error
	lastModes uint32
}

func (f *fakeGatewayStatusController) GetGatewayStatus(_ context.Context, _ *platformv1.GetGatewayStatusRequest) (*platformv1.GetGatewayStatusResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.GetGatewayStatusResponse{Status: f.status}, nil
}

func (f *fakeGatewayStatusController) SetGatewayMode(_ context.Context, req *platformv1.SetGatewayModeRequest) (*platformv1.SetGatewayModeResponse, error) {
	f.lastModes = req.GetModes()
	if f.err != nil {
		return nil, f.err
	}
	f.status.Modes = req.GetModes()
	return &platformv1.SetGatewayModeResponse{GatewayStatus: f.status}, nil
}

var gatewayStatusStartedAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newFakeGatewayStatusController() *fakeGatewayStatusController {
	return &fakeGatewayStatusController{status: &platformv1.GatewayStatus{
		Id:            "gw-1",
		NodeId:        "node-1",
		Modes:         quicwire.GatewayModeOverlay,
		Tier:          "edge",
		Reputation:    0.75,
		UptimeSeconds: 42,
		Healthy:       true,
		StartedAt:     timestamppb.New(gatewayStatusStartedAt),
	}}
}

func TestGatewayStatusQUICAdapter_Status(t *testing.T) {
	ctx := context.Background()

	t.Run("converts the gRPC status", func(t *testing.T) {
		adapter := gatewayStatusQUICAdapter{controller: newFakeGatewayStatusController()}

		info, err := adapter.Status(ctx)

		require.NoError(t, err)
		assert.Equal(t, &quic.GatewayStatusInfo{
			ID:            "gw-1",
			NodeID:        "node-1",
			Modes:         quicwire.GatewayModeOverlay,
			Tier:          "edge",
			Reputation:    0.75,
			UptimeSeconds: 42,
			Healthy:       true,
			StartedAt:     gatewayStatusStartedAt.Unix(),
		}, info)
	})

	t.Run("no controller is not configured", func(t *testing.T) {
		_, err := gatewayStatusQUICAdapter{}.Status(ctx)
		assert.ErrorIs(t, err, quic.ErrGatewayFeatureNotConfigured)
	})

	t.Run("a controller error passes through", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		fake.err = status.Error(codes.Unavailable, "no gateway")

		_, err := gatewayStatusQUICAdapter{controller: fake}.Status(ctx)

		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

func TestGatewayStatusQUICAdapter_SetModes(t *testing.T) {
	ctx := context.Background()

	t.Run("sets the bitmask and returns the new status", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		want := quicwire.GatewayModeEdge | quicwire.GatewayModeTransit

		info, err := gatewayStatusQUICAdapter{controller: fake}.SetModes(ctx, want)

		require.NoError(t, err)
		assert.Equal(t, want, fake.lastModes)
		assert.Equal(t, want, info.Modes)
	})

	t.Run("no controller is not configured", func(t *testing.T) {
		_, err := gatewayStatusQUICAdapter{}.SetModes(ctx, quicwire.GatewayModeEdge)
		assert.ErrorIs(t, err, quic.ErrGatewayFeatureNotConfigured)
	})

	t.Run("a controller error passes through", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		fake.err = status.Error(codes.InvalidArgument, "modes is required")

		_, err := gatewayStatusQUICAdapter{controller: fake}.SetModes(ctx, 0)

		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	})
}

func TestProtoGatewayStatusToQUIC(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, protoGatewayStatusToQUIC(nil))
	})

	t.Run("a missing start time is zero", func(t *testing.T) {
		info := protoGatewayStatusToQUIC(&platformv1.GatewayStatus{Id: "gw"})
		assert.Equal(t, "gw", info.ID)
		assert.Zero(t, info.StartedAt)
	})
}

func TestNewGatewayStatusView(t *testing.T) {
	t.Run("spells out the modes", func(t *testing.T) {
		view := newGatewayStatusView(&platformv1.GatewayStatus{
			Id:        "gw",
			Modes:     quicwire.GatewayModesAll,
			StartedAt: timestamppb.New(gatewayStatusStartedAt),
		})
		assert.Equal(t, []string{"overlay", "edge", "transit"}, view.Modes)
		assert.Equal(t, quicwire.GatewayModesAll, view.ModeBitmask)
		require.NotNil(t, view.StartedAt)
		assert.True(t, gatewayStatusStartedAt.Equal(*view.StartedAt))
	})

	t.Run("nil stays nil and a missing start time stays unset", func(t *testing.T) {
		assert.Nil(t, newGatewayStatusView(nil))
		assert.Nil(t, newGatewayStatusView(&platformv1.GatewayStatus{}).StartedAt)
	})
}

func TestGatewayStatusTools_GatewayStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("returns the status view", func(t *testing.T) {
		var tools gatewayStatusTools
		tools.SetGatewayStatusController(newFakeGatewayStatusController())

		out, err := tools.GatewayStatus(ctx)

		require.NoError(t, err)
		view := out.(*gatewayStatusView)
		assert.Equal(t, "gw-1", view.ID)
		assert.Equal(t, []string{"overlay"}, view.Modes)
	})

	t.Run("no controller is service not available", func(t *testing.T) {
		_, err := gatewayStatusTools{}.GatewayStatus(ctx)
		assert.Equal(t, ErrServiceNotAvailable{Service: "gateway"}, err)
	})

	t.Run("a controller error passes through", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		fake.err = status.Error(codes.Unavailable, "no gateway")

		_, err := gatewayStatusTools{controller: fake}.GatewayStatus(ctx)

		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

func TestGatewayStatusTools_GatewayModeSet(t *testing.T) {
	ctx := context.Background()

	t.Run("encodes the names and returns the new status", func(t *testing.T) {
		fake := newFakeGatewayStatusController()

		out, err := gatewayStatusTools{controller: fake}.GatewayModeSet(ctx, []string{"transit", "edge"})

		require.NoError(t, err)
		assert.Equal(t, quicwire.GatewayModeEdge|quicwire.GatewayModeTransit, fake.lastModes)
		assert.Equal(t, []string{"edge", "transit"}, out.(*gatewayStatusView).Modes)
	})

	t.Run("an unknown name is refused before the service", func(t *testing.T) {
		fake := newFakeGatewayStatusController()

		_, err := gatewayStatusTools{controller: fake}.GatewayModeSet(ctx, []string{"edge", "router"})

		var unknown *gatewaysvc.ErrUnknownGatewayMode
		require.True(t, errors.As(err, &unknown), "got %T: %v", err, err)
		assert.Equal(t, "router", unknown.Mode)
		assert.Zero(t, fake.lastModes)
	})

	t.Run("no controller is service not available", func(t *testing.T) {
		_, err := gatewayStatusTools{}.GatewayModeSet(ctx, []string{"edge"})
		assert.Equal(t, ErrServiceNotAvailable{Service: "gateway"}, err)
	})

	t.Run("a controller error passes through", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		fake.err = status.Error(codes.Unavailable, "no gateway")

		_, err := gatewayStatusTools{controller: fake}.GatewayModeSet(ctx, []string{"edge"})

		assert.Equal(t, codes.Unavailable, status.Code(err))
	})
}

// TestGatewayStatus_UnconfiguredServiceParity runs the real gateway gRPC
// service with no in-process gateway through the QUIC adapter and the MCP
// tools: both report it unavailable, as gRPC does.
func TestGatewayStatus_UnconfiguredServiceParity(t *testing.T) {
	ctx := context.Background()
	svc := NewGatewayService()

	_, err := gatewayStatusQUICAdapter{controller: svc}.Status(ctx)
	assert.Equal(t, codes.Unavailable, status.Code(err), "QUIC status")

	_, err = gatewayStatusQUICAdapter{controller: svc}.SetModes(ctx, quicwire.GatewayModeEdge)
	assert.Equal(t, codes.Unavailable, status.Code(err), "QUIC set mode")

	_, err = gatewayStatusTools{controller: svc}.GatewayStatus(ctx)
	assert.Equal(t, codes.Unavailable, status.Code(err), "MCP status")

	_, err = gatewayStatusTools{controller: svc}.GatewayModeSet(ctx, []string{"edge"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "MCP set mode")
}

func newGatewayStatusRESTService(controller GatewayStatusController) *gatewayRESTService {
	svc := newGatewayRESTService(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.SetGatewayStatusController(controller)
	return svc
}

func TestGatewayRESTService_GetGatewayStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("converts the gRPC status", func(t *testing.T) {
		resp, err := newGatewayStatusRESTService(newFakeGatewayStatusController()).GetGatewayStatus(ctx)

		require.NoError(t, err)
		assert.Equal(t, "gw-1", resp.ID)
		assert.Equal(t, "node-1", resp.NodeID)
		assert.Equal(t, quicwire.GatewayModeOverlay, resp.Modes)
		assert.Equal(t, "edge", resp.Tier)
		assert.Equal(t, 0.75, resp.Reputation)
		assert.Equal(t, uint64(42), resp.UptimeSeconds)
		assert.True(t, resp.Healthy)
		assert.True(t, gatewayStatusStartedAt.Equal(resp.StartedAt))
		assert.False(t, resp.Timestamp.IsZero())
	})

	t.Run("no controller is not configured", func(t *testing.T) {
		_, err := newGatewayStatusRESTService(nil).GetGatewayStatus(ctx)
		assert.Equal(t, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway status"}, err)
	})

	t.Run("an unavailable gateway is not configured", func(t *testing.T) {
		_, err := newGatewayStatusRESTService(NewGatewayService()).GetGatewayStatus(ctx)
		assert.Equal(t, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway status"}, err)
	})

	t.Run("any other error passes through", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		fake.err = status.Error(codes.Internal, "broken")

		_, err := newGatewayStatusRESTService(fake).GetGatewayStatus(ctx)

		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestGatewayRESTService_SetGatewayMode(t *testing.T) {
	ctx := context.Background()

	t.Run("sets the bitmask and returns the new status", func(t *testing.T) {
		fake := newFakeGatewayStatusController()
		want := quicwire.GatewayModeEdge | quicwire.GatewayModeTransit

		resp, err := newGatewayStatusRESTService(fake).SetGatewayMode(ctx, want)

		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Equal(t, want, fake.lastModes)
		assert.Equal(t, want, resp.GatewayStatus.Modes)
	})

	t.Run("no controller is not configured", func(t *testing.T) {
		_, err := newGatewayStatusRESTService(nil).SetGatewayMode(ctx, quicwire.GatewayModeEdge)
		assert.Equal(t, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway mode"}, err)
	})

	t.Run("an unavailable gateway is not configured", func(t *testing.T) {
		_, err := newGatewayStatusRESTService(NewGatewayService()).SetGatewayMode(ctx, quicwire.GatewayModeEdge)
		assert.Equal(t, rest.ErrGatewayFeatureNotConfigured{Feature: "gateway mode"}, err)
	})

	t.Run("a refused bitmask is an invalid mode", func(t *testing.T) {
		_, err := newGatewayStatusRESTService(NewGatewayService()).SetGatewayMode(ctx, quicwire.GatewayModeEdge|8)
		assert.Equal(t, rest.ErrInvalidGatewayMode{Mode: quicwire.GatewayModeEdge | 8}, err)
	})
}

func TestProtoGatewayStatusToREST(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, protoGatewayStatusToREST(nil))
	})

	t.Run("a missing start time is zero", func(t *testing.T) {
		resp := protoGatewayStatusToREST(&platformv1.GatewayStatus{Id: "gw"})
		assert.Equal(t, "gw", resp.ID)
		assert.True(t, resp.StartedAt.IsZero())
	})
}
