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

package quic

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// windowGatewayService records the update options the handler builds.
type windowGatewayService struct {
	*testGatewayService
	lastUpdate *UpdateIPAMPoolOptions
}

func (s *windowGatewayService) UpdateIPAMPool(_ context.Context, poolID string, opts *UpdateIPAMPoolOptions) (*IPAMPoolInfo, error) {
	s.lastUpdate = opts
	return &IPAMPoolInfo{ID: poolID, RangeStart: opts.RangeStart, RangeEnd: opts.RangeEnd, Reserved: opts.Reserved}, nil
}

// TestGatewayIPAMWindow_CreateCarriesWindow verifies the create handler
// passes the window to the service.
func TestGatewayIPAMWindow_CreateCarriesWindow(t *testing.T) {
	handler, service := createTestGatewayHandler()
	payload, err := quicwire.EncodePayload(&GatewayCreateIPAMPoolRequest{
		Name: "lab", CIDR: "10.4.9.0/24",
		Reserved: []string{"10.4.9.1/32"}, RangeStart: "10.4.9.50", RangeEnd: "10.4.9.254",
	})
	require.NoError(t, err)

	resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpGatewayCreateIPAMPool, Payload: payload})
	require.Equal(t, quicwire.StatusOK, resp.Status)
	assert.Equal(t, []string{"10.4.9.1/32"}, service.lastCreatePoolOpts.Reserved)
	assert.Equal(t, "10.4.9.50", service.lastCreatePoolOpts.RangeStart)
	assert.Equal(t, "10.4.9.254", service.lastCreatePoolOpts.RangeEnd)
}

// TestGatewayIPAMWindow_UpdateCarriesWindow verifies update_window and the
// window fields reach the service and come back in the response.
func TestGatewayIPAMWindow_UpdateCarriesWindow(t *testing.T) {
	svc := &windowGatewayService{testGatewayService: newTestGatewayService()}
	handler := NewGatewayHandler(newGatewayTestLogger(), svc)
	payload, err := quicwire.EncodePayload(&GatewayUpdateIPAMPoolRequest{
		PoolID: "lab", UpdateWindow: true, RangeStart: "10.4.9.60", RangeEnd: "10.4.9.200",
	})
	require.NoError(t, err)

	resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpGatewayUpdateIPAMPool, Payload: payload})
	require.Equal(t, quicwire.StatusOK, resp.Status)
	require.True(t, svc.lastUpdate.UpdateWindow)
	assert.Equal(t, "10.4.9.60", svc.lastUpdate.RangeStart)

	var out GatewayUpdateIPAMPoolResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &out))
	assert.Equal(t, "10.4.9.200", out.Pool.RangeEnd)
}

// TestGatewayIPAMWindow_ErrorStatus maps a window refusal to
// StatusInvalidArgument, and the detail error matches the sentinel.
func TestGatewayIPAMWindow_ErrorStatus(t *testing.T) {
	handler, service := createTestGatewayHandler()
	service.createPoolErr = ErrGatewayIPAMWindowDetail{Reason: "IP 10.4.9.1 is reserved"}
	payload, err := quicwire.EncodePayload(&GatewayCreateIPAMPoolRequest{Name: "lab", CIDR: "10.4.9.0/24"})
	require.NoError(t, err)

	resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpGatewayCreateIPAMPool, Payload: payload})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)

	detail := ErrGatewayIPAMWindowDetail{Reason: "x"}
	assert.True(t, errors.Is(detail, ErrGatewayIPAMWindow))
	assert.Contains(t, detail.Error(), "x")
}
