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

func zoneRequest(t *testing.T, op byte, body any) *quicwire.Request {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = quicwire.EncodePayload(body)
		require.NoError(t, err)
	}
	return &quicwire.Request{Opcode: op, Payload: payload}
}

// TestGatewayZoneHandlers_RoundTrip carries the whole zone schema over each
// zone opcode.
func TestGatewayZoneHandlers_RoundTrip(t *testing.T) {
	h, svc := createTestGatewayHandler()
	ctx := context.Background()

	resp := h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayCreateNetworkZone, &GatewayCreateNetworkZoneRequest{
		Opts: &CreateNetworkZoneOptions{
			Name: "lab", Offset: 9, PortClasses: []string{"hypervisor"},
			AllowTo:          []NetworkZonePathInfo{{Zone: "control-plane", Services: []string{"dns"}}},
			Services:         []string{"ssh"},
			Isolate:          true,
			PrivilegedAccess: &NetworkZonePrivilegedAccessInfo{Reason: "lab dns", ApprovedBy: "owner"},
		},
	}))
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var created GatewayCreateNetworkZoneResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &created))
	assert.Equal(t, uint8(9), created.Zone.Offset)
	assert.True(t, created.Zone.RestartRequired)
	got := svc.lastZoneCreate
	require.NotNil(t, got)
	assert.Equal(t, []string{"hypervisor"}, got.PortClasses)
	assert.Equal(t, []NetworkZonePathInfo{{Zone: "control-plane", Services: []string{"dns"}}}, got.AllowTo)
	assert.Equal(t, "owner", got.PrivilegedAccess.ApprovedBy)

	resp = h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayUpdateNetworkZone, &GatewayUpdateNetworkZoneRequest{
		Name: "storage", Opts: &UpdateNetworkZoneOptions{Isolate: true, Services: []string{"nvme-tcp"}},
	}))
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	assert.Equal(t, "storage", svc.lastZoneName)
	assert.Equal(t, []string{"nvme-tcp"}, svc.lastZoneUpdate.Services)

	resp = h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayUpdateNetworkZone, &GatewayUpdateNetworkZoneRequest{Name: "backup"}))
	require.Equal(t, quicwire.StatusOK, resp.Status, "update without options sends empty options")
	require.NotNil(t, svc.lastZoneUpdate)

	resp = h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayListNetworkZones, &GatewayListNetworkZonesRequest{LifecycleRole: "provisioning"}))
	require.Equal(t, quicwire.StatusOK, resp.Status)
	var list GatewayListNetworkZonesResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &list))
	require.Len(t, list.Zones, 1)
	assert.Equal(t, "provisioning", svc.lastZoneRole)
	require.NotNil(t, list.Zones[0].Numbering)
	assert.Equal(t, uint16(405), list.Zones[0].Numbering.VLAN)

	resp = h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayDeleteNetworkZone, &GatewayDeleteNetworkZoneRequest{Name: "lab"}))
	require.Equal(t, quicwire.StatusOK, resp.Status)
	var deleted GatewayDeleteNetworkZoneResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &deleted))
	assert.True(t, deleted.RestartRequired)
}

// TestGatewayZoneHandlers_Errors covers missing names, undecodable payloads,
// the service error statuses and the retired assign opcode.
func TestGatewayZoneHandlers_Errors(t *testing.T) {
	h, svc := createTestGatewayHandler()
	ctx := context.Background()

	for _, req := range []*quicwire.Request{
		zoneRequest(t, quicwire.OpGatewayCreateNetworkZone, &GatewayCreateNetworkZoneRequest{}),
		zoneRequest(t, quicwire.OpGatewayUpdateNetworkZone, &GatewayUpdateNetworkZoneRequest{}),
		zoneRequest(t, quicwire.OpGatewayDeleteNetworkZone, &GatewayDeleteNetworkZoneRequest{}),
	} {
		assert.Equal(t, quicwire.StatusInvalidArgument, h.HandleRequest(ctx, req).Status, "op 0x%02x without a name", req.Opcode)
	}

	for _, op := range []byte{quicwire.OpGatewayCreateNetworkZone, quicwire.OpGatewayUpdateNetworkZone, quicwire.OpGatewayDeleteNetworkZone, quicwire.OpGatewayListNetworkZones} {
		resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: op, Payload: []byte{0xc1, 0xff, 0x00}})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "op 0x%02x with a bad payload", op)
	}

	cause := errors.New("zone: offset 03 is not an owner offset")
	cases := []struct {
		err  error
		want byte
	}{
		{GatewayZoneError{Kind: ErrGatewayZoneNotFound, Cause: cause}, quicwire.StatusNotFound},
		{GatewayZoneError{Kind: ErrGatewayZoneAlreadyExists, Cause: cause}, quicwire.StatusAlreadyExists},
		{GatewayZoneError{Kind: ErrGatewayZoneInvalid, Cause: cause}, quicwire.StatusInvalidArgument},
		{errors.New("backend down"), quicwire.StatusInternalError},
	}
	for _, tc := range cases {
		svc.zoneErr = tc.err
		resp := h.HandleRequest(ctx, zoneRequest(t, quicwire.OpGatewayUpdateNetworkZone, &GatewayUpdateNetworkZoneRequest{Name: "storage"}))
		assert.Equal(t, tc.want, resp.Status, "error %v", tc.err)
	}

	resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: 0x14})
	assert.NotEqual(t, quicwire.StatusOK, resp.Status, "0x14 (assign) is retired")
}

// TestGatewayZoneError covers the typed zone error.
func TestGatewayZoneError(t *testing.T) {
	cause := errors.New("zone: \"lab\" not found")
	err := GatewayZoneError{Kind: ErrGatewayZoneNotFound, Cause: cause}
	assert.True(t, errors.Is(err, ErrGatewayZoneNotFound))
	assert.False(t, errors.Is(err, ErrGatewayZoneInvalid))
	assert.Equal(t, cause, errors.Unwrap(err))
	assert.Contains(t, err.Error(), "zone not found")
	assert.Contains(t, err.Error(), `"lab"`)
	assert.Equal(t, "invalid zone", GatewayZoneError{Kind: ErrGatewayZoneInvalid}.Error())
}

// TestGatewayZoneHandlers_NoService answers Unavailable without a backend.
func TestGatewayZoneHandlers_NoService(t *testing.T) {
	h := NewGatewayHandler(newGatewayTestLogger(), nil)
	for _, op := range []byte{quicwire.OpGatewayCreateNetworkZone, quicwire.OpGatewayUpdateNetworkZone, quicwire.OpGatewayDeleteNetworkZone, quicwire.OpGatewayListNetworkZones} {
		assert.Equal(t, quicwire.StatusUnavailable, h.HandleRequest(context.Background(), &quicwire.Request{Opcode: op}).Status, "op 0x%02x", op)
	}
}
