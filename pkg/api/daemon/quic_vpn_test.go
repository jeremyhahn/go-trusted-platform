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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// vpnCategoryRequest builds an OpVPNCategory request carrying the encoded
// platform.v1 request message after the sub-opcode.
func vpnCategoryRequest(t *testing.T, sub byte, message interface{}) *quicwire.Request {
	t.Helper()
	body, err := quicwire.EncodePayload(message)
	require.NoError(t, err)
	return &quicwire.Request{Opcode: quicwire.OpVPNCategory, Payload: append([]byte{sub}, body...)}
}

// newVPNQUICHandler wires the shared VPN test server into a QUIC handler.
func newVPNQUICHandler(t *testing.T) (*QUICServiceHandler, *VPNGRPCService) {
	t.Helper()
	server, _ := newVPNTestServer(t)
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetVPNService(server)
	return handler, server
}

// TestQUICVPNErrorClassesMatchGRPC pins QUIC parity with gRPC and REST: every
// pkg/vpn error lands in the QUIC status class matching its gRPC code.
func TestQUICVPNErrorClassesMatchGRPC(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)
	for _, tc := range vpnServiceErrorCases {
		resp := handler.vpnErrorResponse("op", vpnErrToGRPC(tc.err))
		assert.Equal(t, tc.quic, resp.Status, "%T", tc.err)
	}
}

// TestQUICVPNErrorResponse_KeyCollisionIsAConflict covers the one code the
// shared delegate map has no entry for, and that the shared map still answers
// everything else.
func TestQUICVPNErrorResponse_KeyCollisionIsAConflict(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)

	resp := handler.vpnErrorResponse("op", vpnErrToGRPC(&vpn.ErrKeyCollision{Kind: "peer", Key: "a", Stored: "b"}))
	assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status)

	resp = handler.vpnErrorResponse("op", errors.New("boom"))
	assert.Equal(t, quicwire.StatusInternalError, resp.Status)
}

// requireVPNQUICOK asserts a successful reply and decodes its payload.
func requireVPNQUICOK(t *testing.T, resp *quicwire.Response, decoded interface{}) {
	t.Helper()
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload %q", resp.Payload)
	require.NoError(t, quicwire.DecodePayload(resp.Payload, decoded))
}

func TestQUICVPNCategoryMapsServiceRefusals(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)
	ctx := context.Background()

	cases := []struct {
		name string
		req  *quicwire.Request
		want byte
	}{
		{
			name: "revoke a peer never enrolled",
			req:  vpnCategoryRequest(t, quicwire.VPNSubRevokePeer, &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "ghost"}),
			want: quicwire.StatusNotFound,
		},
		{
			name: "enrol without a tenant",
			req:  vpnCategoryRequest(t, quicwire.VPNSubEnrolPeer, &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{DeviceId: "laptop-1"}}),
			want: quicwire.StatusInvalidArgument,
		},
		{
			name: "status of an unknown gateway",
			req:  vpnCategoryRequest(t, quicwire.VPNSubGetStatus, &platformv1.GetVPNStatusRequest{GatewayId: "gw-missing"}),
			want: quicwire.StatusNotFound,
		},
		{
			name: "undecodable request body",
			req:  &quicwire.Request{Opcode: quicwire.OpVPNCategory, Payload: []byte{quicwire.VPNSubEnrolPeer, 0xC1}},
			want: quicwire.StatusInvalidRequest,
		},
		{
			name: "missing sub-opcode",
			req:  &quicwire.Request{Opcode: quicwire.OpVPNCategory},
			want: quicwire.StatusInvalidRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.HandleRequest(ctx, tc.req)
			assert.Equal(t, tc.want, resp.Status, "payload %q", resp.Payload)
		})
	}
}

func TestQUICVPNCategoryStoreFailureIsUnavailable(t *testing.T) {
	server, storage := newVPNTestServer(t)
	storage.ListError = errors.New("raft leader lost")
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetVPNService(server)

	resp := handler.HandleRequest(context.Background(), vpnCategoryRequest(t, quicwire.VPNSubListPeers, &platformv1.ListVPNPeersRequest{}))
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestQUICVPNCategoryRejectsUnknownSubOpcodes(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)
	req := &quicwire.Request{Opcode: quicwire.OpVPNCategory, Payload: []byte{0x7F}}

	// The authorization guard refuses an unclassified sub-opcode before
	// dispatch; the category handler still rejects it on its own.
	assert.Equal(t, quicwire.StatusPermissionDenied, handler.HandleRequest(context.Background(), req).Status)
	assert.Equal(t, quicwire.StatusNotImplemented, handler.handleVPNCategory(context.Background(), req).Status)
}

func TestQUICVPNCategoryWithoutServiceIsUnavailable(t *testing.T) {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())

	for sub := range vpnQUICHandlers {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpVPNCategory, Payload: []byte{sub}})
		assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "sub-opcode 0x%02X", sub)
	}
}
