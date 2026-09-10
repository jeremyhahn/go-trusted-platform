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
	"bytes"
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipamBackends "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Reproduction test: QUIC gateway ListNetworkZones with 7 built-in zones
// =============================================================================

// TestQUICGatewayListNetworkZones_Reproduction reproduces the integration-test
// failure "ListNetworkZones not implemented: QUIC read response: read payload: EOF".
//
// It drives the REAL path used by the daemon:
//
//	QUICServiceHandler.handleGatewayCategory (opcode 0x2F)
//	  → GatewayHandler.handleListNetworkZones (sub-opcode 0x10)
//	    → fullGatewayQUICAdapter.ListNetworkZones
//	      → ZoneService.List (returns 7 built-in ZoneRecords)
//	        → zoneRecordToQUICInfo → NetworkZoneInfo slice
//	          → EncodePayload (msgpack)
//
// The request frame is framed exactly as sendCategoryRequest in the integration
// adapter: opcode 0x2F, payload[0]=0x10, remaining bytes = msgpack({lifecycle_role:""}).
//
// Before the fix this test fails with a panic (recovered via the new guard) or
// surfaces the exact encoding bug that produces the stream EOF.
func TestQUICGatewayListNetworkZones_Reproduction(t *testing.T) {
	ctx := context.Background()

	// Build the real ZoneService seeded from defaults (7 built-in zones).
	zoneSvc, err := gateway.NewZoneService(nil, nil)
	require.NoError(t, err, "NewZoneService must succeed with nil seed")

	// Build the real IPAM memory backend used by the daemon.
	ipamAlloc := ipamBackends.NewMemoryBackend()

	// Wire fullGatewayQUICAdapter exactly as newFullGatewayQUICAdapter does in the daemon.
	adapter := newFullGatewayQUICAdapter(ipamAlloc, zoneSvc, nil)

	// Build the GatewayHandler exactly as the daemon does.
	logger := logging.DefaultLogger()
	gatewayHandler := quic.NewGatewayHandler(logger, adapter)

	// Build the QUICServiceHandler with only the gateway handler wired.
	h := NewQUICServiceHandler(logger,
		WithQUICGatewayHandler(gatewayHandler),
	)

	// Build the request frame exactly as sendCategoryRequest does:
	//   payload = [sub_opcode(1)] + msgpack({lifecycle_role:""})
	listReq := struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}{LifecycleRole: ""}

	bodyBytes, err := quic.EncodePayload(listReq)
	require.NoError(t, err, "encoding list request must not fail")

	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = 0x10 // OpGatewayListNetworkZones sub-opcode
	copy(payload[1:], bodyBytes)

	req := &quic.Request{
		Opcode:  0x2F, // OpGatewayCategory
		Token:   "",
		Payload: payload,
	}

	resp := h.HandleRequest(ctx, req)
	require.NotNil(t, resp, "response must not be nil")
	assert.Equal(t, quic.StatusOK, resp.Status,
		"ListNetworkZones over QUIC must succeed; got status 0x%02x payload: %s",
		resp.Status, string(resp.Payload))

	// Decode the response exactly as the integration adapter decodes it.
	var listResp quic.GatewayListNetworkZonesResponse
	err = quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err, "decoding list response must not fail")

	// zone.Resolve(nil) returns the 7 built-in zones.
	assert.Len(t, listResp.Zones, 7,
		"expected 7 built-in zones, got %d", len(listResp.Zones))

	for _, z := range listResp.Zones {
		assert.NotEmpty(t, z.Name, "zone must have a name")
	}
}

// TestQUICGatewayListNetworkZones_FilterByRole verifies that the lifecycle_role
// filter works correctly over the QUIC path.
func TestQUICGatewayListNetworkZones_FilterByRole(t *testing.T) {
	ctx := context.Background()

	zoneSvc, err := gateway.NewZoneService(nil, nil)
	require.NoError(t, err)

	ipamAlloc := ipamBackends.NewMemoryBackend()
	adapter := newFullGatewayQUICAdapter(ipamAlloc, zoneSvc, nil)
	logger := logging.DefaultLogger()
	gatewayHandler := quic.NewGatewayHandler(logger, adapter)
	h := NewQUICServiceHandler(logger, WithQUICGatewayHandler(gatewayHandler))

	t.Run("provisioning role returns exactly one zone", func(t *testing.T) {
		listReq := struct {
			LifecycleRole string `codec:"lifecycle_role,omitempty"`
		}{LifecycleRole: "provisioning"}

		bodyBytes, err := quic.EncodePayload(listReq)
		require.NoError(t, err)

		payload := make([]byte, 1+len(bodyBytes))
		payload[0] = 0x10
		copy(payload[1:], bodyBytes)

		resp := h.HandleRequest(ctx, &quic.Request{Opcode: 0x2F, Payload: payload})
		require.NotNil(t, resp)
		assert.Equal(t, quic.StatusOK, resp.Status)

		var listResp quic.GatewayListNetworkZonesResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &listResp))
		require.Len(t, listResp.Zones, 1)
		assert.Equal(t, "provisioning", listResp.Zones[0].LifecycleRole)
	})

	t.Run("unknown role returns empty list", func(t *testing.T) {
		listReq := struct {
			LifecycleRole string `codec:"lifecycle_role,omitempty"`
		}{LifecycleRole: "nonexistent"}

		bodyBytes, err := quic.EncodePayload(listReq)
		require.NoError(t, err)

		payload := make([]byte, 1+len(bodyBytes))
		payload[0] = 0x10
		copy(payload[1:], bodyBytes)

		resp := h.HandleRequest(ctx, &quic.Request{Opcode: 0x2F, Payload: payload})
		require.NotNil(t, resp)
		assert.Equal(t, quic.StatusOK, resp.Status)

		var listResp quic.GatewayListNetworkZonesResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &listResp))
		assert.Empty(t, listResp.Zones)
	})
}

// TestQUICGatewayListNetworkZones_NilZoneSvc verifies that a nil zone service
// in fullGatewayQUICAdapter returns StatusUnavailable, not a panic.
func TestQUICGatewayListNetworkZones_NilZoneSvc(t *testing.T) {
	ctx := context.Background()

	ipamAlloc := ipamBackends.NewMemoryBackend()
	// zoneSvc is nil — simulates daemon started without sdn config.
	adapter := newFullGatewayQUICAdapter(ipamAlloc, nil, nil)
	logger := logging.DefaultLogger()
	gatewayHandler := quic.NewGatewayHandler(logger, adapter)
	h := NewQUICServiceHandler(logger, WithQUICGatewayHandler(gatewayHandler))

	bodyBytes, err := quic.EncodePayload(struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}{})
	require.NoError(t, err)

	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = 0x10
	copy(payload[1:], bodyBytes)

	resp := h.HandleRequest(ctx, &quic.Request{Opcode: 0x2F, Payload: payload})
	require.NotNil(t, resp)
	assert.Equal(t, quic.StatusUnavailable, resp.Status,
		"nil zone service must return StatusUnavailable, not a panic")
}

// =============================================================================
// Round-trip framing test
// =============================================================================

// TestQUICGatewayCategory_FramingRoundTrip verifies the WriteRequest/ReadRequest
// wire framing used by the integration adapter does not corrupt the payload
// delivered to the handler, ensuring the stream-level frame matches expectations.
func TestQUICGatewayCategory_FramingRoundTrip(t *testing.T) {
	// Build the request exactly as sendCategoryRequest does.
	listReq := struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}{LifecycleRole: ""}

	bodyBytes, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	// payload = [sub_opcode] + [msgpack body]
	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = 0x10
	copy(payload[1:], bodyBytes)

	wireReq := &quic.Request{
		Opcode:  0x2F,
		Token:   "",
		Payload: payload,
	}

	// Write to a bytes.Buffer, then read back.
	var buf bytes.Buffer
	require.NoError(t, quic.WriteRequest(&buf, wireReq))

	decoded, err := quic.ReadRequest(&buf)
	require.NoError(t, err)

	assert.Equal(t, byte(0x2F), decoded.Opcode)
	assert.Equal(t, "", decoded.Token)
	require.Len(t, decoded.Payload, len(payload),
		"payload length must survive wire framing")
	assert.Equal(t, byte(0x10), decoded.Payload[0],
		"sub-opcode must be payload[0] after framing round-trip")
}

// =============================================================================
// Panic recovery guard test
// =============================================================================

// panicGatewayService is a GatewayServiceInterface that panics in ListNetworkZones
// to verify that the recover() guard in handleStream catches it and returns a
// StatusInternalError response instead of closing the stream silently.
type panicGatewayService struct{}

func (p *panicGatewayService) Status(_ context.Context) (*quic.GatewayStatusInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) Snapshot(_ context.Context, _ string) (*quic.GatewaySnapshotInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListSnapshots(_ context.Context) ([]*quic.GatewaySnapshotInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) SetMode(_ context.Context, _ string) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) BGPStatus(_ context.Context) (*quic.BGPStatusInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListBGPPeers(_ context.Context) ([]*quic.BGPPeerInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) AnnouncePrefix(_ context.Context, _ string, _ *quic.AnnouncePrefixOptions) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) WithdrawPrefix(_ context.Context, _ string) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListPrefixes(_ context.Context) ([]*quic.PrefixInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListIPAMPools(_ context.Context, _ string) ([]*quic.IPAMPoolInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) GetIPAMPool(_ context.Context, _ string) (*quic.IPAMPoolInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) CreateIPAMPool(_ context.Context, _ *quic.CreateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) UpdateIPAMPool(_ context.Context, _ string, _ *quic.UpdateIPAMPoolOptions) (*quic.IPAMPoolInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) DeleteIPAMPool(_ context.Context, _ string) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) AllocateIP(_ context.Context, _ string, _ *quic.AllocateIPOptions) (*quic.IPAllocationInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ReleaseIP(_ context.Context, _ string, _ string) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListAllocations(_ context.Context, _ string) ([]*quic.IPAllocationInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListNetworkZones(_ context.Context, _ string) ([]*quic.NetworkZoneInfo, error) {
	panic("deliberate panic in ListNetworkZones to test recover() guard")
}
func (p *panicGatewayService) CreateNetworkZone(_ context.Context, _ *quic.CreateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) UpdateNetworkZone(_ context.Context, _ string, _ *quic.UpdateNetworkZoneOptions) (*quic.NetworkZoneInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) DeleteNetworkZone(_ context.Context, _ string) (bool, error) {
	return false, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) AssignNetworkZone(_ context.Context, _ string, _ string) (bool, error) {
	return false, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) AddVIP(_ context.Context, _ *quic.LBVIPSpec) (*quic.LBVIPInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) RemoveVIP(_ context.Context, _, _ string, _ uint16) error {
	return quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) GetVIP(_ context.Context, _, _ string, _ uint16) (*quic.LBVIPInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) ListVIPs(_ context.Context) ([]*quic.LBVIPInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) SetVIPBackends(_ context.Context, _, _ string, _ uint16, _ []*quic.LBBackendSpec) (*quic.LBVIPInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}
func (p *panicGatewayService) LBStatus(_ context.Context) (*quic.LBStatusInfo, error) {
	return nil, quic.ErrGatewayFeatureNotConfigured
}

// TestQUICHandler_RecoverGuard_PanicInHandler verifies that when a handler
// panics, the QUICServiceHandler.HandleRequest recover() guard catches it and
// returns StatusInternalError instead of propagating the panic.
func TestQUICHandler_RecoverGuard_PanicInHandler(t *testing.T) {
	ctx := context.Background()

	logger := logging.DefaultLogger()
	gatewayHandler := quic.NewGatewayHandler(logger, &panicGatewayService{})
	h := NewQUICServiceHandler(logger, WithQUICGatewayHandler(gatewayHandler))

	bodyBytes, err := quic.EncodePayload(struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}{})
	require.NoError(t, err)

	payload := make([]byte, 1+len(bodyBytes))
	payload[0] = 0x10
	copy(payload[1:], bodyBytes)

	// Must not panic — the recover guard must catch the panic.
	var resp *quic.Response
	require.NotPanics(t, func() {
		resp = h.HandleRequest(ctx, &quic.Request{Opcode: 0x2F, Payload: payload})
	})

	require.NotNil(t, resp)
	assert.Equal(t, quic.StatusInternalError, resp.Status,
		"a panicking handler must produce StatusInternalError, not a nil response or panic")
}
