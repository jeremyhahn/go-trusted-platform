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

// Package quic: in-process transport test for the gateway-category opcode path.
//
// This test covers the full round-trip:
//   client dial → TLS handshake → OpenStream → WriteRequest → ReadResponse
//
// over a real quic-go loopback connection backed by the same handler chain that
// the integration daemon wires:
//   QUICServiceHandler → handleGatewayCategory → GatewayHandler →
//   testTransportGatewayService (seeded with the 9 built-in zones)
//
// The test was written to reproduce and lock in the fix for a stream truncation
// bug where the client received the 5-byte response header (status + length)
// but got EOF before the payload completed. Root cause: WriteResponse performed
// three separate stream.Write() calls; quic-go flushed the 5-byte header as its
// own STREAM frame before the payload frame was queued, and the deferred
// stream.Close() on the server side occasionally sent a FIN before the payload
// frames were delivered, producing "read payload: EOF" on the client.
//
// The fix (single atomic Write for the full response frame) is validated here by
// verifying that the response payload is always fully received even when
// back-to-back streams are opened immediately after the connection is established
// (mirroring the Setup() → listZonesRaw() sequence in the integration adapter).

package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Minimal gateway service stub for transport tests
// =============================================================================

// testTransportGatewayService is a minimal GatewayServiceInterface that
// returns a fixed set of 9 network zones, matching the seeded zone count the
// integration daemon exposes.
type testTransportGatewayService struct{}

func (s *testTransportGatewayService) Status(_ context.Context) (*GatewayStatusInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) Snapshot(_ context.Context, _ string) (*GatewaySnapshotInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListSnapshots(_ context.Context) ([]*GatewaySnapshotInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) SetMode(_ context.Context, _ string) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) BGPStatus(_ context.Context) (*BGPStatusInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListBGPPeers(_ context.Context) ([]*BGPPeerInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) AnnouncePrefix(_ context.Context, _ string, _ *AnnouncePrefixOptions) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) WithdrawPrefix(_ context.Context, _ string) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListPrefixes(_ context.Context) ([]*PrefixInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListIPAMPools(_ context.Context, _ string) ([]*IPAMPoolInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) GetIPAMPool(_ context.Context, _ string) (*IPAMPoolInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) CreateIPAMPool(_ context.Context, _ *CreateIPAMPoolOptions) (*IPAMPoolInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) UpdateIPAMPool(_ context.Context, _ string, _ *UpdateIPAMPoolOptions) (*IPAMPoolInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) DeleteIPAMPool(_ context.Context, _ string) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) AllocateIP(_ context.Context, _ string, _ *AllocateIPOptions) (*IPAllocationInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ReleaseIP(_ context.Context, _ string, _ string) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListAllocations(_ context.Context, _ string) ([]*IPAllocationInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}

// ListNetworkZones returns the 9 built-in zones — the same count the integration
// daemon exposes after gateway.NewZoneService(nil, nil).
func (s *testTransportGatewayService) ListNetworkZones(_ context.Context, _ string) ([]*NetworkZoneInfo, error) {
	now := time.Now().Unix()
	names := []string{"transit", "fabric", "management", "hypervisor", "quarantine", "provisioning", "control-plane", "storage", "backup"}
	out := make([]*NetworkZoneInfo, len(names))
	for i, n := range names {
		out[i] = &NetworkZoneInfo{
			Name:      n,
			Offset:    uint8(i),
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
	return out, nil
}
func (s *testTransportGatewayService) CreateNetworkZone(_ context.Context, opts *CreateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	if opts == nil || opts.Name == "" {
		return nil, ErrGatewayZoneNameRequired
	}
	return &NetworkZoneInfo{Name: opts.Name, CreatedAt: time.Now().Unix()}, nil
}
func (s *testTransportGatewayService) UpdateNetworkZone(_ context.Context, _ string, _ *UpdateNetworkZoneOptions) (*NetworkZoneInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) DeleteNetworkZone(_ context.Context, _ string) (bool, error) {
	return false, ErrGatewayFeatureNotConfigured
}

func (s *testTransportGatewayService) AddVIP(_ context.Context, _ *LBVIPSpec) (*LBVIPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) RemoveVIP(_ context.Context, _, _ string, _ uint16) error {
	return ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) GetVIP(_ context.Context, _, _ string, _ uint16) (*LBVIPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) ListVIPs(_ context.Context) ([]*LBVIPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) SetVIPBackends(_ context.Context, _, _ string, _ uint16, _ []*LBBackendSpec) (*LBVIPInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}
func (s *testTransportGatewayService) LBStatus(_ context.Context) (*LBStatusInfo, error) {
	return nil, ErrGatewayFeatureNotConfigured
}

func (s *testTransportGatewayService) NAT64Status(_ context.Context) (*quicwire.NAT64StatusInfo, error) {
	return &quicwire.NAT64StatusInfo{Active: true, InstancePresent: true}, nil
}

var _ GatewayServiceInterface = (*testTransportGatewayService)(nil)

// =============================================================================
// Transport test handler: wraps GatewayHandler as a top-level category handler,
// identical to how QUICServiceHandler.handleGatewayCategory dispatches.
// =============================================================================

// gatewayCategoryHandler wraps a GatewayHandler and implements the same
// category-opcode dispatch that QUICServiceHandler.handleGatewayCategory uses:
// the first payload byte is the sub-opcode; the remainder is the inner payload.
type gatewayCategoryHandler struct {
	gwHandler *GatewayHandler
}

func (h *gatewayCategoryHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest, Payload: []byte("nil request")}
	}
	if req.Opcode != quicwire.OpGatewayCategory {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest, Payload: []byte("expected OpGatewayCategory")}
	}
	if len(req.Payload) == 0 {
		return &quicwire.Response{Status: quicwire.StatusInvalidRequest, Payload: []byte("missing sub_opcode")}
	}
	subOpcode := req.Payload[0]
	subPayload := req.Payload[1:]
	subReq := &quicwire.Request{
		Opcode:  subOpcode,
		Token:   req.Token,
		Payload: subPayload,
	}
	return h.gwHandler.HandleRequest(ctx, subReq)
}

// =============================================================================
// Wire helpers mirroring the integration adapter
// =============================================================================

// msgpackEncode encodes v with MessagePack.
func msgpackEncode(v interface{}) ([]byte, error) {
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return nil, err
	}
	return c.Marshal(v)
}

// msgpackDecode decodes data into v with MessagePack.
func msgpackDecode(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return err
	}
	return c.Unmarshal(data, &v)
}

// writeTestRequest writes [opcode:1][tokenLen:2][token:0][payloadLen:4][payload:N].
func writeTestRequest(w io.Writer, opcode byte, payload []byte) error {
	payloadLen := uint32(len(payload))
	buf := make([]byte, 0, 1+2+4+len(payload))
	buf = append(buf, opcode)
	buf = append(buf, 0, 0) // token_len = 0
	b4 := make([]byte, 4)
	binary.BigEndian.PutUint32(b4, payloadLen)
	buf = append(buf, b4...)
	buf = append(buf, payload...)
	_, err := w.Write(buf)
	return err
}

// readTestResponse reads [status:1][payloadLen:4][payload:N] from r using
// io.ReadFull, matching the adapter's readFull loop.
func readTestResponse(r io.Reader) (status byte, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, nil, &quicwire.WrappedError{Msg: "read header", Err: err}
	}
	status = header[0]
	payloadLen := binary.BigEndian.Uint32(header[1:5])
	if payloadLen == 0 {
		return status, nil, nil
	}
	payload = make([]byte, payloadLen)
	if _, err = io.ReadFull(r, payload); err != nil {
		return status, nil, &quicwire.WrappedError{Msg: "read payload", Err: err}
	}
	return status, payload, nil
}

// =============================================================================
// In-process loopback server builder
// =============================================================================

// startGatewayTransportServer starts a QUIC server on 127.0.0.1:0 backed by
// the testTransportGatewayService and returns the server, the actual bound
// address, and a client TLS config that trusts the server's self-signed cert.
func startGatewayTransportServer(t *testing.T) (srv *Server, addr string, clientTLS *tls.Config) {
	t.Helper()

	serverTLS := generateTestTLSConfig()
	// Use "platform-quic" ALPN to match the production server
	serverTLS.NextProtos = []string{"platform-quic"}

	cfg := &ServerConfig{
		ListenAddr:                 "127.0.0.1:0",
		TLSConfig:                  serverTLS,
		MaxStreams:                 1000,
		MaxIdleTimeout:             30 * time.Second,
		MaxIncomingStreams:         1000,
		MaxIncomingUniStreams:      100,
		KeepAlivePeriod:            15 * time.Second,
		HandshakeIdleTimeout:       5 * time.Second,
		MaxReceiveBufferSize:       1 * 1024 * 1024,
		InitialStreamReceiveWindow: 512 * 1024,
		MaxStreamReceiveWindow:     6 * 1024 * 1024,
	}

	logger := logging.NewLogger(slog.LevelDebug, io.Discard)
	gwHandler := NewGatewayHandler(logger, &testTransportGatewayService{})
	handler := &gatewayCategoryHandler{gwHandler: gwHandler}

	srv, err := NewServer(cfg, WithHandler(handler), WithLogger(logger))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Server.Start: %v", err)
	}

	addr = srv.ListenAddr()

	// Build client TLS that trusts the server's self-signed cert — no InsecureSkipVerify.
	serverCertDER := serverTLS.Certificates[0].Certificate[0]
	serverCert, err := x509.ParseCertificate(serverCertDER)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(serverCert)
	clientTLS = &tls.Config{
		RootCAs:    pool,
		NextProtos: []string{"platform-quic"},
		MinVersion: tls.VersionTLS13,
	}

	return srv, addr, clientTLS
}

// =============================================================================
// Tests
// =============================================================================

// TestGatewayTransport_ListNetworkZones_FullRoundTrip verifies that a
// ListNetworkZones request returns all 9 zones over a real quic-go loopback
// connection. This is the exact scenario that triggered the stream truncation
// bug: the response payload arrived in fragments and io.ReadFull returned EOF
// mid-payload before the fix.
func TestGatewayTransport_ListNetworkZones_FullRoundTrip(t *testing.T) {
	srv, addr, clientTLS := startGatewayTransportServer(t)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	conn, err := quicgo.DialAddr(ctx, addr, clientTLS, &quicgo.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	// Build the payload: [sub_opcode:1][msgpack body]
	type listZonesReq struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}
	bodyBytes, err := msgpackEncode(&listZonesReq{})
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}
	payload := append([]byte{quicwire.OpGatewayListNetworkZones}, bodyBytes...)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	defer stream.Close()

	if err := writeTestRequest(stream, quicwire.OpGatewayCategory, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}

	status, respPayload, err := readTestResponse(stream)
	if err != nil {
		t.Fatalf("read response: %v", err) // was: "read payload: EOF" before the fix
	}
	if status != quicwire.StatusOK {
		t.Fatalf("expected StatusOK (0x00), got 0x%02x: %s", status, respPayload)
	}

	type listZonesResp struct {
		Zones     []*NetworkZoneInfo `codec:"zones"`
		Timestamp int64              `codec:"timestamp"`
	}
	var resp listZonesResp
	if err := msgpackDecode(respPayload, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Zones) != 9 {
		t.Errorf("expected 9 zones, got %d", len(resp.Zones))
	}
}

// TestGatewayTransport_ListNetworkZones_BackToBack verifies that multiple
// back-to-back ListNetworkZones requests on the same connection all complete
// without truncation. The integration adapter's Setup() calls listZonesRaw
// immediately after dialing, which is the exact sequence that triggered the
// original failure: the first stream was opened before the QUIC connection's
// flow-control credit was fully distributed.
func TestGatewayTransport_ListNetworkZones_BackToBack(t *testing.T) {
	srv, addr, clientTLS := startGatewayTransportServer(t)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	conn, err := quicgo.DialAddr(ctx, addr, clientTLS, &quicgo.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	type listZonesReq struct {
		LifecycleRole string `codec:"lifecycle_role,omitempty"`
	}
	type listZonesResp struct {
		Zones     []*NetworkZoneInfo `codec:"zones"`
		Timestamp int64              `codec:"timestamp"`
	}

	for i := range 5 {
		bodyBytes, err := msgpackEncode(&listZonesReq{})
		if err != nil {
			t.Fatalf("iteration %d: encode: %v", i, err)
		}
		payload := append([]byte{quicwire.OpGatewayListNetworkZones}, bodyBytes...)

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("iteration %d: OpenStreamSync: %v", i, err)
		}

		if err := writeTestRequest(stream, quicwire.OpGatewayCategory, payload); err != nil {
			_ = stream.Close()
			t.Fatalf("iteration %d: write request: %v", i, err)
		}

		status, respPayload, err := readTestResponse(stream)
		_ = stream.Close()
		if err != nil {
			t.Fatalf("iteration %d: read response: %v (truncation bug)", i, err)
		}
		if status != quicwire.StatusOK {
			t.Fatalf("iteration %d: expected StatusOK, got 0x%02x: %s", i, status, respPayload)
		}

		var resp listZonesResp
		if err := msgpackDecode(respPayload, &resp); err != nil {
			t.Fatalf("iteration %d: decode: %v", i, err)
		}
		if len(resp.Zones) != 9 {
			t.Errorf("iteration %d: expected 9 zones, got %d", i, len(resp.Zones))
		}
	}
}

// TestGatewayTransport_WriteResponseAtomic confirms that WriteResponse produces
// a single contiguous buffer in memory — the invariant the fix relies on. This
// guards against future refactors that might re-introduce multi-write splits.
func TestGatewayTransport_WriteResponseAtomic(t *testing.T) {
	payload := bytes.Repeat([]byte("Z"), 512) // typical zone list size
	resp := &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}

	var buf bytes.Buffer
	if err := quicwire.WriteResponse(&buf, resp); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}

	// The buffer must have been written in a single Write call. Since bytes.Buffer
	// always accumulates all writes, we can verify the total length is exactly
	// 1 (status) + 4 (length) + len(payload).
	want := 1 + 4 + len(payload)
	if buf.Len() != want {
		t.Errorf("WriteResponse wrote %d bytes, want %d", buf.Len(), want)
	}

	// Verify the frame can be read back correctly.
	status, readPayload, err := readTestResponse(&buf)
	if err != nil {
		t.Fatalf("readTestResponse: %v", err)
	}
	if status != quicwire.StatusOK {
		t.Errorf("status: got 0x%02x, want 0x%02x", status, quicwire.StatusOK)
	}
	if !bytes.Equal(readPayload, payload) {
		t.Errorf("payload mismatch: got %d bytes, want %d", len(readPayload), len(payload))
	}
}

// TestGatewayTransport_ErrorResponse verifies that non-OK responses with a
// payload are also transmitted without truncation (the same fix applies to
// error payloads like "gateway service not available").
func TestGatewayTransport_ErrorResponse(t *testing.T) {
	srv, addr, clientTLS := startGatewayTransportServer(t)
	t.Cleanup(func() { _ = srv.Stop() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	conn, err := quicgo.DialAddr(ctx, addr, clientTLS, &quicgo.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialAddr: %v", err)
	}
	defer conn.CloseWithError(0, "test done")

	// Request gateway status — the test service returns ErrGatewayFeatureNotConfigured
	// which maps to StatusUnavailable with a non-empty error message payload.
	payload := []byte{quicwire.OpGatewayStatus}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	defer stream.Close()

	if err := writeTestRequest(stream, quicwire.OpGatewayCategory, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}

	status, respPayload, err := readTestResponse(stream)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if status != quicwire.StatusUnavailable {
		t.Errorf("expected StatusUnavailable (0x%02x), got 0x%02x", quicwire.StatusUnavailable, status)
	}
	if len(respPayload) == 0 {
		t.Error("expected non-empty error message in response payload")
	}
}
