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

//go:build integration

package piv

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

const (
	defaultQUICTimeout     = 30 * time.Second
	defaultQUICIdleTimeout = 60 * time.Second
)

// QUICAdapter drives PIV operations via QUIC. Payload layout:
// [sub-opcode byte][MsgPack-encoded request].
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config

	mu     sync.RWMutex
	conn   *quicgo.Conn
	closed bool
}

// NewQUICAdapter returns an unconfigured QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{tlsConfig: helpers.QUICTLSConfig([]string{"platform-quic"})}
}

// Name returns "QUIC".
func (q *QUICAdapter) Name() string { return "QUIC" }

// Setup dials platformd over QUIC.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformQUIC
	}
	q.endpoint = endpoint

	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrConnectionFailed{Protocol: "QUIC", Endpoint: endpoint, Err: fmt.Errorf("adapter closed")}
	}
	dialCtx, cancel := context.WithTimeout(ctx, defaultQUICTimeout)
	defer cancel()
	conn, err := quicgo.DialAddr(dialCtx, endpoint, q.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  defaultQUICIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return ErrConnectionFailed{Protocol: "QUIC", Endpoint: endpoint, Err: err}
	}
	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || q.conn == nil {
		return nil
	}
	q.closed = true
	return q.conn.CloseWithError(0, "adapter teardown")
}

// sendSub issues a PIV category request with a sub-opcode prefix byte.
func (q *QUICAdapter) sendSub(ctx context.Context, sub byte, in interface{}, out interface{}) error {
	q.mu.RLock()
	conn := q.conn
	closed := q.closed
	q.mu.RUnlock()
	if closed || conn == nil {
		return ErrConnectionFailed{Protocol: "QUIC", Endpoint: q.endpoint, Err: fmt.Errorf("no connection")}
	}

	var body []byte
	if in != nil {
		encoded, err := quic.EncodePayload(in)
		if err != nil {
			return fmt.Errorf("encode payload: %w", err)
		}
		body = encoded
	}
	payload := make([]byte, 1+len(body))
	payload[0] = sub
	copy(payload[1:], body)

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if err := quic.WriteRequest(stream, &quic.Request{Opcode: quic.OpPIVCategory, Payload: payload}); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	resp, err := quic.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Status != quic.StatusOK {
		return fmt.Errorf("QUIC piv sub 0x%02X failed: status 0x%02X", sub, resp.Status)
	}
	if out != nil && len(resp.Payload) > 0 {
		return quic.DecodePayload(resp.Payload, out)
	}
	return nil
}

// quicToSDKDevice converts a QUIC PIV device to the SDK type.
func quicToSDKDevice(d quic.PIVDevice) pivsdk.Device {
	return pivsdk.Device{
		ID:              d.ID,
		Name:            d.Name,
		Manufacturer:    d.Manufacturer,
		Model:           d.Model,
		Serial:          d.Serial,
		FirmwareVersion: d.FirmwareVersion,
	}
}

// quicToSDKSlot converts a QUIC PIV slot to the SDK type.
func quicToSDKSlot(s quic.PIVSlot) pivsdk.Slot {
	return pivsdk.Slot{
		ID:             s.ID,
		Name:           s.Name,
		Algorithm:      pivsdk.Algorithm(s.Algorithm),
		HasKey:         s.HasKey,
		HasCertificate: s.HasCertificate,
	}
}

// ListDevices issues PIVSubListDevices.
func (q *QUICAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	_ = req
	var wire quic.PIVListDevicesResp
	if err := q.sendSub(ctx, quic.PIVSubListDevices, nil, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVListDevices", Err: err}
	}
	out := &pivsdk.ListDevicesResponse{Devices: make([]pivsdk.Device, 0, len(wire.Devices))}
	for _, d := range wire.Devices {
		out.Devices = append(out.Devices, quicToSDKDevice(d))
	}
	return out, nil
}

// ListSlots issues PIVSubListSlots.
func (q *QUICAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	if req == nil {
		req = &pivsdk.ListSlotsRequest{}
	}
	in := &quic.PIVListSlotsReq{Device: req.Device}
	var wire quic.PIVListSlotsResp
	if err := q.sendSub(ctx, quic.PIVSubListSlots, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVListSlots", Err: err}
	}
	out := &pivsdk.ListSlotsResponse{Slots: make([]pivsdk.Slot, 0, len(wire.Slots))}
	for _, s := range wire.Slots {
		out.Slots = append(out.Slots, quicToSDKSlot(s))
	}
	return out, nil
}

// SlotInfo issues PIVSubSlotInfo.
func (q *QUICAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	if req == nil {
		req = &pivsdk.SlotInfoRequest{}
	}
	in := &quic.PIVSlotInfoReq{Slot: req.Slot, Device: req.Device}
	var wire quic.PIVSlotInfoResp
	if err := q.sendSub(ctx, quic.PIVSubSlotInfo, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVSlotInfo", Err: err}
	}
	return &pivsdk.SlotInfoResponse{
		Slot:           quicToSDKSlot(wire.Slot),
		PublicKeyPEM:   wire.PublicKeyPEM,
		CertificatePEM: wire.CertificatePEM,
	}, nil
}

// Generate issues PIVSubGenerate.
func (q *QUICAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	if req == nil {
		req = &pivsdk.GenerateRequest{}
	}
	in := &quic.PIVGenerateReq{Slot: req.Slot, Algorithm: string(req.Algorithm), PIN: req.PIN}
	var wire quic.PIVGenerateResp
	if err := q.sendSub(ctx, quic.PIVSubGenerate, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVGenerate", Err: err}
	}
	return &pivsdk.GenerateResponse{PublicKeyPEM: wire.PublicKeyPEM}, nil
}

// Import issues PIVSubImport.
func (q *QUICAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	if req == nil {
		req = &pivsdk.ImportRequest{}
	}
	in := &quic.PIVImportReq{Slot: req.Slot, PrivateKeyPEM: req.PrivateKeyPEM, PIN: req.PIN}
	var wire quic.PIVImportResp
	if err := q.sendSub(ctx, quic.PIVSubImport, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVImport", Err: err}
	}
	return &pivsdk.ImportResponse{Imported: wire.Imported}, nil
}

// Sign issues PIVSubSign.
func (q *QUICAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	if req == nil {
		req = &pivsdk.SignRequest{}
	}
	in := &quic.PIVSignReq{Slot: req.Slot, Payload: req.Payload, PIN: req.PIN}
	var wire quic.PIVSignResp
	if err := q.sendSub(ctx, quic.PIVSubSign, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVSign", Err: err}
	}
	return &pivsdk.SignResponse{Signature: wire.Signature}, nil
}

// Attest issues PIVSubAttest.
func (q *QUICAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	if req == nil {
		req = &pivsdk.AttestRequest{}
	}
	in := &quic.PIVAttestReq{Slot: req.Slot}
	var wire quic.PIVAttestResp
	if err := q.sendSub(ctx, quic.PIVSubAttest, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVAttest", Err: err}
	}
	return &pivsdk.AttestResponse{
		AttestationCertPEM:  wire.AttestationCertPEM,
		AttestationChainPEM: wire.AttestationChainPEM,
	}, nil
}

// Reset issues PIVSubReset.
func (q *QUICAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	if req == nil {
		req = &pivsdk.ResetRequest{}
	}
	in := &quic.PIVResetReq{Device: req.Device}
	var wire quic.PIVResetResp
	if err := q.sendSub(ctx, quic.PIVSubReset, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "PIVReset", Err: err}
	}
	return &pivsdk.ResetResponse{Reset: wire.Reset}, nil
}

var _ PIVCommands = (*QUICAdapter)(nil)
