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

package fido2

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

const (
	defaultQUICTimeout     = 30 * time.Second
	defaultQUICIdleTimeout = 60 * time.Second
)

// QUICAdapter drives FIDO2 operations via QUIC. Payload layout:
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
	return &QUICAdapter{tlsConfig: helpers.QUICTLSConfig()}
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

// sendSub issues a FIDO2 category request with a sub-opcode prefix byte.
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
		encoded, err := quicwire.EncodePayload(in)
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

	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: quicwire.OpFIDO2Category, Payload: payload}); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Status != quicwire.StatusOK {
		return fmt.Errorf("QUIC fido2 sub 0x%02X failed: status 0x%02X", sub, resp.Status)
	}
	if out != nil && len(resp.Payload) > 0 {
		return quicwire.DecodePayload(resp.Payload, out)
	}
	return nil
}

// quicToSDKDevice converts a QUIC FIDO2 device to the SDK type.
func quicToSDKDevice(d quic.FIDO2Device) fido2sdk.Device {
	return fido2sdk.Device{
		ID:           d.ID,
		Path:         d.Path,
		Manufacturer: d.Manufacturer,
		Product:      d.Product,
		ProductID:    d.ProductID,
		VendorID:     d.VendorID,
	}
}

// ListDevices issues FIDO2SubListDevices.
func (q *QUICAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	_ = req
	var wire quic.FIDO2ListDevicesResp
	if err := q.sendSub(ctx, quicwire.FIDO2SubListDevices, nil, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "FIDO2ListDevices", Err: err}
	}
	out := &fido2sdk.ListDevicesResponse{Devices: make([]fido2sdk.Device, 0, len(wire.Devices))}
	for _, d := range wire.Devices {
		out.Devices = append(out.Devices, quicToSDKDevice(d))
	}
	return out, nil
}

// WaitDevice issues FIDO2SubWaitDevice.
func (q *QUICAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	if req == nil {
		req = &fido2sdk.WaitDeviceRequest{}
	}
	in := &quic.FIDO2WaitDeviceReq{TimeoutSeconds: req.TimeoutSeconds}
	var wire quic.FIDO2WaitDeviceResp
	if err := q.sendSub(ctx, quicwire.FIDO2SubWaitDevice, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "FIDO2WaitDevice", Err: err}
	}
	return &fido2sdk.WaitDeviceResponse{Device: quicToSDKDevice(wire.Device)}, nil
}

// Info issues FIDO2SubInfo.
func (q *QUICAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	if req == nil {
		req = &fido2sdk.InfoRequest{}
	}
	in := &quic.FIDO2InfoReq{Device: req.Device}
	var wire quic.FIDO2InfoResp
	if err := q.sendSub(ctx, quicwire.FIDO2SubInfo, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "FIDO2Info", Err: err}
	}
	return &fido2sdk.InfoResponse{
		Info: fido2sdk.Info{
			Device:          quicToSDKDevice(wire.Device),
			AAGUID:          wire.AAGUID,
			FirmwareVersion: wire.FirmwareVersion,
			Extensions:      wire.Extensions,
			Options:         wire.Options,
			MaxMsgSize:      wire.MaxMsgSize,
		},
	}, nil
}

// Register issues FIDO2SubRegister.
func (q *QUICAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	if req == nil {
		req = &fido2sdk.RegisterRequest{}
	}
	in := &quic.FIDO2RegisterReq{
		Username: req.Username, Role: string(req.Role),
		RequirePIN: req.RequirePIN, RequireUV: req.RequireUV, RPID: req.RPID,
	}
	var wire quic.FIDO2RegisterResp
	if err := q.sendSub(ctx, quicwire.FIDO2SubRegister, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "FIDO2Register", Err: err}
	}
	return &fido2sdk.RegisterResponse{
		CredentialID: wire.CredentialID, AAGUID: wire.AAGUID, PublicKeyPEM: wire.PublicKeyPEM,
	}, nil
}

// Authenticate issues FIDO2SubAuthenticate.
func (q *QUICAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	if req == nil {
		req = &fido2sdk.AuthenticateRequest{}
	}
	in := &quic.FIDO2AuthenticateReq{CredentialID: req.CredentialID}
	var wire quic.FIDO2AuthenticateResp
	if err := q.sendSub(ctx, quicwire.FIDO2SubAuthenticate, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "FIDO2Authenticate", Err: err}
	}
	return &fido2sdk.AuthenticateResponse{Authenticated: wire.Authenticated, Counter: wire.Counter}, nil
}

var _ FIDO2Commands = (*QUICAdapter)(nil)
