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

package luks

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

const (
	defaultQUICTimeout     = 30 * time.Second
	defaultQUICIdleTimeout = 60 * time.Second
)

// QUICAdapter drives LUKS operations via QUIC. Payload layout:
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

// sendSub issues a LUKS category request with a sub-opcode prefix byte.
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

	if err := quicwire.WriteRequest(stream, &quicwire.Request{Opcode: quicwire.OpLUKSCategory, Payload: payload}); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Status != quicwire.StatusOK {
		return fmt.Errorf("QUIC luks sub 0x%02X failed: status 0x%02X", sub, resp.Status)
	}
	if out != nil && len(resp.Payload) > 0 {
		return quicwire.DecodePayload(resp.Payload, out)
	}
	return nil
}

// quicToSDKKeyslot converts a QUIC keyslot to the SDK type.
func quicToSDKKeyslot(k quic.LUKSKeyslot) lukssdk.Keyslot {
	return lukssdk.Keyslot{
		Slot:     k.Slot,
		Type:     lukssdk.KeyType(k.Type),
		KeySize:  k.KeySize,
		Priority: k.Priority,
	}
}

// Status issues LUKSSubStatus.
func (q *QUICAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	if req == nil {
		req = &lukssdk.StatusRequest{}
	}
	in := &quic.LUKSStatusReq{Device: req.Device}
	var wire quic.LUKSStatusResp
	if err := q.sendSub(ctx, quicwire.LUKSSubStatus, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSStatus", Err: err}
	}
	return &lukssdk.StatusResponse{
		Device: wire.Device, IsLUKS: wire.IsLUKS, Version: wire.Version,
		UUID: wire.UUID, Label: wire.Label, Cipher: wire.Cipher, ActiveSlots: wire.ActiveSlots,
	}, nil
}

// ListSlots issues LUKSSubListSlots.
func (q *QUICAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	if req == nil {
		req = &lukssdk.ListSlotsRequest{}
	}
	in := &quic.LUKSListSlotsReq{Device: req.Device}
	var wire quic.LUKSListSlotsResp
	if err := q.sendSub(ctx, quicwire.LUKSSubListSlots, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSListSlots", Err: err}
	}
	out := &lukssdk.ListSlotsResponse{
		Device: wire.Device,
		Slots:  make([]lukssdk.Keyslot, 0, len(wire.Slots)),
	}
	for _, s := range wire.Slots {
		out.Slots = append(out.Slots, quicToSDKKeyslot(s))
	}
	return out, nil
}

// Info issues LUKSSubInfo.
func (q *QUICAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	if req == nil {
		req = &lukssdk.InfoRequest{}
	}
	in := &quic.LUKSInfoReq{Device: req.Device}
	var wire quic.LUKSInfoResp
	if err := q.sendSub(ctx, quicwire.LUKSSubInfo, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSInfo", Err: err}
	}
	out := &lukssdk.InfoResponse{
		Device: wire.Device, UUID: wire.UUID, Label: wire.Label, Version: wire.Version,
		Cipher: wire.Cipher, KeySize: wire.KeySize, SectorSize: wire.SectorSize,
		MetadataJSON: wire.MetadataJSON,
		Slots:        make([]lukssdk.Keyslot, 0, len(wire.Slots)),
	}
	for _, s := range wire.Slots {
		out.Slots = append(out.Slots, quicToSDKKeyslot(s))
	}
	return out, nil
}

// EnrollPassphrase issues LUKSSubEnrollPassphrase.
func (q *QUICAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollPassphraseRequest{}
	}
	in := &quic.LUKSEnrollPassphraseReq{
		Device: req.Device, ExistingPassphrase: req.ExistingPassphrase, NewPassphrase: req.NewPassphrase,
	}
	var wire quic.LUKSEnrollPassphraseResp
	if err := q.sendSub(ctx, quicwire.LUKSSubEnrollPassphrase, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSEnrollPassphrase", Err: err}
	}
	return &lukssdk.EnrollPassphraseResponse{Slot: wire.Slot}, nil
}

// EnrollFIDO2 issues LUKSSubEnrollFIDO2.
func (q *QUICAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	if req == nil {
		req = &lukssdk.EnrollFIDO2Request{}
	}
	in := &quic.LUKSEnrollFIDO2Req{
		Device: req.Device, ExistingPassphrase: req.ExistingPassphrase,
		CredentialID: req.CredentialID, RequirePIN: req.RequirePIN, RequireUV: req.RequireUV,
	}
	var wire quic.LUKSEnrollFIDO2Resp
	if err := q.sendSub(ctx, quicwire.LUKSSubEnrollFIDO2, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSEnrollFIDO2", Err: err}
	}
	return &lukssdk.EnrollFIDO2Response{Slot: wire.Slot, TokenID: wire.TokenID}, nil
}

// EnrollTPM issues LUKSSubEnrollTPM.
func (q *QUICAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollTPMRequest{}
	}
	in := &quic.LUKSEnrollTPMReq{
		Device: req.Device, ExistingPassphrase: req.ExistingPassphrase,
		PCRs: req.PCRs, Handle: req.Handle,
	}
	var wire quic.LUKSEnrollTPMResp
	if err := q.sendSub(ctx, quicwire.LUKSSubEnrollTPM, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSEnrollTPM", Err: err}
	}
	return &lukssdk.EnrollTPMResponse{Slot: wire.Slot, TokenID: wire.TokenID}, nil
}

// EnrollRecovery issues LUKSSubEnrollRecovery.
func (q *QUICAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollRecoveryRequest{}
	}
	in := &quic.LUKSEnrollRecoveryReq{Device: req.Device, ExistingPassphrase: req.ExistingPassphrase}
	var wire quic.LUKSEnrollRecoveryResp
	if err := q.sendSub(ctx, quicwire.LUKSSubEnrollRecovery, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSEnrollRecovery", Err: err}
	}
	return &lukssdk.EnrollRecoveryResponse{Slot: wire.Slot, RecoveryKey: wire.RecoveryKey}, nil
}

// RemoveKey issues LUKSSubRemoveKey.
func (q *QUICAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	if req == nil {
		req = &lukssdk.RemoveKeyRequest{}
	}
	in := &quic.LUKSRemoveKeyReq{Device: req.Device, Slot: req.Slot}
	var wire quic.LUKSRemoveKeyResp
	if err := q.sendSub(ctx, quicwire.LUKSSubRemoveKey, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSRemoveKey", Err: err}
	}
	return &lukssdk.RemoveKeyResponse{Removed: wire.Removed}, nil
}

// TestUnlock issues LUKSSubTestUnlock.
func (q *QUICAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	if req == nil {
		req = &lukssdk.TestUnlockRequest{}
	}
	in := &quic.LUKSTestUnlockReq{Device: req.Device, Slot: req.Slot}
	var wire quic.LUKSTestUnlockResp
	if err := q.sendSub(ctx, quicwire.LUKSSubTestUnlock, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSTestUnlock", Err: err}
	}
	return &lukssdk.TestUnlockResponse{Unlocked: wire.Unlocked}, nil
}

// ChangePassphrase issues LUKSSubChangePassphrase.
func (q *QUICAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.ChangePassphraseRequest{}
	}
	in := &quic.LUKSChangePassphraseReq{
		Device: req.Device, Slot: req.Slot,
		OldPassphrase: req.OldPassphrase, NewPassphrase: req.NewPassphrase,
	}
	var wire quic.LUKSChangePassphraseResp
	if err := q.sendSub(ctx, quicwire.LUKSSubChangePassphrase, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "LUKSChangePassphrase", Err: err}
	}
	return &lukssdk.ChangePassphraseResponse{Changed: wire.Changed}, nil
}

var _ LUKSCommands = (*QUICAdapter)(nil)
