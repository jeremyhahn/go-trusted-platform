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

package ceremony

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

const (
	defaultQUICTimeout     = 30 * time.Second
	defaultQUICIdleTimeout = 60 * time.Second
)

// QUICAdapter drives ceremony operations via the QUIC wire protocol.
// Payload layout: [sub-opcode byte][MsgPack-encoded request].
type QUICAdapter struct {
	endpoint  string
	tlsConfig *tls.Config

	mu     sync.RWMutex
	conn   *quicgo.Conn
	closed bool
}

// NewQUICAdapter returns an unconfigured QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		tlsConfig: helpers.QUICTLSConfig(),
	}
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

// sendSub performs a QUIC request against OpCeremonyCategory, wrapping the
// sub-opcode as the first payload byte.
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

	req := &quicwire.Request{Opcode: quicwire.OpCeremonyCategory, Payload: payload}
	if err := quicwire.WriteRequest(stream, req); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	resp, err := quicwire.ReadResponse(stream)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Status != quicwire.StatusOK {
		return fmt.Errorf("QUIC ceremony sub 0x%02X failed: status 0x%02X", sub, resp.Status)
	}
	if out != nil && len(resp.Payload) > 0 {
		if err := quicwire.DecodePayload(resp.Payload, out); err != nil {
			return fmt.Errorf("decode payload: %w", err)
		}
	}
	return nil
}

// Init invokes the ceremony init sub-opcode.
func (q *QUICAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	if req == nil {
		req = &ceremonysdk.InitRequest{}
	}
	in := &quic.CeremonyInitReq{
		SOPIN: req.SOPIN, UserPIN: req.UserPIN, Threshold: req.Threshold,
		Hostname: req.Hostname, SANs: req.SANs, CredentialSealStrategy: req.CredentialSealStrategy,
	}
	var wire quic.CeremonyInitResp
	if err := q.sendSub(ctx, quicwire.CeremonySubInit, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyInit", Err: err}
	}
	out := &ceremonysdk.InitResponse{
		CeremonyID: wire.CeremonyID,
		State:      ceremonysdk.CeremonyState(wire.State),
	}
	if !wire.InitializedAt.IsZero() {
		t := wire.InitializedAt
		out.InitializedAt = &t
	}
	return out, nil
}

// Status invokes the ceremony status sub-opcode.
func (q *QUICAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	var wire quic.CeremonyStatusResp
	if err := q.sendSub(ctx, quicwire.CeremonySubStatus, nil, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyStatus", Err: err}
	}
	out := &ceremonysdk.StatusResponse{
		CeremonyID:       wire.CeremonyID,
		State:            ceremonysdk.CeremonyState(wire.State),
		Threshold:        wire.Threshold,
		OfficersEnrolled: wire.OfficersEnrolled,
		OfficersRequired: wire.OfficersRequired,
	}
	if !wire.InitializedAt.IsZero() {
		t := wire.InitializedAt
		out.InitializedAt = &t
	}
	return out, nil
}

// ClaimCertBegin invokes the claim-cert begin sub-opcode.
func (q *QUICAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimCertBeginRequest{}
	}
	in := &quic.CeremonyClaimCertBeginReq{
		Username:          req.Username,
		AuthenticatorType: string(req.AuthenticatorType),
		Slot:              req.Slot,
		CredentialID:      req.CredentialID,
	}
	var wire quic.CeremonyClaimCertBeginResp
	if err := q.sendSub(ctx, quicwire.CeremonySubClaimCertBegin, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyClaimCertBegin", Err: err}
	}
	out := &ceremonysdk.ClaimCertBeginResponse{
		Nonce:       wire.Nonce,
		ChallengeID: wire.ChallengeID,
	}
	if !wire.ExpiresAt.IsZero() {
		t := wire.ExpiresAt
		out.ExpiresAt = &t
	}
	return out, nil
}

// ClaimCertComplete invokes the claim-cert complete sub-opcode.
func (q *QUICAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimCertCompleteRequest{}
	}
	in := &quic.CeremonyClaimCertCompleteReq{
		Username: req.Username, Nonce: req.Nonce, Signature: req.Signature,
	}
	var wire quic.CeremonyClaimCertCompleteResp
	if err := q.sendSub(ctx, quicwire.CeremonySubClaimCertComplete, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyClaimCertComplete", Err: err}
	}
	return &ceremonysdk.ClaimCertCompleteResponse{
		Certificate: wire.CertificatePEM,
		Chain:       wire.ChainPEM,
	}, nil
}

// ClaimShareBegin invokes the claim-share-begin sub-opcode.
func (q *QUICAdapter) ClaimShareBegin(ctx context.Context, req *ceremonysdk.ClaimShareBeginRequest) (*ceremonysdk.ClaimShareBeginResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimShareBeginRequest{}
	}
	in := &quic.CeremonyClaimShareBeginReq{Username: req.Username}
	var wire quic.CeremonyClaimShareBeginResp
	if err := q.sendSub(ctx, quicwire.CeremonySubClaimShareBegin, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyClaimShareBegin", Err: err}
	}
	resp := &ceremonysdk.ClaimShareBeginResponse{Nonce: wire.Nonce}
	if !wire.ExpiresAt.IsZero() {
		t := wire.ExpiresAt
		resp.ExpiresAt = &t
	}
	return resp, nil
}

// ClaimShareComplete invokes the claim-share-complete sub-opcode.
func (q *QUICAdapter) ClaimShareComplete(ctx context.Context, req *ceremonysdk.ClaimShareCompleteRequest) (*ceremonysdk.ClaimShareCompleteResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimShareCompleteRequest{}
	}
	in := &quic.CeremonyClaimShareCompleteReq{
		Username:  req.Username,
		Nonce:     req.Nonce,
		Signature: req.Signature,
	}
	var wire quic.CeremonyClaimShareCompleteResp
	if err := q.sendSub(ctx, quicwire.CeremonySubClaimShareComplete, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonyClaimShareComplete", Err: err}
	}
	return &ceremonysdk.ClaimShareCompleteResponse{Share: wire.Share, Index: wire.Index}, nil
}

// SignCSR invokes the sign-csr sub-opcode.
func (q *QUICAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	if req == nil {
		req = &ceremonysdk.SignCSRRequest{}
	}
	in := &quic.CeremonySignCSRReq{
		Username: req.Username, SOPIN: req.SOPIN, CSRPEM: req.CSRPEM, Role: string(req.Role),
	}
	var wire quic.CeremonySignCSRResp
	if err := q.sendSub(ctx, quicwire.CeremonySubSignCSR, in, &wire); err != nil {
		return nil, ErrCallFailed{Protocol: "QUIC", Method: "CeremonySignCSR", Err: err}
	}
	return &ceremonysdk.SignCSRResponse{
		Certificate: wire.CertificatePEM,
		Chain:       wire.ChainPEM,
	}, nil
}

var _ CeremonyCommands = (*QUICAdapter)(nil)
