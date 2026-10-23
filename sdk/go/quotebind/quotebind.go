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

// Package quotebind checks that a node's TPM quote was produced for the
// connection the caller asked over (#482).
//
// The node never quotes a caller's nonce as sent: it quotes
// SHA-256(nonce || binding), where binding is the TLS exporter of the
// connection the request arrived on (label EXPORTER-attested-peer), and
// echoes the binding. A caller that derives the same exporter from its own
// end of the connection and finds that value in the signed quote knows the
// quote came from the node terminating its connection. A relay that
// forwards the nonce over a second connection gets a quote bound to the
// second connection, which Check refuses.
//
// The check reads the qualifying data out of the quote; the quote's
// signature must still be verified against the node's attestation key
// (VerifyAttestationQuote with the binding, or locally) before the quote is
// evidence of anything.
package quotebind

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Capture records the channel binding of the connection one quote call
// travels on. Use one Capture per call: pass Option() to the call, then
// Check the quote it returns.
type Capture struct {
	binding []byte
}

// Option returns the call option that has the transport adapter hand the
// attested-peer binding of the call's connection to c before the request
// is sent. Transports with no TLS 1.3 connection refuse the call.
func (c *Capture) Option() grpc.CallOption {
	return transport.WithExportedChannelBinding(exportPeerBinding, func(_ context.Context, binding []byte) error {
		c.binding = binding
		return nil
	})
}

// exportPeerBinding derives the attested-peer binding of a TLS 1.3
// connection. TLS 1.2 is refused, as the daemon refuses it: its exporter
// is not bound to the handshake without the extended master secret.
func exportPeerBinding(state *tls.ConnectionState) ([]byte, error) {
	if state == nil {
		return nil, &transport.ErrChannelUnbound{Reason: "no TLS connection state"}
	}
	if state.Version != tls.VersionTLS13 {
		return nil, &transport.ErrChannelUnbound{Reason: "TLS 1.3 is required"}
	}
	return xkms.PeerChannelBinding(state)
}

// Binding returns the binding the call's connection exported, or nil if
// the call never reached a connection.
func (c *Capture) Binding() []byte {
	return c.binding
}

// Check verifies that quote — a marshaled TPMS_ATTEST — carries
// SHA-256(nonce || binding) for the binding of the caller's own
// connection.
func (c *Capture) Check(nonce, quote []byte) error {
	if len(c.binding) == 0 {
		return &ErrQuoteNotBound{Reason: "no channel binding was derived for the call"}
	}
	quoted, err := QuotedData(quote)
	if err != nil {
		return err
	}
	if !bytes.Equal(quoted, xkms.PeerQualifyingData(nonce, c.binding)) {
		return &ErrQuoteNotBound{Reason: "the quote does not carry the nonce bound to this connection"}
	}
	return nil
}

// CheckEcho is Check for a reply that also echoes the binding the node
// derived: the echo must be the caller's own binding.
func (c *Capture) CheckEcho(nonce, echoedBinding, quote []byte) error {
	if len(c.binding) == 0 {
		return &ErrQuoteNotBound{Reason: "no channel binding was derived for the call"}
	}
	if !bytes.Equal(echoedBinding, c.binding) {
		return &ErrQuoteNotBound{Reason: "the node derived its binding from a different connection"}
	}
	return c.Check(nonce, quote)
}

// QuotedData returns the qualifying data (TPMS_ATTEST extraData) a
// marshaled quote carries. Attestation structures other than a quote
// (certify, NV certify, ...) are refused: their qualifying data proves
// nothing about a connection.
func QuotedData(quote []byte) ([]byte, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote)
	if err != nil {
		return nil, &ErrQuoteMalformed{Reason: "not a TPMS_ATTEST structure", Cause: err}
	}
	if attest.Type != tpm2.TPMSTAttestQuote {
		return nil, &ErrQuoteMalformed{Reason: fmt.Sprintf("attestation type %#x is not a quote", uint16(attest.Type))}
	}
	return attest.ExtraData.Buffer, nil
}
