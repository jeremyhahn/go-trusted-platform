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

// Package channelbind is the attesting node's half of the attestation
// channel binding (#482). It covers every endpoint that has the node's TPM
// quote caller-supplied data: collect-host, the attestation quote and the
// TPM quote.
//
// A collector sends a bare nonce. The node derives the TLS exporter binding
// of the connection the request arrived on and quotes
// SHA-256(nonce || binding), never the nonce as sent. The collector derives
// the same binding from its own end and accepts the quote only when the two
// agree. A relay that forwards the nonce to a healthy node over a second
// connection gets a quote bound to that second connection, which the
// collector refuses: the attested state belongs to whoever terminates the
// collector's TLS connection, not to whoever the request was passed on to.
//
// Binding is a property of the connection, so a request that has no TLS
// connection (the Unix socket, the embedded transport, plain HTTP), or whose
// exporter cannot be read, is refused. Quoting the bare nonce instead would
// make the node exactly the oracle a relay needs.
package channelbind

import (
	"context"
	"crypto/tls"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// Transport names a refusal (ErrChannelBindingRequired) reports.
const (
	TransportREST = "REST"
	TransportMCP  = "MCP"
	TransportQUIC = "QUIC"
)

// connectionKey is the context key WithConnectionTLS stores under.
type connectionKey struct{}

// connection wraps the state so a request recorded with no TLS (plain HTTP)
// is still distinguishable from one that was never recorded.
type connection struct {
	transport string
	state     *tls.ConnectionState
}

// WithConnectionTLS records the TLS state of the connection a request
// arrived on, for a transport whose handler has it in hand (REST's and
// MCP-over-HTTP's http.Request.TLS). transport names the connection in a
// refusal. A nil state records a request that arrived without TLS.
func WithConnectionTLS(ctx context.Context, transport string, state *tls.ConnectionState) context.Context {
	return context.WithValue(ctx, connectionKey{}, connection{transport: transport, state: state})
}

// ConnectionTLS returns the state and transport WithConnectionTLS recorded.
// The boolean reports whether anything was recorded; the state is nil when
// the request arrived without TLS.
func ConnectionTLS(ctx context.Context) (*tls.ConnectionState, string, bool) {
	conn, ok := ctx.Value(connectionKey{}).(connection)
	return conn.state, conn.transport, ok
}

// Bound is a nonce bound to one connection: the binding the node derived
// from the connection, and the value it has the TPM quote.
type Bound struct {
	// Binding is the TLS exporter of the connection (label
	// EXPORTER-attested-peer, 32 bytes). A node returns it so a direct
	// caller can compare it with the value it derives from its own end.
	Binding []byte
	// QualifyingData is SHA-256(nonce || Binding), what the TPM quotes.
	QualifyingData []byte
}

// Bind binds nonce to the connection whose TLS state is state. transport
// names that connection in the refusal when it carries no binding.
func Bind(state *tls.ConnectionState, transport string, nonce []byte) (Bound, error) {
	binding, err := xkmssdk.PeerChannelBinding(state)
	if err != nil {
		return Bound{}, ErrChannelBindingRequired{Transport: transport, Cause: err}
	}
	return Bound{Binding: binding, QualifyingData: xkmssdk.PeerQualifyingData(nonce, binding)}, nil
}

// QualifyingData returns the value a node quotes for a collector's nonce:
// SHA-256(nonce || binding), where binding is the TLS exporter of the
// connection the request arrived on. transport names that connection in the
// refusal when it carries no binding.
func QualifyingData(state *tls.ConnectionState, transport string, nonce []byte) ([]byte, error) {
	bound, err := Bind(state, transport, nonce)
	if err != nil {
		return nil, err
	}
	return bound.QualifyingData, nil
}

// ExpectedQualifyingData is the verifier's side: the value a quote must
// carry for nonce. With no binding that is the nonce itself; with one it is
// SHA-256(nonce || binding), the value a node quotes over a bound
// connection. A binding without a nonce is refused, since it would bind
// nothing.
func ExpectedQualifyingData(nonce, binding []byte) ([]byte, error) {
	if len(binding) == 0 {
		return nonce, nil
	}
	if len(nonce) == 0 {
		return nil, ErrBindingWithoutNonce{}
	}
	return xkmssdk.PeerQualifyingData(nonce, binding), nil
}
