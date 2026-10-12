// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quic

import (
	"context"
	"crypto/tls"
)

type connectionTLSKey struct{}

// WithConnectionTLS returns a context carrying the TLS state of the QUIC
// connection a request arrived on. The state is the handshake's own, so its
// exporter value is the connection's, not anything the client supplied.
func WithConnectionTLS(ctx context.Context, state *tls.ConnectionState) context.Context {
	return context.WithValue(ctx, connectionTLSKey{}, state)
}

// ConnectionTLS returns the TLS state WithConnectionTLS stored, or nil when
// the request did not arrive over a QUIC connection.
func ConnectionTLS(ctx context.Context) *tls.ConnectionState {
	state, ok := ctx.Value(connectionTLSKey{}).(*tls.ConnectionState)
	if !ok {
		return nil
	}
	return state
}
