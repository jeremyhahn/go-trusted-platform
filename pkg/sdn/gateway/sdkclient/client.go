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

// Package sdkclient dials the go-quicbaas SDK from gatewayd. gatewayd has no
// in-process quicbaas service to source clients from, so every collaborator
// that reaches quicbaasd directly (the proxy audit sink, the secret store)
// goes through the same address + transport mapping here.
package sdkclient

import (
	"crypto/tls"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// Transport names accepted by TransportOptions. Empty, "grpc" or an
// unknown name lets the SDK auto-detect from the address (gRPC by default,
// a .sock path resolves to unix).
const (
	TransportUnix = "unix"
	TransportREST = "rest"
	TransportQUIC = "quic"
	TransportMCP  = "mcp"
)

// TransportOptions maps a transport name to the go-quicbaas SDK option,
// mirroring sdk/go's own quicbaasTransportOptions: empty or unknown returns
// nil so the SDK auto-detects from addr.
func TransportOptions(addr, transport string) []quicbaassdk.Option {
	switch transport {
	case TransportUnix:
		return []quicbaassdk.Option{quicbaassdk.WithUnix(addr)}
	case TransportREST:
		return []quicbaassdk.Option{quicbaassdk.WithREST()}
	case TransportQUIC:
		return []quicbaassdk.Option{quicbaassdk.WithQUIC()}
	case TransportMCP:
		return []quicbaassdk.Option{quicbaassdk.WithMCP()}
	default:
		return nil
	}
}

// Dial opens a go-quicbaas SDK client to quicbaasd at addr over transport.
// A non-nil tlsCfg authenticates the connection (the SDK refuses every
// connection without one); nil leaves the SDK's own TLS handling in place.
func Dial(addr, transport string, tlsCfg *tls.Config) (quicbaassdk.Client, error) {
	opts := TransportOptions(addr, transport)
	if tlsCfg != nil {
		opts = append(opts, quicbaassdk.WithTLSConfig(tlsCfg))
	}
	return quicbaassdk.NewClient(addr, opts...)
}
