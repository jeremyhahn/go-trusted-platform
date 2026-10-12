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

package transport

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
)

const (
	// ChannelBindingLabel is the RFC 8446 §7.5 exporter label the channel
	// binding is derived under. Both ends of a connection derive it; neither
	// sends it.
	ChannelBindingLabel = "EXPORTER-go-trusted-platform-diskless-boot"

	// ChannelBindingSize is the length of the exported channel binding.
	ChannelBindingSize = 32
)

// ExportChannelBinding derives the channel binding of a TLS 1.3 connection.
// The client proves over it and the daemon checks the proof against its own
// derivation from the same connection; TLS 1.2 is refused because its
// exporter is not bound to the handshake without the extended master secret.
func ExportChannelBinding(state *tls.ConnectionState) ([]byte, error) {
	if state == nil {
		return nil, &ErrChannelUnbound{Reason: "no TLS connection state"}
	}
	if state.Version != tls.VersionTLS13 {
		return nil, &ErrChannelUnbound{Reason: "TLS 1.3 is required"}
	}
	binding, err := state.ExportKeyingMaterial(ChannelBindingLabel, nil, ChannelBindingSize)
	if err != nil {
		return nil, &ErrChannelUnbound{Reason: "keying material export failed", Cause: err}
	}
	return binding, nil
}

// BindFunc receives the channel binding of the connection a call is about
// to travel on — the RFC 8446 §7.5 exporter the daemon reads from the same
// connection — and completes the request with it, typically by signing it
// or quoting over it. The adapter invokes it after the connection exists
// and before the request is encoded.
type BindFunc func(ctx context.Context, binding []byte) error

// channelBindingOption carries a BindFunc through a gRPC call's options to
// the adapter that owns the connection.
type channelBindingOption struct {
	grpc.EmptyCallOption
	bind BindFunc
}

// WithChannelBinding asks the transport adapter to call bind with the
// channel binding of the connection the call travels on, before sending
// the request. Adapters whose transport carries no TLS 1.3 connection
// refuse such calls with ErrChannelBindingUnavailable instead of sending
// a request that could never be bound.
func WithChannelBinding(bind BindFunc) grpc.CallOption {
	return channelBindingOption{bind: bind}
}

// ChannelBindingFrom returns the BindFunc carried by opts, if any.
func ChannelBindingFrom(opts []grpc.CallOption) (BindFunc, bool) {
	for _, opt := range opts {
		if binding, ok := opt.(channelBindingOption); ok && binding.bind != nil {
			return binding.bind, true
		}
	}
	return nil, false
}

// BindChannel derives the channel binding from state — the TLS state of
// the connection the call is about to travel on — and hands it to bind.
func BindChannel(ctx context.Context, transportName string, state *tls.ConnectionState, bind BindFunc) error {
	binding, err := ExportChannelBinding(state)
	if err != nil {
		return &ErrChannelBindingUnavailable{Transport: transportName, Reason: "the connection exports no channel binding", Cause: err}
	}
	return bind(ctx, binding)
}

// ErrChannelBindingUnavailable is returned when a call needs the channel
// binding of its connection and the transport cannot provide one: the
// transport carries no TLS 1.3 connection (Unix socket, MCP, embedded), or
// the connection could not be established.
type ErrChannelBindingUnavailable struct {
	Transport string
	Reason    string
	Cause     error
}

func (e *ErrChannelBindingUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transport %s: channel binding unavailable: %s: %v", e.Transport, e.Reason, e.Cause)
	}
	return fmt.Sprintf("transport %s: channel binding unavailable: %s", e.Transport, e.Reason)
}

func (e *ErrChannelBindingUnavailable) Unwrap() error { return e.Cause }

// ErrChannelUnbound reports a TLS connection no channel binding can be
// derived from: no connection state, a version below TLS 1.3, or an
// exporter that produced no keying material.
type ErrChannelUnbound struct {
	Reason string
	Cause  error
}

func (e *ErrChannelUnbound) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("transport: channel cannot be bound: %s: %v", e.Reason, e.Cause)
	}
	return "transport: channel cannot be bound: " + e.Reason
}

func (e *ErrChannelUnbound) Unwrap() error { return e.Cause }
