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

package channelbind

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrChannelBindingRequired refuses a quote request that arrived on a
// connection with no channel binding: a transport with no TLS (the Unix
// socket, the embedded transport, plain HTTP, MCP over stdio), or a TLS
// connection whose exporter cannot be read. The node never quotes the bare
// nonce in its place.
type ErrChannelBindingRequired struct {
	Transport string
	Cause     error
}

func (e ErrChannelBindingRequired) Error() string {
	return "attestation: a quote is bound to the TLS connection it is " +
		"requested over, and this " + e.Transport + " request has none"
}

func (e ErrChannelBindingRequired) Unwrap() error { return e.Cause }

// GRPCStatus classifies the refusal as FailedPrecondition: the request is
// well formed, but the connection it arrived on cannot carry it.
func (e ErrChannelBindingRequired) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}

// ErrBindingWithoutNonce refuses a verification that names a channel
// binding but no nonce to bind.
type ErrBindingWithoutNonce struct{}

func (ErrBindingWithoutNonce) Error() string {
	return "attestation: a channel binding was given without the nonce it binds"
}

// GRPCStatus classifies the refusal as InvalidArgument.
func (e ErrBindingWithoutNonce) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}
