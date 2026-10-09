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
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// The payload codec keys on exact Go field names. A daemon wire struct whose
// names differ from the pb message's (GatewayID vs GatewayId, VTEP vs Vtep)
// would decode as zero values on a by-name decode, so such methods translate
// their request into the wire struct and their response back onto the pb
// reply through the encoders and decoders registered here.

// categoryRequestEncoder converts a gRPC request message into the daemon
// wire struct a category dispatcher decodes, for methods whose pb field
// names differ from the wire struct's.
type categoryRequestEncoder func(args interface{}) (interface{}, error)

// categoryRequestEncoders routes category-opcode methods whose requests need
// translating before encoding. Methods absent from this map encode the pb
// request directly. Entries are registered by the init of the file that
// owns each method's wire translation.
var categoryRequestEncoders = map[string]categoryRequestEncoder{}

// requestEncoder builds a categoryRequestEncoder that type-checks the pb
// request and converts it into the daemon wire struct.
func requestEncoder[P any](method string, convert func(*P) interface{}) categoryRequestEncoder {
	return func(args interface{}) (interface{}, error) {
		req, ok := args.(*P)
		if !ok || req == nil {
			return nil, ErrInvalidArgsType{Method: method}
		}
		return convert(req), nil
	}
}

// responseDecoder builds a categoryResponseDecoder that decodes the daemon
// wire struct W and applies it onto the pb reply R.
func responseDecoder[W any, R any](method string, apply func(*W, *R) error) categoryResponseDecoder {
	return func(payload []byte, reply interface{}) error {
		out, ok := reply.(*R)
		if !ok || out == nil {
			return ErrInvalidReplyType{Method: method}
		}
		var wire W
		if err := quicapi.DecodePayload(payload, &wire); err != nil {
			return ErrDecodingFailed{Err: err}
		}
		return apply(&wire, out)
	}
}
