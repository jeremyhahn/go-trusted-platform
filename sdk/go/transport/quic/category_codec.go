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

package quic

// Translation between gRPC messages and the daemon's category-opcode wire
// structs.
//
// The payload codec keys on exact Go field names, and the daemon wire structs
// (pkg/api/quic/phase35_types.go, sdk/go/wire/quicwire) do not share the pb
// names (CredentialID vs CredentialId, RPID vs RpId, GatewayID vs GatewayId,
// VTEP vs Vtep) and carry enums as strings and times as time.Time or Unix
// seconds. A by-name decode would drop fields silently, leaving zero values,
// so methods whose shapes differ translate their request into the wire struct
// and their response back onto the pb reply through the maps below.

import (
	"math"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

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
func requestEncoder[P any](method string, convert func(*P) (interface{}, error)) categoryRequestEncoder {
	return func(args interface{}) (interface{}, error) {
		req, ok := args.(*P)
		if !ok || req == nil {
			return nil, ErrInvalidArgsType{Method: method}
		}
		return convert(req)
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
		if err := quicwire.DecodePayload(payload, &wire); err != nil {
			return ErrDecodingFailed{Err: err}
		}
		return apply(&wire, out)
	}
}

// registerCategoryCodecs adds a service's translators to the shared
// category-opcode tables. It runs from each service file's init.
func registerCategoryCodecs(encoders map[string]categoryRequestEncoder, decoders map[string]categoryResponseDecoder) {
	for method, encode := range encoders {
		categoryRequestEncoders[method] = encode
	}
	for method, decode := range decoders {
		categoryResponseDecoders[method] = decode
	}
}

// categoryPage reports one page of a paged list reply: the entries it
// carried and the number the daemon holds in all.
type categoryPage struct {
	received int32
	total    int32
}

// categoryPager drives a category list method the daemon serves one page at
// a time, so the caller still receives the whole list in one reply, as over
// gRPC. request builds the wire request for the page starting at offset, and
// decode appends that page's entries to the pb reply.
type categoryPager struct {
	request func(args interface{}, offset int32) (interface{}, error)
	decode  func(payload []byte, reply interface{}) (categoryPage, error)
}

// categoryPagers routes the paged category list methods. A paged method
// takes this route instead of the request encoder and reply decoder tables.
var categoryPagers = map[string]categoryPager{}

// pagedRequest builds a categoryPager request that type-checks the pb
// request and converts it into the daemon wire struct for one page.
func pagedRequest[P any](method string, convert func(req *P, offset int32) interface{}) func(interface{}, int32) (interface{}, error) {
	return func(args interface{}, offset int32) (interface{}, error) {
		req, ok := args.(*P)
		if !ok || req == nil {
			return nil, ErrInvalidArgsType{Method: method}
		}
		return convert(req, offset), nil
	}
}

// pageCount converts a page's entry count to the wire's int32, capped at the
// largest count the wire carries.
func pageCount(n int) int32 {
	return int32(min(n, math.MaxInt32))
}
