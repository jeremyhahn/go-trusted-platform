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

import (
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The canonical QUIC wire contract for the device surface is the
// platform.v1 protobuf messages themselves: the adapter encodes the pb
// request structs directly and the daemon replies with the pb response
// structs (the payload codec keys on exact Go field names). Two RPCs
// share a wire opcode with their list counterparts, so their replies are
// derived from the list response here:
//
//   - CountDevices shares OpDeviceList with ListDevices.
//   - CountProfiles shares OpDeviceListProfiles with ListProfiles.
//
// The daemon always returns the full list response with the pagination
// total populated; these decoders project it onto the Count* reply.

// methodResponseDecoders routes non-category methods whose reply shape
// differs from the daemon wire response. Methods absent from this map
// decode directly into the pb reply via the default codec path.
var methodResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.DeviceService_CountDevices_FullMethodName:  decodeDeviceCountReply,
	platformv1.DeviceService_CountProfiles_FullMethodName: decodeProfileCountReply,
}

// decodeDeviceCountReply decodes the ListDevicesResponse wire payload and
// projects the pagination total onto the CountDevicesResponse reply.
func decodeDeviceCountReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.CountDevicesResponse)
	if !ok {
		return ErrInvalidReplyType{
			Method: platformv1.DeviceService_CountDevices_FullMethodName,
		}
	}
	var wire platformv1.ListDevicesResponse
	if err := quicapi.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Count = int32(wire.GetPagination().GetTotalItems())
	return nil
}

// decodeProfileCountReply decodes the ListProfilesResponse wire payload
// and projects the pagination total onto the CountProfilesResponse reply.
func decodeProfileCountReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.CountProfilesResponse)
	if !ok {
		return ErrInvalidReplyType{
			Method: platformv1.DeviceService_CountProfiles_FullMethodName,
		}
	}
	var wire platformv1.ListProfilesResponse
	if err := quicapi.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Count = int32(wire.GetPagination().GetTotalItems())
	return nil
}
