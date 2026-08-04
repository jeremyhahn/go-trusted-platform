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

package rest

// Provisioning (config delivery) response decoding for the REST transport.
//
// The config-delivery REST handler (pkg/provisioning/configdelivery)
// serves domain JSON types — not protojson-encoded pb messages — and the
// FetchConfig / PollSession responses flatten the pb oneof into two
// alternative payload shapes. The decoders below capture the raw envelope
// payload and delegate to the canonical wire mapping in
// sdk/go/services/provision so the pb replies come back identical to a
// gRPC call.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// restResponseDecoder decodes a raw REST payload into the caller's pb reply
// when the server-side JSON shape does not match the pb message.
type restResponseDecoder func(raw []byte, reply interface{}) error

// restResponseDecoders routes gRPC methods whose REST responses require
// custom decoding. Methods absent from this map decode directly into the
// reply via decodeJSONResult (protojson for pb messages).
var restResponseDecoders = map[string]restResponseDecoder{
	"/platform.v1.ConfigDeliveryService/FetchConfig":  decodeProvisioningFetchConfig,
	"/platform.v1.ConfigDeliveryService/PollSession":  decodeProvisioningPollSession,
	"/platform.v1.ConfigDeliveryService/ListSessions": decodeProvisioningListSessions,
	"/platform.v1.ConfigDeliveryService/GetSession":   decodeProvisioningGetSession,
}

// decodeProvisioningFetchConfig maps the tri-state FetchConfig JSON payload
// (delivered config XOR pending session) onto the pb oneof reply.
func decodeProvisioningFetchConfig(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.FetchConfigResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/FetchConfig"}
	}
	decoded, err := provision.DecodeFetchConfigJSON(raw)
	if err != nil {
		return err
	}
	out.Result = decoded.Result
	return nil
}

// decodeProvisioningPollSession maps the tri-state PollSession JSON payload
// (delivered config XOR pending status) onto the pb oneof reply.
func decodeProvisioningPollSession(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.PollSessionResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/PollSession"}
	}
	decoded, err := provision.DecodePollSessionJSON(raw)
	if err != nil {
		return err
	}
	out.Result = decoded.Result
	return nil
}

// decodeProvisioningListSessions maps the bare domain session array onto the
// pb ListSessionsResponse reply.
func decodeProvisioningListSessions(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListSessionsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/ListSessions"}
	}
	decoded, err := provision.DecodeListSessionsJSON(raw)
	if err != nil {
		return err
	}
	out.Sessions = decoded.GetSessions()
	return nil
}

// decodeProvisioningGetSession maps the bare domain session object onto the
// pb GetSessionResponse reply.
func decodeProvisioningGetSession(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetSessionResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/GetSession"}
	}
	decoded, err := provision.DecodeGetSessionJSON(raw)
	if err != nil {
		return err
	}
	out.Session = decoded.GetSession()
	return nil
}
