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

// Provisioning (config delivery) wire support for the QUIC transport.
//
// The provisioning sub-operations multiplex under OpProvisioningCategory
// (0xCF) with the first payload byte selecting the sub-operation; requests
// encode the platformv1 pb structs directly (the QUIC payload codec keys on
// exact Go field names, which match the daemon-side mirror structs).
//
// Two responses need special decode handling: the daemon FLATTENS the
// protobuf oneofs in FetchConfigResponse and PollSessionResponse into single
// wire structs with a Result string discriminator ("delivered" | "pending")
// because interface-typed oneof fields do not round-trip through the codec.
// The SDK must not import pkg/api/daemon, so this file defines mirror decode
// structs whose FIELD NAMES match the daemon wire structs byte-for-byte
// (ConfigDeliveryFetchConfigResponse / ConfigDeliveryPollSessionResponse in
// pkg/api/daemon/quic_configdelivery.go) — that field-name equality IS the
// msgpack contract — and maps them back onto the pb oneofs.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Result discriminator values for the flattened FetchConfig and PollSession
// responses, mirroring the daemon-side ConfigDeliveryResultDelivered and
// ConfigDeliveryResultPending constants.
const (
	provisioningResultDelivered = "delivered"
	provisioningResultPending   = "pending"
)

// provisioningFetchConfigWire mirrors the daemon wire struct
// ConfigDeliveryFetchConfigResponse (pkg/api/daemon/quic_configdelivery.go)
// FIELD-FOR-FIELD. The QUIC payload codec keys on exact Go field names and
// ignores struct tags, so these names MUST NOT be renamed independently of
// the daemon struct. The codec tags are documentation only.
type provisioningFetchConfigWire struct {
	Result              string `codec:"result"`
	ConfigJson          []byte `codec:"config_json"`
	Status              string `codec:"status"`
	SessionId           string `codec:"session_id"`
	ProvisionUrl        string `codec:"provision_url"`
	PollIntervalSeconds int32  `codec:"poll_interval_seconds"`
}

// toProto maps the flat wire form back onto the pb oneof, mirroring the
// daemon-side ConfigDeliveryFetchConfigResponse.ToProto exactly.
func (w *provisioningFetchConfigWire) toProto() *platformv1.FetchConfigResponse {
	if w.Result == provisioningResultPending {
		return &platformv1.FetchConfigResponse{
			Result: &platformv1.FetchConfigResponse_Pending{
				Pending: &platformv1.PendingSession{
					SessionId:           w.SessionId,
					ProvisionUrl:        w.ProvisionUrl,
					PollIntervalSeconds: w.PollIntervalSeconds,
				},
			},
		}
	}
	return &platformv1.FetchConfigResponse{
		Result: &platformv1.FetchConfigResponse_Delivered{
			Delivered: &platformv1.DeliveredConfig{
				ConfigJson: w.ConfigJson,
				Status:     w.Status,
			},
		},
	}
}

// provisioningPollSessionWire mirrors the daemon wire struct
// ConfigDeliveryPollSessionResponse (pkg/api/daemon/quic_configdelivery.go)
// FIELD-FOR-FIELD. See provisioningFetchConfigWire for the naming contract.
type provisioningPollSessionWire struct {
	Result        string `codec:"result"`
	ConfigJson    []byte `codec:"config_json"`
	Status        string `codec:"status"`
	PendingStatus string `codec:"pending_status"`
}

// toProto maps the flat wire form back onto the pb oneof, mirroring the
// daemon-side ConfigDeliveryPollSessionResponse.ToProto exactly.
func (w *provisioningPollSessionWire) toProto() *platformv1.PollSessionResponse {
	if w.Result == provisioningResultDelivered {
		return &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{
					ConfigJson: w.ConfigJson,
					Status:     w.Status,
				},
			},
		}
	}
	return &platformv1.PollSessionResponse{
		Result: &platformv1.PollSessionResponse_PendingStatus{
			PendingStatus: w.PendingStatus,
		},
	}
}

// categoryEmptyBodyMethods lists category-opcode methods whose request has
// no wire body: the payload is the single sub-opcode byte, matching the
// daemon dispatchers that ignore payload[1:]. The generated gRPC clients
// pass non-nil empty request messages, so the adapter must drop the encoded
// empty body explicitly to honor the wire contract.
var categoryEmptyBodyMethods = map[string]struct{}{
	platformv1.ConfigDeliveryService_GetNonce_FullMethodName:     {},
	platformv1.ConfigDeliveryService_ListSessions_FullMethodName: {},
}

// categoryResponseDecoder decodes a category-opcode response payload into
// the caller's reply message when the default codec decode does not apply
// (e.g. flattened oneof responses).
type categoryResponseDecoder func(payload []byte, reply interface{}) error

// categoryResponseDecoders routes category-opcode methods whose responses
// require custom decoding. Methods absent from this map use the default
// quicwire.DecodePayload path.
var categoryResponseDecoders = map[string]categoryResponseDecoder{
	platformv1.ConfigDeliveryService_FetchConfig_FullMethodName: decodeProvisioningFetchConfigReply,
	platformv1.ConfigDeliveryService_PollSession_FullMethodName: decodeProvisioningPollSessionReply,
	platformv1.GatewayService_GetNAT64Status_FullMethodName:     decodeGatewayNAT64StatusReply,
}

// decodeProvisioningFetchConfigReply decodes the flattened FetchConfig wire
// response and populates the pb oneof reply.
func decodeProvisioningFetchConfigReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.FetchConfigResponse)
	if !ok {
		return ErrInvalidReplyType{
			Method: platformv1.ConfigDeliveryService_FetchConfig_FullMethodName,
		}
	}
	var wire provisioningFetchConfigWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Result = wire.toProto().Result
	return nil
}

// decodeProvisioningPollSessionReply decodes the flattened PollSession wire
// response and populates the pb oneof reply.
func decodeProvisioningPollSessionReply(payload []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.PollSessionResponse)
	if !ok {
		return ErrInvalidReplyType{
			Method: platformv1.ConfigDeliveryService_PollSession_FullMethodName,
		}
	}
	var wire provisioningPollSessionWire
	if err := quicwire.DecodePayload(payload, &wire); err != nil {
		return ErrDecodingFailed{Err: err}
	}
	out.Result = wire.toProto().Result
	return nil
}
