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

package mcp

// Provisioning (config delivery) argument and response mapping for the MCP
// transport.
//
// The provision_* MCP tools (pkg/api/mcp/provision_tools.go) accept
// snake_case arguments matching pkg/provisioning/configdelivery/types.go and
// return domain JSON shapes:
//
//   - provision_fetch_config: delivered config ({"config": ..., "status"})
//     XOR pending session (session_id / provision_url /
//     poll_interval_seconds); pending iff no "config" key.
//   - provision_poll_session: delivered config XOR {"status": "pending"};
//     pending iff status == "pending" and no "config" key.
//   - provision_list_sessions / provision_get_session: domain session
//     objects wrapped under "sessions" / "session".
//
// The generic pb JSON round-trip cannot express those shapes (oneofs,
// enum-vs-string profile fields, RFC3339 timestamps), so the decoders below
// delegate to the canonical wire mapping in sdk/go/services/provision.
//
// provision_fulfill_session sends its uint64 profile_id as a DECIMAL STRING
// (the repo-wide uint64-on-the-wire convention; the server accepts string or
// number), which requires a custom argument builder since the pb JSON tags
// would emit a number.

import (
	"encoding/json"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/provision"
)

// mcpArgBuilder converts a gRPC request message into MCP tool arguments when
// the generic JSON round-trip does not produce the tool's expected shape.
type mcpArgBuilder func(args interface{}) (map[string]interface{}, error)

// mcpArgBuilders routes gRPC methods whose MCP tool arguments require custom
// construction. Methods absent from this map use structToMap.
var mcpArgBuilders = map[string]mcpArgBuilder{
	"/platform.v1.ConfigDeliveryService/FulfillSession": buildProvisionFulfillSessionArgs,
}

// buildProvisionFulfillSessionArgs builds the provision_fulfill_session tool
// arguments, sending profile_id as a decimal string so uint64 IDs survive
// JSON number precision limits in every client along the path.
func buildProvisionFulfillSessionArgs(args interface{}) (map[string]interface{}, error) {
	req, ok := args.(*platformv1.FulfillSessionRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: "/platform.v1.ConfigDeliveryService/FulfillSession"}
	}
	return map[string]interface{}{
		"session_id": req.GetSessionId(),
		"profile_id": strconv.FormatUint(req.GetProfileId(), 10),
	}, nil
}

// mcpReplyDecoder decodes an MCP tool result into the caller's pb reply when
// the generic JSON round-trip does not apply.
type mcpReplyDecoder func(result interface{}, reply interface{}) error

// mcpReplyDecoders routes gRPC methods whose MCP tool results require custom
// decoding. Methods absent from this map use mapToStruct.
var mcpReplyDecoders = map[string]mcpReplyDecoder{
	"/platform.v1.ConfigDeliveryService/FetchConfig":  decodeProvisionFetchConfigResult,
	"/platform.v1.ConfigDeliveryService/PollSession":  decodeProvisionPollSessionResult,
	"/platform.v1.ConfigDeliveryService/ListSessions": decodeProvisionListSessionsResult,
	"/platform.v1.ConfigDeliveryService/GetSession":   decodeProvisionGetSessionResult,
	"/platform.v1.GatewayService/GetNAT64Status":      decodeGatewayNAT64StatusResult,
}

// mcpRequestReplyDecoder decodes an MCP tool result into the caller's pb
// reply when the decoding depends on the request, e.g. picking one entry
// out of a list tool's result.
type mcpRequestReplyDecoder func(args interface{}, result interface{}, reply interface{}) error

// mcpRequestReplyDecoders routes gRPC methods whose decoding needs the
// request. They take precedence over mcpReplyDecoders.
var mcpRequestReplyDecoders = map[string]mcpRequestReplyDecoder{}

// decodeGatewayNAT64StatusResult wraps the bare status object the
// gateway_nat64_status tool returns into the gRPC reply.
func decodeGatewayNAT64StatusResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetNAT64StatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.GatewayService/GetNAT64Status"}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	decoded, err := gateway.DecodeNAT64StatusJSON(data)
	if err != nil {
		return err
	}
	out.Status = decoded.Status
	return nil
}

// resultJSON renders a generic MCP tool result back to JSON bytes for the
// canonical provision wire decoders.
func resultJSON(result interface{}) ([]byte, error) {
	data, err := json.Marshal(result)
	if err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}
	return data, nil
}

// decodeProvisionFetchConfigResult maps the tri-state provision_fetch_config
// result onto the pb oneof reply.
func decodeProvisionFetchConfigResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.FetchConfigResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/FetchConfig"}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	decoded, err := provision.DecodeFetchConfigJSON(data)
	if err != nil {
		return err
	}
	out.Result = decoded.Result
	return nil
}

// decodeProvisionPollSessionResult maps the tri-state provision_poll_session
// result onto the pb oneof reply.
func decodeProvisionPollSessionResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.PollSessionResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/PollSession"}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	decoded, err := provision.DecodePollSessionJSON(data)
	if err != nil {
		return err
	}
	out.Result = decoded.Result
	return nil
}

// decodeProvisionListSessionsResult maps the provision_list_sessions result
// ({"sessions": [...]}) onto the pb reply.
func decodeProvisionListSessionsResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListSessionsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/ListSessions"}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	decoded, err := provision.DecodeListSessionsJSON(data)
	if err != nil {
		return err
	}
	out.Sessions = decoded.GetSessions()
	return nil
}

// decodeProvisionGetSessionResult maps the provision_get_session result
// ({"session": {...}}) onto the pb reply.
func decodeProvisionGetSessionResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetSessionResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: "/platform.v1.ConfigDeliveryService/GetSession"}
	}
	data, err := resultJSON(result)
	if err != nil {
		return err
	}
	decoded, err := provision.DecodeGetSessionJSON(data)
	if err != nil {
		return err
	}
	out.Session = decoded.GetSession()
	return nil
}
