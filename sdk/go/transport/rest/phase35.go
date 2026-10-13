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

// Ceremony, PIV and FIDO2 over REST.
//
// The daemon serves these under /api/v1/{ceremony,piv,fido2}
// (pkg/api/daemon/{ceremony,piv,fido2}_rest.go). Three things differ from the
// pb messages:
//
//   - Identifiers travel in the URL: PIV slots and devices, and the FIDO2
//     device, are path segments. The flat routes the client once used
//     (/piv/slots, /piv/generate, /fido2/info, ...) do not exist on the
//     server.
//   - Enums travel as strings ("ecdsa", "so", "fido2"), where encoding/json
//     would send the pb enum number. Requests with an enum field are
//     rebuilt by a restRequestEncoder before they are sent.
//   - Replies carry the daemon's domain JSON (Go-named keys, string states)
//     rather than the pb shape, so the replies that cannot decode directly
//     go through the canonical wire decoders in sdk/go/services/{ceremony,
//     piv,fido2}.

import (
	"net/http"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// restRequestEncoder rebuilds the request body of a method whose pb message
// cannot be marshalled with encoding/json as the server expects. body is the
// pb message (the clone with path and query fields cleared, for a templated
// route).
type restRequestEncoder func(body interface{}) (interface{}, error)

// restRequestEncoders routes gRPC methods to their body encoder. Methods
// absent from this map send the pb message as is.
var restRequestEncoders = map[string]restRequestEncoder{}

// encodeRequestBody applies the method's request encoder, if it has one.
func encodeRequestBody(method string, body interface{}) (interface{}, error) {
	encode, ok := restRequestEncoders[method]
	if !ok {
		return body, nil
	}
	return encode(body)
}

// requestEncoder builds a restRequestEncoder that type-checks the pb request
// before handing it to build.
func requestEncoder[P any](method string, build func(*P) (map[string]interface{}, error)) restRequestEncoder {
	return func(body interface{}) (interface{}, error) {
		req, ok := body.(*P)
		if !ok || req == nil {
			return nil, ErrUnexpectedRequestType{Method: method}
		}
		return build(req)
	}
}

// wireDecoder builds a restResponseDecoder that decodes the raw payload with a
// canonical service wire decoder and copies the result into the caller's
// reply.
func wireDecoder[R any, P interface {
	*R
	proto.Message
}](method string, decode func([]byte) (P, error)) restResponseDecoder {
	return func(raw []byte, reply interface{}) error {
		out, ok := reply.(P)
		if !ok || out == nil {
			return ErrUnexpectedReplyType{Method: method}
		}
		decoded, err := decode(raw)
		if err != nil {
			return err
		}
		proto.Reset(out)
		proto.Merge(out, decoded)
		return nil
	}
}

func init() {
	// PIV: /api/v1/piv/devices/{device}/..., /api/v1/piv/slots/{slot}/...
	// ListDevices is a flat route (grpcMethodToRESTMap).
	slot := pathParam{placeholder: "{slot}", field: "slot"}
	templatedRouteTable[platformv1.PIVService_ListSlots_FullMethodName] =
		itemRoute("/api/v1/piv/devices/{device}/slots", http.MethodGet, "{device}", "device")
	templatedRouteTable[platformv1.PIVService_SlotInfo_FullMethodName] = templatedRoute{
		path:        "/api/v1/piv/slots/{slot}",
		method:      http.MethodGet,
		pathParams:  []pathParam{slot},
		queryParams: []queryParam{{name: "device", field: "device"}},
	}
	templatedRouteTable[platformv1.PIVService_Generate_FullMethodName] =
		itemRoute("/api/v1/piv/slots/{slot}/generate", http.MethodPost, slot.placeholder, slot.field)
	templatedRouteTable[platformv1.PIVService_Import_FullMethodName] =
		itemRoute("/api/v1/piv/slots/{slot}/import", http.MethodPost, slot.placeholder, slot.field)
	templatedRouteTable[platformv1.PIVService_Sign_FullMethodName] =
		itemRoute("/api/v1/piv/slots/{slot}/sign", http.MethodPost, slot.placeholder, slot.field)
	templatedRouteTable[platformv1.PIVService_Attest_FullMethodName] =
		itemRoute("/api/v1/piv/slots/{slot}/attest", http.MethodPost, slot.placeholder, slot.field)
	templatedRouteTable[platformv1.PIVService_Reset_FullMethodName] =
		itemRoute("/api/v1/piv/devices/{device}/reset", http.MethodPost, "{device}", "device")

	// FIDO2: the wait timeout is a query parameter, the device a path segment.
	// ListDevices, Register and Authenticate are flat routes.
	templatedRouteTable[platformv1.FIDO2Service_WaitDevice_FullMethodName] = templatedRoute{
		path:        "/api/v1/fido2/devices/wait",
		method:      http.MethodGet,
		queryParams: []queryParam{{name: "timeout_seconds", field: "timeout_seconds"}},
	}
	templatedRouteTable[platformv1.FIDO2Service_Info_FullMethodName] =
		itemRoute("/api/v1/fido2/devices/{device}", http.MethodGet, "{device}", "device")

	restRequestEncoders[platformv1.CeremonyService_ClaimCertBegin_FullMethodName] = requestEncoder(
		platformv1.CeremonyService_ClaimCertBegin_FullMethodName,
		func(r *platformv1.CeremonyClaimCertBeginRequest) (map[string]interface{}, error) {
			authenticator, err := ceremonysdk.AuthenticatorTypeToWire(r.GetAuthenticatorType())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"username":           r.GetUsername(),
				"authenticator_type": authenticator,
				"slot":               r.GetSlot(),
				"credential_id":      r.GetCredentialId(),
			}, nil
		})
	restRequestEncoders[platformv1.CeremonyService_SignCSR_FullMethodName] = requestEncoder(
		platformv1.CeremonyService_SignCSR_FullMethodName,
		func(r *platformv1.CeremonySignCSRRequest) (map[string]interface{}, error) {
			role, err := ceremonysdk.OfficerRoleToWire(r.GetRole())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"username": r.GetUsername(),
				"so_pin":   r.GetSoPin(),
				"csr_pem":  r.GetCsrPem(),
				"role":     role,
			}, nil
		})
	restRequestEncoders[platformv1.PIVService_Generate_FullMethodName] = requestEncoder(
		platformv1.PIVService_Generate_FullMethodName,
		func(r *platformv1.PIVGenerateRequest) (map[string]interface{}, error) {
			algorithm, err := pivsdk.AlgorithmToWire(r.GetAlgorithm())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"algorithm": algorithm, "pin": r.GetPin()}, nil
		})
	restRequestEncoders[platformv1.FIDO2Service_Register_FullMethodName] = requestEncoder(
		platformv1.FIDO2Service_Register_FullMethodName,
		func(r *platformv1.FIDO2RegisterRequest) (map[string]interface{}, error) {
			role, err := fido2sdk.RoleToWire(r.GetRole())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"username":    r.GetUsername(),
				"role":        role,
				"require_pin": r.GetRequirePin(),
				"require_uv":  r.GetRequireUv(),
				"rp_id":       r.GetRpId(),
			}, nil
		})

	restResponseDecoders[platformv1.CeremonyService_Init_FullMethodName] =
		wireDecoder(platformv1.CeremonyService_Init_FullMethodName, ceremonysdk.DecodeInitJSON)
	restResponseDecoders[platformv1.CeremonyService_Status_FullMethodName] =
		wireDecoder(platformv1.CeremonyService_Status_FullMethodName, ceremonysdk.DecodeStatusJSON)
	restResponseDecoders[platformv1.CeremonyService_ClaimCertBegin_FullMethodName] =
		wireDecoder(platformv1.CeremonyService_ClaimCertBegin_FullMethodName, ceremonysdk.DecodeClaimCertBeginJSON)
	restResponseDecoders[platformv1.CeremonyService_ClaimShareBegin_FullMethodName] =
		wireDecoder(platformv1.CeremonyService_ClaimShareBegin_FullMethodName, ceremonysdk.DecodeClaimShareBeginJSON)

	restResponseDecoders[platformv1.PIVService_ListDevices_FullMethodName] =
		wireDecoder(platformv1.PIVService_ListDevices_FullMethodName, pivsdk.DecodeListDevicesJSON)
	restResponseDecoders[platformv1.PIVService_ListSlots_FullMethodName] =
		wireDecoder(platformv1.PIVService_ListSlots_FullMethodName, pivsdk.DecodeListSlotsJSON)
	restResponseDecoders[platformv1.PIVService_SlotInfo_FullMethodName] =
		wireDecoder(platformv1.PIVService_SlotInfo_FullMethodName, pivsdk.DecodeSlotInfoJSON)

	restResponseDecoders[platformv1.FIDO2Service_ListDevices_FullMethodName] =
		wireDecoder(platformv1.FIDO2Service_ListDevices_FullMethodName, fido2sdk.DecodeListDevicesJSON)
	restResponseDecoders[platformv1.FIDO2Service_WaitDevice_FullMethodName] =
		wireDecoder(platformv1.FIDO2Service_WaitDevice_FullMethodName, fido2sdk.DecodeWaitDeviceJSON)
	restResponseDecoders[platformv1.FIDO2Service_Info_FullMethodName] =
		wireDecoder(platformv1.FIDO2Service_Info_FullMethodName, fido2sdk.DecodeInfoJSON)
	restResponseDecoders[platformv1.FIDO2Service_Register_FullMethodName] =
		wireDecoder(platformv1.FIDO2Service_Register_FullMethodName, fido2sdk.DecodeRegisterJSON)
	restResponseDecoders[platformv1.FIDO2Service_Authenticate_FullMethodName] =
		wireDecoder(platformv1.FIDO2Service_Authenticate_FullMethodName, fido2sdk.DecodeAuthenticateJSON)
}
