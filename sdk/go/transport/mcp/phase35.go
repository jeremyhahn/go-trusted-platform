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

// Ceremony, PIV, FIDO2 and LUKS tool mapping for the MCP transport.
//
// The platform_ceremony_*, platform_piv_*, platform_fido2_* and
// platform_luks_* tools (pkg/api/mcp/phase35_tools.go) take snake_case
// arguments and carry enums as strings, so the four requests with an enum
// field build their arguments explicitly. The generic pb round trip is
// correct for every other request: the PIV payload and the ceremony share
// signature are bytes, which both sides carry as base64, and no LUKS request
// carries an enum.
//
// Replies that carry a state, a time or a domain struct with Go-named keys
// go through the canonical wire decoders in sdk/go/services/{ceremony,piv,
// fido2,luks}; the rest decode through the generic round trip.

import (
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
)

// phase35ToolMap routes each ceremony, PIV, FIDO2 and LUKS method to its tool.
var phase35ToolMap = map[string]string{
	platformv1.CeremonyService_Init_FullMethodName:               "platform_ceremony_init",
	platformv1.CeremonyService_Status_FullMethodName:             "platform_ceremony_status",
	platformv1.CeremonyService_ClaimCertBegin_FullMethodName:     "platform_ceremony_claim_cert_begin",
	platformv1.CeremonyService_ClaimCertComplete_FullMethodName:  "platform_ceremony_claim_cert_complete",
	platformv1.CeremonyService_ClaimShareBegin_FullMethodName:    "platform_ceremony_claim_share_begin",
	platformv1.CeremonyService_ClaimShareComplete_FullMethodName: "platform_ceremony_claim_share_complete",
	platformv1.CeremonyService_SignCSR_FullMethodName:            "platform_ceremony_sign_csr",

	platformv1.PIVService_ListDevices_FullMethodName: "platform_piv_list_devices",
	platformv1.PIVService_ListSlots_FullMethodName:   "platform_piv_list_slots",
	platformv1.PIVService_SlotInfo_FullMethodName:    "platform_piv_slot_info",
	platformv1.PIVService_Generate_FullMethodName:    "platform_piv_generate",
	platformv1.PIVService_Import_FullMethodName:      "platform_piv_import",
	platformv1.PIVService_Sign_FullMethodName:        "platform_piv_sign",
	platformv1.PIVService_Attest_FullMethodName:      "platform_piv_attest",
	platformv1.PIVService_Reset_FullMethodName:       "platform_piv_reset",

	platformv1.FIDO2Service_ListDevices_FullMethodName:  "platform_fido2_list_devices",
	platformv1.FIDO2Service_WaitDevice_FullMethodName:   "platform_fido2_wait_device",
	platformv1.FIDO2Service_Info_FullMethodName:         "platform_fido2_info",
	platformv1.FIDO2Service_Register_FullMethodName:     "platform_fido2_register",
	platformv1.FIDO2Service_Authenticate_FullMethodName: "platform_fido2_authenticate",

	platformv1.LUKSService_Status_FullMethodName:           "platform_luks_status",
	platformv1.LUKSService_ListSlots_FullMethodName:        "platform_luks_list_slots",
	platformv1.LUKSService_Info_FullMethodName:             "platform_luks_info",
	platformv1.LUKSService_EnrollPassphrase_FullMethodName: "platform_luks_enroll_passphrase",
	platformv1.LUKSService_EnrollFIDO2_FullMethodName:      "platform_luks_enroll_fido2",
	platformv1.LUKSService_EnrollTPM_FullMethodName:        "platform_luks_enroll_tpm",
	platformv1.LUKSService_EnrollRecovery_FullMethodName:   "platform_luks_enroll_recovery",
	platformv1.LUKSService_RemoveKey_FullMethodName:        "platform_luks_remove_key",
	platformv1.LUKSService_TestUnlock_FullMethodName:       "platform_luks_test_unlock",
	platformv1.LUKSService_ChangePassphrase_FullMethodName: "platform_luks_change_passphrase",
}

// phase35ArgBuilders holds the requests whose enum field must reach the tool
// as its wire string.
var phase35ArgBuilders = map[string]mcpArgBuilder{
	platformv1.CeremonyService_ClaimCertBegin_FullMethodName: argBuilder(platformv1.CeremonyService_ClaimCertBegin_FullMethodName,
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
		}),
	platformv1.CeremonyService_SignCSR_FullMethodName: argBuilder(platformv1.CeremonyService_SignCSR_FullMethodName,
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
		}),
	platformv1.PIVService_Generate_FullMethodName: argBuilder(platformv1.PIVService_Generate_FullMethodName,
		func(r *platformv1.PIVGenerateRequest) (map[string]interface{}, error) {
			algorithm, err := pivsdk.AlgorithmToWire(r.GetAlgorithm())
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"slot":      r.GetSlot(),
				"algorithm": algorithm,
				"pin":       r.GetPin(),
			}, nil
		}),
	platformv1.FIDO2Service_Register_FullMethodName: argBuilder(platformv1.FIDO2Service_Register_FullMethodName,
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
		}),
}

// phase35ReplyDecoders holds the replies the generic round trip cannot place:
// states and times, and the domain structs whose keys are Go field names.
var phase35ReplyDecoders = map[string]mcpReplyDecoder{
	platformv1.CeremonyService_Init_FullMethodName:           wireDecoder(platformv1.CeremonyService_Init_FullMethodName, ceremonysdk.DecodeInitJSON),
	platformv1.CeremonyService_Status_FullMethodName:         wireDecoder(platformv1.CeremonyService_Status_FullMethodName, ceremonysdk.DecodeStatusJSON),
	platformv1.CeremonyService_ClaimCertBegin_FullMethodName: wireDecoder(platformv1.CeremonyService_ClaimCertBegin_FullMethodName, ceremonysdk.DecodeClaimCertBeginJSON),
	platformv1.CeremonyService_ClaimShareBegin_FullMethodName: wireDecoder(platformv1.CeremonyService_ClaimShareBegin_FullMethodName,
		ceremonysdk.DecodeClaimShareBeginJSON),

	platformv1.PIVService_ListDevices_FullMethodName: wireDecoder(platformv1.PIVService_ListDevices_FullMethodName, pivsdk.DecodeListDevicesJSON),
	platformv1.PIVService_ListSlots_FullMethodName:   wireDecoder(platformv1.PIVService_ListSlots_FullMethodName, pivsdk.DecodeListSlotsJSON),
	platformv1.PIVService_SlotInfo_FullMethodName:    wireDecoder(platformv1.PIVService_SlotInfo_FullMethodName, pivsdk.DecodeSlotInfoJSON),

	platformv1.FIDO2Service_ListDevices_FullMethodName:  wireDecoder(platformv1.FIDO2Service_ListDevices_FullMethodName, fido2sdk.DecodeListDevicesJSON),
	platformv1.FIDO2Service_WaitDevice_FullMethodName:   wireDecoder(platformv1.FIDO2Service_WaitDevice_FullMethodName, fido2sdk.DecodeWaitDeviceJSON),
	platformv1.FIDO2Service_Info_FullMethodName:         wireDecoder(platformv1.FIDO2Service_Info_FullMethodName, fido2sdk.DecodeInfoJSON),
	platformv1.FIDO2Service_Register_FullMethodName:     wireDecoder(platformv1.FIDO2Service_Register_FullMethodName, fido2sdk.DecodeRegisterJSON),
	platformv1.FIDO2Service_Authenticate_FullMethodName: wireDecoder(platformv1.FIDO2Service_Authenticate_FullMethodName, fido2sdk.DecodeAuthenticateJSON),

	platformv1.LUKSService_Status_FullMethodName:    wireDecoder(platformv1.LUKSService_Status_FullMethodName, lukssdk.DecodeStatusJSON),
	platformv1.LUKSService_ListSlots_FullMethodName: wireDecoder(platformv1.LUKSService_ListSlots_FullMethodName, lukssdk.DecodeListSlotsJSON),
	platformv1.LUKSService_Info_FullMethodName:      wireDecoder(platformv1.LUKSService_Info_FullMethodName, lukssdk.DecodeInfoJSON),
	platformv1.LUKSService_EnrollPassphrase_FullMethodName: wireDecoder(platformv1.LUKSService_EnrollPassphrase_FullMethodName,
		lukssdk.DecodeEnrollPassphraseJSON),
	platformv1.LUKSService_EnrollFIDO2_FullMethodName:    wireDecoder(platformv1.LUKSService_EnrollFIDO2_FullMethodName, lukssdk.DecodeEnrollFIDO2JSON),
	platformv1.LUKSService_EnrollTPM_FullMethodName:      wireDecoder(platformv1.LUKSService_EnrollTPM_FullMethodName, lukssdk.DecodeEnrollTPMJSON),
	platformv1.LUKSService_EnrollRecovery_FullMethodName: wireDecoder(platformv1.LUKSService_EnrollRecovery_FullMethodName, lukssdk.DecodeEnrollRecoveryJSON),
}

// argBuilder builds an mcpArgBuilder that type-checks the pb request before
// converting it into the tool's arguments.
func argBuilder[P any](method string, build func(*P) (map[string]interface{}, error)) mcpArgBuilder {
	return func(args interface{}) (map[string]interface{}, error) {
		req, ok := args.(*P)
		if !ok || req == nil {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		return build(req)
	}
}

// wireDecoder builds an mcpReplyDecoder that renders the tool result back to
// JSON, decodes it with a canonical service wire decoder and copies the
// decoded message into the caller's reply.
func wireDecoder[R any, P interface {
	*R
	proto.Message
}](method string, decode func([]byte) (P, error)) mcpReplyDecoder {
	return func(result interface{}, reply interface{}) error {
		out, ok := reply.(P)
		if !ok || out == nil {
			return ErrUnexpectedReplyType{Method: method}
		}
		data, err := resultJSON(result)
		if err != nil {
			return err
		}
		decoded, err := decode(data)
		if err != nil {
			return err
		}
		proto.Reset(out)
		proto.Merge(out, decoded)
		return nil
	}
}

func init() {
	for method, tool := range phase35ToolMap {
		grpcMethodToMCPToolMap[method] = tool
	}
	for method, build := range phase35ArgBuilders {
		mcpArgBuilders[method] = build
	}
	for method, decode := range phase35ReplyDecoders {
		mcpReplyDecoders[method] = decode
	}
}
