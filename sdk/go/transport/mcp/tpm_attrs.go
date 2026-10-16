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

// TPM capability, platform-attribute and PCR-extend mapping for the MCP
// transport (#704).
//
// platform_tpm_capabilities answers in the pb reply's own names (algorithms,
// commands, ecc_curves), so the generic JSON round-trip carries it.
// platform_tpm_pcr_extend takes the PCR as "pcr_index", not "index", and
// answers with a bare success/message pair; platform_tpm_platform flattens
// each provisioned key into <key>_handle and <key>_algorithm. Those two need
// their own mapping.

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	mcpArgBuilders[platformv1.TPMService_ExtendPCR_FullMethodName] = buildTPMExtendPCRArgs
	mcpReplyDecoders[platformv1.TPMService_ExtendPCR_FullMethodName] = decodeTPMExtendPCRResult
	mcpReplyDecoders[platformv1.TPMService_GetPlatformAttributes_FullMethodName] = decodeTPMPlatformResult
}

// buildTPMExtendPCRArgs maps the pb extend request onto the
// platform_tpm_pcr_extend arguments: the data as base64 and the PCR under
// "pcr_index".
func buildTPMExtendPCRArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ExtendPCRRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_ExtendPCR_FullMethodName}
	}
	return map[string]interface{}{
		"pcr_index": in.GetIndex(),
		"hash_alg":  in.GetHashAlg(),
		"data":      in.GetData(),
	}, nil
}

// tpmExtendPCRResult is the platform_tpm_pcr_extend result.
type tpmExtendPCRResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// decodeTPMExtendPCRResult wraps the tool's success/message pair into the
// reply's status.
func decodeTPMExtendPCRResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ExtendPCRResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_ExtendPCR_FullMethodName}
	}
	var extended tpmExtendPCRResult
	if err := mapToStruct(result, &extended); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: extended.Success, Message: extended.Message}
	return nil
}

// tpmPlatformResult is the platform_tpm_platform result. A key that is not
// provisioned has neither of its fields.
type tpmPlatformResult struct {
	Device       string  `json:"device"`
	IsFIPS       bool    `json:"is_fips"`
	PCRExtended  bool    `json:"pcr_extended"`
	CanSeal      bool    `json:"can_seal"`
	IsSimulator  bool    `json:"is_simulator"`
	Manufacturer string  `json:"manufacturer"`
	EKHandle     *uint32 `json:"ek_handle"`
	EKAlgorithm  string  `json:"ek_algorithm"`
	SRKHandle    *uint32 `json:"srk_handle"`
	SRKAlgorithm string  `json:"srk_algorithm"`
	IAKHandle    *uint32 `json:"iak_handle"`
	IAKAlgorithm string  `json:"iak_algorithm"`
}

// decodeTPMPlatformResult folds the tool's flattened key fields back into
// the reply's key references.
func decodeTPMPlatformResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.TPMPlatformAttributesResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_GetPlatformAttributes_FullMethodName}
	}
	var platform tpmPlatformResult
	if err := mapToStruct(result, &platform); err != nil {
		return err
	}
	out.Device = platform.Device
	out.IsFips = platform.IsFIPS
	out.PcrExtended = platform.PCRExtended
	out.CanSeal = platform.CanSeal
	out.IsSimulator = platform.IsSimulator
	out.Manufacturer = platform.Manufacturer
	out.Ek = tpmKeyRef(platform.EKHandle, platform.EKAlgorithm)
	out.Srk = tpmKeyRef(platform.SRKHandle, platform.SRKAlgorithm)
	out.Iak = tpmKeyRef(platform.IAKHandle, platform.IAKAlgorithm)
	return nil
}

// tpmKeyRef builds a key reference from a provisioned key's fields; a key
// with no handle stays absent.
func tpmKeyRef(handle *uint32, algorithm string) *platformv1.TPMKeyRef {
	if handle == nil {
		return nil
	}
	return &platformv1.TPMKeyRef{Handle: *handle, Algorithm: algorithm}
}
