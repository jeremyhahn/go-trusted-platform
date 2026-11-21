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

// TPM seal and NV data mapping for the MCP transport (#1690).
//
// platform_tpm_seal and platform_tpm_unseal seal under the platform SRK
// only: a request that names another parent key, its password or a PCR
// bank is refused here rather than silently sealed under the SRK. The seal
// tool takes the PCRs as "pcrs" and answers {"sealed_data"}; unseal answers
// {"data"}. platform_tpm_nv_write takes the pb request's own names, so the
// generic JSON round-trip carries its arguments. platform_tpm_nv_read gets a
// builder that caps size at 65535 (the tool refuses more, the gRPC service
// caps it), and its reply still decodes through the generic round-trip.
// The write and delete tools answer with a
// bare success/message pair. platform_tpm_nv_delete undefines through the
// owner hierarchy, so an index password is refused. DefineNVRAM has no
// server tool and stays unrouted.

import (
	"encoding/base64"
	"fmt"
	"math"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	for method, tool := range map[string]string{
		platformv1.TPMService_Seal_FullMethodName:          "platform_tpm_seal",
		platformv1.TPMService_Unseal_FullMethodName:        "platform_tpm_unseal",
		platformv1.TPMService_ReadNVRAM_FullMethodName:     "platform_tpm_nv_read",
		platformv1.TPMService_WriteNVRAM_FullMethodName:    "platform_tpm_nv_write",
		platformv1.TPMService_UndefineNVRAM_FullMethodName: "platform_tpm_nv_delete",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.TPMService_Seal_FullMethodName:          buildTPMSealNVSealArgs,
		platformv1.TPMService_Unseal_FullMethodName:        buildTPMSealNVUnsealArgs,
		platformv1.TPMService_ReadNVRAM_FullMethodName:     buildTPMSealNVReadArgs,
		platformv1.TPMService_UndefineNVRAM_FullMethodName: buildTPMSealNVUndefineArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.TPMService_Seal_FullMethodName:          decodeTPMSealNVSealResult,
		platformv1.TPMService_Unseal_FullMethodName:        decodeTPMSealNVUnsealResult,
		platformv1.TPMService_WriteNVRAM_FullMethodName:    decodeTPMSealNVWriteResult,
		platformv1.TPMService_UndefineNVRAM_FullMethodName: decodeTPMSealNVUndefineResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// ErrTPMSealNVFieldUnsupported reports a request field the MCP seal or NV
// tool cannot honour; Invoke answers it as InvalidArgument before any call.
type ErrTPMSealNVFieldUnsupported struct {
	Method string
	Field  string
}

func (e ErrTPMSealNVFieldUnsupported) Error() string {
	return fmt.Sprintf("%s: %s is not supported over MCP", e.Method, e.Field)
}

// tpmSealNVParentRefusal refuses a request that names a parent key other
// than the platform SRK, its password, or a PCR bank.
func tpmSealNVParentRefusal(method string, parentHandle uint32, parentPassword string, bank platformv1.PCRBank) error {
	switch {
	case parentHandle != 0:
		return ErrTPMSealNVFieldUnsupported{Method: method, Field: "parent_handle"}
	case parentPassword != "":
		return ErrTPMSealNVFieldUnsupported{Method: method, Field: "parent_password"}
	case bank != platformv1.PCRBank_PCR_BANK_UNSPECIFIED:
		return ErrTPMSealNVFieldUnsupported{Method: method, Field: "pcr_bank"}
	}
	return nil
}

// buildTPMSealNVSealArgs maps the pb seal request onto the
// platform_tpm_seal arguments: the data as base64 and the PCRs as "pcrs".
func buildTPMSealNVSealArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.SealRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_Seal_FullMethodName}
	}
	if err := tpmSealNVParentRefusal(platformv1.TPMService_Seal_FullMethodName,
		in.GetParentHandle(), in.GetParentPassword(), in.GetPcrBank()); err != nil {
		return nil, err
	}
	out := map[string]interface{}{"data": base64.StdEncoding.EncodeToString(in.GetData())}
	if pcrs := in.GetPcrIndices(); len(pcrs) > 0 {
		out["pcrs"] = pcrs
	}
	if cn := in.GetCn(); cn != "" {
		out["cn"] = cn
	}
	if pw := in.GetPassword(); pw != "" {
		out["password"] = pw
	}
	return out, nil
}

// buildTPMSealNVUnsealArgs maps the pb unseal request onto the
// platform_tpm_unseal arguments. The PCR indices are not sent: the sealed
// object carries its own policy.
func buildTPMSealNVUnsealArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.UnsealRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_Unseal_FullMethodName}
	}
	if err := tpmSealNVParentRefusal(platformv1.TPMService_Unseal_FullMethodName,
		in.GetParentHandle(), in.GetParentPassword(), in.GetPcrBank()); err != nil {
		return nil, err
	}
	out := map[string]interface{}{}
	if cn := in.GetCn(); cn != "" {
		out["cn"] = cn
	}
	if pw := in.GetPassword(); pw != "" {
		out["password"] = pw
	}
	return out, nil
}

// buildTPMSealNVUndefineArgs maps the pb undefine request onto the
// platform_tpm_nv_delete arguments. The tool undefines through the owner
// hierarchy only, so an index password is refused.
func buildTPMSealNVUndefineArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.UndefineNVRAMRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_UndefineNVRAM_FullMethodName}
	}
	if in.GetPassword() != "" {
		return nil, ErrTPMSealNVFieldUnsupported{Method: platformv1.TPMService_UndefineNVRAM_FullMethodName, Field: "password"}
	}
	out := map[string]interface{}{"index": in.GetIndex()}
	if pw := in.GetParentPassword(); pw != "" {
		out["parent_password"] = pw
	}
	return out, nil
}

func buildTPMSealNVReadArgs(args interface{}) (map[string]interface{}, error) {
	in, ok := args.(*platformv1.ReadNVRAMRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: platformv1.TPMService_ReadNVRAM_FullMethodName}
	}
	out := map[string]interface{}{"index": in.GetIndex()}
	// No NV index exceeds 65535 bytes, so a larger size reads the whole index,
	// as TPMGRPCService.ReadNVRAM does (the MCP tool refuses a size above 65535).
	if size := in.GetSize(); size != 0 {
		out["size"] = min(size, math.MaxUint16)
	}
	// The server refuses an offset past 65535 on every transport.
	if off := in.GetOffset(); off != 0 {
		out["offset"] = off
	}
	if pw := in.GetPassword(); pw != "" {
		out["password"] = pw
	}
	return out, nil
}

// tpmSealNVSealResult is the platform_tpm_seal result.
type tpmSealNVSealResult struct {
	SealedData []byte `json:"sealed_data"`
}

// tpmSealNVUnsealResult is the platform_tpm_unseal result.
type tpmSealNVUnsealResult struct {
	Data []byte `json:"data"`
}

// tpmSealNVStatusResult is the platform_tpm_nv_write and
// platform_tpm_nv_delete result.
type tpmSealNVStatusResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// decodeTPMSealNVSealResult carries the sealed blob into the reply.
func decodeTPMSealNVSealResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.SealResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_Seal_FullMethodName}
	}
	var sealed tpmSealNVSealResult
	if err := mapToStruct(result, &sealed); err != nil {
		return err
	}
	out.SealedData = sealed.SealedData
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeTPMSealNVUnsealResult carries the unsealed data into the reply.
func decodeTPMSealNVUnsealResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.UnsealResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_Unseal_FullMethodName}
	}
	var unsealed tpmSealNVUnsealResult
	if err := mapToStruct(result, &unsealed); err != nil {
		return err
	}
	out.Data = unsealed.Data
	out.Status = &platformv1.Status{Success: true}
	return nil
}

// decodeTPMSealNVWriteResult wraps the tool's success/message pair into the
// reply's status.
func decodeTPMSealNVWriteResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.WriteNVRAMResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_WriteNVRAM_FullMethodName}
	}
	var wrote tpmSealNVStatusResult
	if err := mapToStruct(result, &wrote); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: wrote.Success, Message: wrote.Message}
	return nil
}

// decodeTPMSealNVUndefineResult wraps the tool's success/message pair into
// the reply's status.
func decodeTPMSealNVUndefineResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.UndefineNVRAMResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_UndefineNVRAM_FullMethodName}
	}
	var undefined tpmSealNVStatusResult
	if err := mapToStruct(result, &undefined); err != nil {
		return err
	}
	out.Status = &platformv1.Status{Success: undefined.Success, Message: undefined.Message}
	return nil
}
