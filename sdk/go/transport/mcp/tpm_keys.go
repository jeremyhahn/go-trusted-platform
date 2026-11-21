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

// TPM key-lifecycle mapping for the MCP transport (#1690).
//
// The daemon serves platform_tpm_provision, platform_tpm_clear,
// platform_tpm_ek_create, platform_tpm_ek_delete, platform_tpm_ek_import_cert,
// platform_tpm_srk_create and platform_tpm_srk_delete. The tools work on the
// platform's configured keys: they take an owner password, a handle or a
// base64 DER certificate, and nothing else. A request field the tools cannot
// honour (attributes, endorsement or key passwords, parent handles, a key
// algorithm, an NV index) is refused with ErrTPMKeysFieldUnsupported before
// any call goes out, so the TPM never acts on a request it only half read.
// create_ak on Provision and a transient (persistent false) CreateEK or
// CreateSRK are refused the same way.
//
// Every tool answers {"success", "message"}, the create tools also "handle".
// They send no public key, so PublicKey on the create replies and the
// *_public fields on the Provision reply stay unset.

import (
	"encoding/base64"
	"encoding/pem"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func init() {
	for method, tool := range map[string]string{
		platformv1.TPMService_Provision_FullMethodName:           "platform_tpm_provision",
		platformv1.TPMService_Clear_FullMethodName:               "platform_tpm_clear",
		platformv1.TPMService_CreateEK_FullMethodName:            "platform_tpm_ek_create",
		platformv1.TPMService_DeleteEK_FullMethodName:            "platform_tpm_ek_delete",
		platformv1.TPMService_ImportEKCertificate_FullMethodName: "platform_tpm_ek_import_cert",
		platformv1.TPMService_CreateSRK_FullMethodName:           "platform_tpm_srk_create",
		platformv1.TPMService_DeleteSRK_FullMethodName:           "platform_tpm_srk_delete",
	} {
		grpcMethodToMCPToolMap[method] = tool
	}

	for method, build := range map[string]mcpArgBuilder{
		platformv1.TPMService_Provision_FullMethodName:           buildTPMKeysProvisionArgs,
		platformv1.TPMService_Clear_FullMethodName:               buildTPMKeysClearArgs,
		platformv1.TPMService_CreateEK_FullMethodName:            buildTPMKeysCreateEKArgs,
		platformv1.TPMService_DeleteEK_FullMethodName:            buildTPMKeysDeleteEKArgs,
		platformv1.TPMService_ImportEKCertificate_FullMethodName: buildTPMKeysImportEKCertificateArgs,
		platformv1.TPMService_CreateSRK_FullMethodName:           buildTPMKeysCreateSRKArgs,
		platformv1.TPMService_DeleteSRK_FullMethodName:           buildTPMKeysDeleteSRKArgs,
	} {
		mcpArgBuilders[method] = build
	}

	for method, decode := range map[string]mcpReplyDecoder{
		platformv1.TPMService_Provision_FullMethodName:           decodeTPMKeysProvisionResult,
		platformv1.TPMService_Clear_FullMethodName:               decodeTPMKeysClearResult,
		platformv1.TPMService_CreateEK_FullMethodName:            decodeTPMKeysCreateEKResult,
		platformv1.TPMService_DeleteEK_FullMethodName:            decodeTPMKeysDeleteEKResult,
		platformv1.TPMService_ImportEKCertificate_FullMethodName: decodeTPMKeysImportEKCertificateResult,
		platformv1.TPMService_CreateSRK_FullMethodName:           decodeTPMKeysCreateSRKResult,
		platformv1.TPMService_DeleteSRK_FullMethodName:           decodeTPMKeysDeleteSRKResult,
	} {
		mcpReplyDecoders[method] = decode
	}
}

// ErrTPMKeysFieldUnsupported refuses a request field the MCP key-lifecycle
// tools cannot honour.
type ErrTPMKeysFieldUnsupported struct {
	Method string
	Field  string
}

func (e ErrTPMKeysFieldUnsupported) Error() string {
	return e.Method + ": " + e.Field + " is not supported over MCP; the tool uses the platform's configured keys"
}

// tpmKeysStatusResult is the answer of every key-lifecycle tool.
type tpmKeysStatusResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Handle  uint32 `json:"handle"`
}

func (r tpmKeysStatusResult) status() *platformv1.Status {
	return &platformv1.Status{Success: r.Success, Message: r.Message}
}

func tpmKeysDecodeStatus(result interface{}) (tpmKeysStatusResult, error) {
	var out tpmKeysStatusResult
	err := mapToStruct(result, &out)
	return out, err
}

// tpmKeysOwnerArgs carries the owner password, left out when empty.
func tpmKeysOwnerArgs(password string) map[string]interface{} {
	args := map[string]interface{}{}
	if password != "" {
		args["owner_password"] = password
	}
	return args
}

// buildTPMKeysProvisionArgs sends the owner password only. The tool
// provisions the EK and the shared SRK only, so create_ek and create_srk are
// not sent; create_ak is refused because the tool creates no attestation key.
func buildTPMKeysProvisionArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_Provision_FullMethodName
	in, ok := args.(*platformv1.TPMProvisionRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	switch {
	case in.GetCreateAk():
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "create_ak"}
	case in.GetEndorsementPassword() != "":
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "endorsement_password"}
	case in.GetEkAttributes() != nil:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "ek_attributes"}
	case in.GetSrkAttributes() != nil:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "srk_attributes"}
	case in.GetAkAttributes() != nil:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "ak_attributes"}
	}
	return tpmKeysOwnerArgs(in.GetOwnerPassword()), nil
}

// buildTPMKeysClearArgs refuses a request without confirm, so a zero-value
// request never clears the TPM.
func buildTPMKeysClearArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_Clear_FullMethodName
	in, ok := args.(*platformv1.TPMClearRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if !in.GetConfirm() {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "confirm"}
	}
	return tpmKeysOwnerArgs(in.GetOwnerPassword()), nil
}

// buildTPMKeysCreateEKArgs sends no arguments. The tool always persists the
// key, so a transient request (persistent false) is refused.
func buildTPMKeysCreateEKArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_CreateEK_FullMethodName
	in, ok := args.(*platformv1.CreateEKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if in.GetAttributes() != nil {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "attributes"}
	}
	if !in.GetPersistent() {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "persistent"}
	}
	return map[string]interface{}{}, nil
}

// buildTPMKeysCreateSRKArgs sends no arguments. The tool always persists the
// key under the platform's EK, so a transient request (persistent false) is
// refused.
func buildTPMKeysCreateSRKArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_CreateSRK_FullMethodName
	in, ok := args.(*platformv1.CreateSRKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	switch {
	case in.GetAttributes() != nil:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "attributes"}
	case in.GetParentHandle() != 0:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "parent_handle"}
	case in.GetParentPassword() != "":
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "parent_password"}
	case !in.GetPersistent():
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "persistent"}
	}
	return map[string]interface{}{}, nil
}

// tpmKeysDeleteArgs sends the handle and refuses an algorithm or password.
func tpmKeysDeleteArgs(method string, handle uint32, alg platformv1.KeyAlgorithm, password string) (map[string]interface{}, error) {
	if alg != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "algorithm"}
	}
	if password != "" {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "password"}
	}
	return map[string]interface{}{"handle": handle}, nil
}

func buildTPMKeysDeleteEKArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_DeleteEK_FullMethodName
	in, ok := args.(*platformv1.DeleteEKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	return tpmKeysDeleteArgs(method, in.GetHandle(), in.GetAlgorithm(), in.GetPassword())
}

func buildTPMKeysDeleteSRKArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_DeleteSRK_FullMethodName
	in, ok := args.(*platformv1.DeleteSRKRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	return tpmKeysDeleteArgs(method, in.GetHandle(), in.GetAlgorithm(), in.GetPassword())
}

// buildTPMKeysImportEKCertificateArgs sends the certificate as base64 DER.
// format is read case-insensitively: "DER" or "" takes the bytes as they are,
// "PEM" takes the first CERTIFICATE block.
func buildTPMKeysImportEKCertificateArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.TPMService_ImportEKCertificate_FullMethodName
	in, ok := args.(*platformv1.ImportEKCertificateRequest)
	if !ok {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	if in.GetNvramIndex() != 0 {
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "nvram_index"}
	}
	var der []byte
	switch strings.ToUpper(in.GetFormat()) {
	case "", "DER":
		der = in.GetCertificate()
	case "PEM":
		rest := in.GetCertificate()
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "certificate"}
			}
			if block.Type == "CERTIFICATE" {
				der = block.Bytes
				break
			}
		}
	default:
		return nil, ErrTPMKeysFieldUnsupported{Method: method, Field: "format"}
	}
	return map[string]interface{}{"certificate": base64.StdEncoding.EncodeToString(der)}, nil
}

func decodeTPMKeysProvisionResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.TPMProvisionResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_Provision_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	return nil
}

func decodeTPMKeysClearResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.TPMClearResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_Clear_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	return nil
}

func decodeTPMKeysCreateEKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateEKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_CreateEK_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	out.Handle = res.Handle
	return nil
}

func decodeTPMKeysDeleteEKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteEKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_DeleteEK_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	return nil
}

func decodeTPMKeysImportEKCertificateResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ImportEKCertificateResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_ImportEKCertificate_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	return nil
}

func decodeTPMKeysCreateSRKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateSRKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_CreateSRK_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	out.Handle = res.Handle
	return nil
}

func decodeTPMKeysDeleteSRKResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.DeleteSRKResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.TPMService_DeleteSRK_FullMethodName}
	}
	res, err := tpmKeysDecodeStatus(result)
	if err != nil {
		return err
	}
	out.Status = res.status()
	return nil
}
