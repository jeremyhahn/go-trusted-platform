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

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// =============================================================================
// TPM Tool Execution Functions
// =============================================================================

// executeTPMInfo retrieves TPM device information.
func (r *ToolRegistry) executeTPMInfo(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMInfo(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMProvision provisions the TPM with owner authorization.
func (r *ToolRegistry) executeTPMProvision(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ownerPassword := getString(args, "owner_password")
	result, err := r.service.TPMProvision(ctx, ownerPassword)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMClear clears the TPM.
func (r *ToolRegistry) executeTPMClear(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	ownerPassword := getString(args, "owner_password")
	result, err := r.service.TPMClear(ctx, ownerPassword)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMGetEK retrieves the Endorsement Key.
func (r *ToolRegistry) executeTPMGetEK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMGetEK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMGetEKCert retrieves the EK certificate.
func (r *ToolRegistry) executeTPMGetEKCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMGetEKCert(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMImportEKCert imports an EK certificate.
func (r *ToolRegistry) executeTPMImportEKCert(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	certB64 := getString(args, "certificate")
	if certB64 == "" {
		return nil, ErrTPMCertificateRequired
	}
	certDER, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return nil, ErrTPMInvalidCertificate
	}
	result, err := r.service.TPMImportEKCert(ctx, certDER)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMCreateEK creates an Endorsement Key.
func (r *ToolRegistry) executeTPMCreateEK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMCreateEK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMDeleteEK deletes the Endorsement Key.
func (r *ToolRegistry) executeTPMDeleteEK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMDeleteEK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// optionalUint32Arg reads an optional persistent-handle argument.
//
// It deliberately does not use getInt64: that helper returns 0 for an
// unparseable string, and 0 is a meaningful handle here (the SSRK), so a
// caller sending "0x81000002" would silently receive the wrong key. Hex
// is accepted because every doc, CLI flag and log line in this repo
// writes these handles as 0x8100000n.
func optionalUint32Arg(args map[string]interface{}, key string) (uint32, error) {
	raw, present := args[key]
	if !present || raw == nil {
		return 0, nil
	}
	switch v := raw.(type) {
	case float64:
		if v < 0 || v > math.MaxUint32 || v != math.Trunc(v) {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(v), nil
	case int:
		if v < 0 || int64(v) > math.MaxUint32 {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(v), nil
	case int64:
		if v < 0 || v > math.MaxUint32 {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(v), nil
	case uint64:
		if v > math.MaxUint32 {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(v), nil
	case json.Number:
		parsed, err := strconv.ParseUint(v.String(), 0, 32)
		if err != nil {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(parsed), nil
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseUint(trimmed, 0, 32)
		if err != nil {
			return 0, ErrTPMInvalidHandle
		}
		return uint32(parsed), nil
	default:
		return 0, ErrTPMInvalidHandle
	}
}

// executeTPMGetSRK retrieves the Storage Root Key.
func (r *ToolRegistry) executeTPMGetSRK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	handle, err := optionalUint32Arg(args, "handle")
	if err != nil {
		return nil, err
	}
	result, err := r.service.TPMGetSRK(ctx, handle)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMCreateSRK creates a Storage Root Key.
func (r *ToolRegistry) executeTPMCreateSRK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMCreateSRK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMDeleteSRK deletes the Storage Root Key.
func (r *ToolRegistry) executeTPMDeleteSRK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMDeleteSRK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMGetIAK retrieves the Initial Attestation Key.
func (r *ToolRegistry) executeTPMGetIAK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMGetIAK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMCreateIAK creates an Initial Attestation Key.
func (r *ToolRegistry) executeTPMCreateIAK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMCreateIAK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMDeleteIAK deletes the Initial Attestation Key.
func (r *ToolRegistry) executeTPMDeleteIAK(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMDeleteIAK(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMQuote generates a TPM quote for attestation.
func (r *ToolRegistry) executeTPMQuote(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	nonceB64 := getString(args, "nonce")
	if nonceB64 == "" {
		return nil, ErrTPMNonceRequired
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, ErrTPMInvalidNonce
	}
	pcrs := getIntSlice(args, "pcrs")

	result, err := r.service.TPMQuote(ctx, nonce, pcrs)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMVerifyQuote verifies a TPM quote.
func (r *ToolRegistry) executeTPMVerifyQuote(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	quoteB64 := getString(args, "quote")
	signatureB64 := getString(args, "signature")
	nonceB64 := getString(args, "nonce")

	if nonceB64 == "" {
		return nil, ErrTPMNonceRequired
	}

	quote, err := base64.StdEncoding.DecodeString(quoteB64)
	if err != nil {
		return nil, ErrTPMInvalidData
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, ErrTPMInvalidData
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, ErrTPMInvalidNonce
	}

	result, err := r.service.TPMVerifyQuote(ctx, quote, signature, nonce)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMReadPCRs reads PCR values from the TPM.
func (r *ToolRegistry) executeTPMReadPCRs(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	indices := getIntSlice(args, "indices")
	result, err := r.service.TPMReadPCRs(ctx, indices)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMExtendPCR extends a PCR with measurement data.
func (r *ToolRegistry) executeTPMExtendPCR(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	pcrIndex := getInt(args, "pcr_index")
	dataB64 := getString(args, "data")

	if pcrIndex < 0 || pcrIndex > 23 {
		return nil, ErrTPMInvalidPCRIndex
	}

	if dataB64 == "" {
		return nil, ErrTPMDataRequired
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, ErrTPMInvalidData
	}

	result, err := r.service.TPMExtendPCR(ctx, pcrIndex, data)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMEventLog retrieves the TPM event log.
func (r *ToolRegistry) executeTPMEventLog(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMEventLog(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMCapabilities retrieves TPM capabilities.
func (r *ToolRegistry) executeTPMCapabilities(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMRandom generates random bytes from the TPM.
func (r *ToolRegistry) executeTPMRandom(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	numBytes := getInt(args, "num_bytes")
	if numBytes <= 0 {
		numBytes = 32
	}

	randomBytes, err := r.service.TPMRandom(ctx, numBytes)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"random_bytes": base64.StdEncoding.EncodeToString(randomBytes),
		"num_bytes":    len(randomBytes),
	}, nil
}

// executeTPMSeal seals data to the TPM.
func (r *ToolRegistry) executeTPMSeal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	dataB64 := getString(args, "data")
	if dataB64 == "" {
		return nil, ErrTPMDataRequired
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, ErrTPMInvalidData
	}
	pcrs := getIntSlice(args, "pcrs")

	sealed, err := r.service.TPMSeal(ctx, data, pcrs)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"sealed_data": base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

// executeTPMUnseal unseals data from the TPM.
func (r *ToolRegistry) executeTPMUnseal(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	cn := getString(args, "cn")
	if cn == "" {
		return nil, ErrTPMCNRequired
	}

	data, err := r.service.TPMUnseal(ctx, cn)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(data),
	}, nil
}

// executeTPMCertify certifies a TPM key.
func (r *ToolRegistry) executeTPMCertify(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyHandle := getInt(args, "key_handle")
	result, err := r.service.TPMCertify(ctx, keyHandle)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMNVList lists NVRAM indices.
func (r *ToolRegistry) executeTPMNVList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMNVList(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMNVRead reads data from an NVRAM index.
func (r *ToolRegistry) executeTPMNVRead(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	index := getInt(args, "index")
	size := getInt(args, "size")

	data, err := r.service.TPMNVRead(ctx, index, size)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"index": index,
		"data":  base64.StdEncoding.EncodeToString(data),
		"size":  len(data),
	}, nil
}

// executeTPMNVWrite writes data to an NVRAM index.
func (r *ToolRegistry) executeTPMNVWrite(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	index := getInt(args, "index")
	dataB64 := getString(args, "data")

	if dataB64 == "" {
		return nil, ErrTPMDataRequired
	}
	data, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		return nil, ErrTPMInvalidData
	}

	result, err := r.service.TPMNVWrite(ctx, index, data)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMNVDelete undefines an NVRAM index.
func (r *ToolRegistry) executeTPMNVDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	index := getInt(args, "index")
	result, err := r.service.TPMNVDelete(ctx, index)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMPlatform retrieves platform-level TPM attributes.
func (r *ToolRegistry) executeTPMPlatform(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.TPMPlatform(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMMakeCredential creates a TPM2_MakeCredential challenge.
func (r *ToolRegistry) executeTPMMakeCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	akName, err := decodeTPMBase64Arg(args, "ak_name")
	if err != nil {
		return nil, err
	}
	secret, err := decodeTPMBase64Arg(args, "secret")
	if err != nil {
		return nil, err
	}
	ekCert, err := decodeTPMBase64Arg(args, "ek_cert")
	if err != nil {
		return nil, err
	}
	iakPub, err := decodeTPMBase64Arg(args, "iak_pub")
	if err != nil {
		return nil, err
	}

	result, err := r.service.TPMMakeCredential(ctx, akName, secret, ekCert, iakPub)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// executeTPMActivateCredential activates a TPM2_MakeCredential challenge.
func (r *ToolRegistry) executeTPMActivateCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	credB64 := getString(args, "credential_blob")
	if credB64 == "" {
		return nil, ErrTPMCredentialBlobRequired
	}
	secretB64 := getString(args, "encrypted_secret")
	if secretB64 == "" {
		return nil, ErrTPMEncryptedSecretRequired
	}

	credentialBlob, err := base64.StdEncoding.DecodeString(credB64)
	if err != nil {
		return nil, ErrTPMInvalidBase64
	}
	encryptedSecret, err := base64.StdEncoding.DecodeString(secretB64)
	if err != nil {
		return nil, ErrTPMInvalidBase64
	}

	result, err := r.service.TPMActivateCredential(ctx, credentialBlob, encryptedSecret)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// decodeTPMBase64Arg decodes an optional base64 string argument. A missing or
// empty argument yields a nil slice without error.
func decodeTPMBase64Arg(args map[string]interface{}, key string) ([]byte, error) {
	value := getString(args, key)
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrTPMInvalidBase64
	}
	return decoded, nil
}
