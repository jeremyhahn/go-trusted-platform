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

package main

import (
	"log/slog"
	"strings"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// TPMBinding exposes TPM service methods to the Wails frontend.
type TPMBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewTPMBinding creates a new TPMBinding.
func NewTPMBinding(logger *slog.Logger, conn *ConnectionBinding) *TPMBinding {
	return &TPMBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *TPMBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// Info returns TPM capabilities and information.
func (b *TPMBinding) Info() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().Info(b.conn.ctx, &platformv1.TPMInfoRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Provision initializes the TPM with required keys.
func (b *TPMBinding) Provision(ownerPassword, endorsementPassword string,
	createEK, createSRK, createAK bool) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().Provision(b.conn.ctx, &platformv1.TPMProvisionRequest{
		OwnerPassword:       ownerPassword,
		EndorsementPassword: endorsementPassword,
		CreateEk:            createEK,
		CreateSrk:           createSRK,
		CreateAk:            createAK,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Clear clears the TPM (requires owner authorization).
func (b *TPMBinding) Clear(ownerPassword string, confirm bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().Clear(b.conn.ctx, &platformv1.TPMClearRequest{
		OwnerPassword: ownerPassword,
		Confirm:       confirm,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateEK creates an endorsement key.
func (b *TPMBinding) CreateEK(persistent bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().CreateEK(b.conn.ctx, &platformv1.CreateEKRequest{
		Persistent: persistent,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetEK retrieves the endorsement key by algorithm name and handle.
func (b *TPMBinding) GetEK(algorithm string, handle uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetEK(b.conn.ctx, &platformv1.GetEKRequest{
		Algorithm: algo,
		Handle:    handle,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetEKCertificate retrieves the endorsement key certificate.
func (b *TPMBinding) GetEKCertificate(algorithm string, handle uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetEKCertificate(b.conn.ctx, &platformv1.GetEKCertificateRequest{
		Algorithm: algo,
		Handle:    handle,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ImportEKCertificate imports an EK certificate into the TPM NVRAM.
func (b *TPMBinding) ImportEKCertificate(certificate []byte, format string,
	nvramIndex uint32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().ImportEKCertificate(b.conn.ctx, &platformv1.ImportEKCertificateRequest{
		Certificate: certificate,
		Format:      format,
		NvramIndex:  nvramIndex,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteEK deletes the endorsement key.
func (b *TPMBinding) DeleteEK(handle uint32, algorithm, password string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().DeleteEK(b.conn.ctx, &platformv1.DeleteEKRequest{
		Handle:    handle,
		Algorithm: algo,
		Password:  password,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateSRK creates a storage root key under the specified parent EK.
func (b *TPMBinding) CreateSRK(persistent bool, parentHandle uint32,
	parentPassword string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().CreateSRK(b.conn.ctx, &platformv1.CreateSRKRequest{
		Persistent:     persistent,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetSRK retrieves the storage root key by algorithm name and handle.
func (b *TPMBinding) GetSRK(algorithm string, handle uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetSRK(b.conn.ctx, &platformv1.GetSRKRequest{
		Algorithm: algo,
		Handle:    handle,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteSRK deletes the storage root key.
func (b *TPMBinding) DeleteSRK(handle uint32, algorithm, password string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().DeleteSRK(b.conn.ctx, &platformv1.DeleteSRKRequest{
		Handle:    handle,
		Algorithm: algo,
		Password:  password,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateAK creates an attestation key under the specified parent SRK.
func (b *TPMBinding) CreateAK(persistent bool, parentHandle uint32,
	parentPassword string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().CreateAK(b.conn.ctx, &platformv1.CreateAKRequest{
		Persistent:     persistent,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetAK retrieves the attestation key by algorithm name and handle.
func (b *TPMBinding) GetAK(algorithm string, handle uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetAK(b.conn.ctx, &platformv1.GetAKRequest{
		Algorithm: algo,
		Handle:    handle,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteAK deletes the attestation key.
func (b *TPMBinding) DeleteAK(handle uint32, algorithm, password string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	algo, err := parseKeyAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().DeleteAK(b.conn.ctx, &platformv1.DeleteAKRequest{
		Handle:    handle,
		Algorithm: algo,
		Password:  password,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Seal seals data to the TPM, optionally binding to PCR values.
func (b *TPMBinding) Seal(data []byte, cn string, parentHandle uint32,
	parentPassword, password string, pcrIndices []uint32,
	pcrBank string, overwrite bool) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	bank, err := parsePCRBank(pcrBank)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().Seal(b.conn.ctx, &platformv1.SealRequest{
		Data:           data,
		Cn:             cn,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
		Password:       password,
		PcrIndices:     pcrIndices,
		PcrBank:        bank,
		Overwrite:      overwrite,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Unseal retrieves previously sealed data from the TPM.
func (b *TPMBinding) Unseal(cn string, parentHandle uint32,
	parentPassword, password string, pcrIndices []uint32,
	pcrBank string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	bank, err := parsePCRBank(pcrBank)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().Unseal(b.conn.ctx, &platformv1.UnsealRequest{
		Cn:             cn,
		ParentHandle:   parentHandle,
		ParentPassword: parentPassword,
		Password:       password,
		PcrIndices:     pcrIndices,
		PcrBank:        bank,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// Quote generates a TPM quote for remote attestation. The node quotes
// SHA-256(nonce || channel_binding) for this connection (#482); the SDK
// client refuses a quote that is not bound to it.
func (b *TPMBinding) Quote(akHandle uint32, akPassword string,
	pcrIndices []uint32, pcrBank string, nonce []byte) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	bank, err := parsePCRBank(pcrBank)
	if err != nil {
		return nil, err
	}
	resp, err := tpmsvc.NewClientFromGRPC(cl.TPM()).Quote(b.conn.ctx, akHandle, akPassword, pcrIndices, bank, nonce)
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// VerifyQuote verifies a TPM quote for remote attestation. channelBinding
// is the binding Quote returned with the quote; when set, the quote must
// carry SHA-256(nonce || channelBinding).
func (b *TPMBinding) VerifyQuote(quote, signature, akPublic,
	nonce, channelBinding []byte) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := tpmsvc.NewClientFromGRPC(cl.TPM()).VerifyQuote(b.conn.ctx, &platformv1.VerifyQuoteRequest{
		Quote:          quote,
		Signature:      signature,
		AkPublic:       akPublic,
		Nonce:          nonce,
		ChannelBinding: channelBinding,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetEventLog retrieves the TPM event log in the specified format.
func (b *TPMBinding) GetEventLog(format string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetEventLog(b.conn.ctx, &platformv1.GetEventLogRequest{
		Format: format,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetPCRs reads PCR values from the specified bank and indices.
func (b *TPMBinding) GetPCRs(indices []uint32, bank string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	pcrBank, err := parsePCRBank(bank)
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetPCRs(b.conn.ctx, &platformv1.GetPCRsRequest{
		Indices: indices,
		Bank:    pcrBank,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DefineNVRAM defines an NVRAM index in the TPM.
func (b *TPMBinding) DefineNVRAM(index, size uint32, password string,
	attributes []string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().DefineNVRAM(b.conn.ctx, &platformv1.DefineNVRAMRequest{
		Index:      index,
		Size:       size,
		Password:   password,
		Attributes: attributes,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// WriteNVRAM writes data to an NVRAM index in the TPM.
func (b *TPMBinding) WriteNVRAM(index uint32, data []byte, password string,
	offset uint32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().WriteNVRAM(b.conn.ctx, &platformv1.WriteNVRAMRequest{
		Index:    index,
		Data:     data,
		Password: password,
		Offset:   offset,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ReadNVRAM reads data from an NVRAM index in the TPM.
func (b *TPMBinding) ReadNVRAM(index uint32, password string,
	offset, size uint32) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().ReadNVRAM(b.conn.ctx, &platformv1.ReadNVRAMRequest{
		Index:    index,
		Password: password,
		Offset:   offset,
		Size:     size,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// UndefineNVRAM removes an NVRAM index from the TPM.
func (b *TPMBinding) UndefineNVRAM(index uint32, password string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().UndefineNVRAM(b.conn.ctx, &platformv1.UndefineNVRAMRequest{
		Index:    index,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetRandom returns hardware random bytes from the TPM.
func (b *TPMBinding) GetRandom(numBytes uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.TPM().GetRandom(b.conn.ctx, &platformv1.GetRandomRequest{
		NumBytes: numBytes,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// parsePCRBank converts a PCR bank string to the protobuf enum.
// It accepts both short names (e.g., "sha256") and full enum names
// (e.g., "PCR_BANK_SHA256").
func parsePCRBank(input string) (platformv1.PCRBank, error) {
	if input == "" {
		return platformv1.PCRBank_PCR_BANK_UNSPECIFIED, nil
	}

	upper := strings.ToUpper(input)

	if val, ok := platformv1.PCRBank_value[upper]; ok {
		return platformv1.PCRBank(val), nil
	}

	prefixed := "PCR_BANK_" + upper
	if val, ok := platformv1.PCRBank_value[prefixed]; ok {
		return platformv1.PCRBank(val), nil
	}

	return platformv1.PCRBank_PCR_BANK_UNSPECIFIED,
		&InvalidPCRBankError{Input: input}
}
