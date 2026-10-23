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

//go:build integration

package tpm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TPMAttrCommands is the capability, platform-attribute, PCR-extend and
// credential surface of docs/tpm/api.md §3, §5 and §7. Every network
// transport serves it; platformctl has no verbs for it, so the CLI adapter
// does not implement it.
type TPMAttrCommands interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	Capabilities(ctx context.Context) (*CapabilitiesResult, error)
	PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error)
	ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error
	MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error)
	ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error)
}

// CapabilitiesResult holds the TPM's algorithm, command and ECC-curve names.
type CapabilitiesResult struct {
	Algorithms []string
	Commands   []string
	ECCCurves  []string
}

// KeyRef names a provisioned key by persistent handle and algorithm.
type KeyRef struct {
	Handle    uint32
	Algorithm string
}

// PlatformAttributesResult describes the TPM device and its identity keys.
// A key that is not provisioned is nil.
type PlatformAttributesResult struct {
	Device       string
	IsFIPS       bool
	PCRExtended  bool
	CanSeal      bool
	IsSimulator  bool
	Manufacturer string
	EK           *KeyRef
	SRK          *KeyRef
	IAK          *KeyRef
}

// CredentialChallenge is a TPM2_MakeCredential result.
type CredentialChallenge struct {
	CredentialBlob  []byte
	EncryptedSecret []byte
	Secret          []byte
}

// MCP tool names of the attribute surface.
const (
	MCPToolTPMCapabilities       = "platform_tpm_capabilities"
	MCPToolTPMPlatform           = "platform_tpm_platform"
	MCPToolTPMPCRExtend          = "platform_tpm_pcr_extend"
	MCPToolTPMMakeCredential     = "platform_tpm_make_credential"
	MCPToolTPMActivateCredential = "platform_tpm_activate_credential"
)

// =============================================================================
// TPMService RPCs (REST, gRPC and Unix)
// =============================================================================

// The REST, gRPC and Unix adapters call the same TPMService RPCs; only the
// client's transport differs.

func rpcCapabilities(ctx context.Context, protocol string, client pb.TPMServiceClient) (*CapabilitiesResult, error) {
	resp, err := client.GetCapabilities(ctx, &pb.TPMCapabilitiesRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: protocol, Method: "GetCapabilities", Err: err}
	}
	return &CapabilitiesResult{
		Algorithms: resp.GetAlgorithms(),
		Commands:   resp.GetCommands(),
		ECCCurves:  resp.GetEccCurves(),
	}, nil
}

func rpcPlatformAttributes(ctx context.Context, protocol string, client pb.TPMServiceClient) (*PlatformAttributesResult, error) {
	resp, err := client.GetPlatformAttributes(ctx, &pb.TPMPlatformAttributesRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: protocol, Method: "GetPlatformAttributes", Err: err}
	}
	return &PlatformAttributesResult{
		Device:       resp.GetDevice(),
		IsFIPS:       resp.GetIsFips(),
		PCRExtended:  resp.GetPcrExtended(),
		CanSeal:      resp.GetCanSeal(),
		IsSimulator:  resp.GetIsSimulator(),
		Manufacturer: resp.GetManufacturer(),
		EK:           keyRefFromProto(resp.GetEk()),
		SRK:          keyRefFromProto(resp.GetSrk()),
		IAK:          keyRefFromProto(resp.GetIak()),
	}, nil
}

func keyRefFromProto(ref *pb.TPMKeyRef) *KeyRef {
	if ref == nil {
		return nil
	}
	return &KeyRef{Handle: ref.GetHandle(), Algorithm: ref.GetAlgorithm()}
}

func rpcExtendPCR(ctx context.Context, protocol string, client pb.TPMServiceClient, index int, hashAlg string, data []byte) error {
	_, err := client.ExtendPCR(ctx, &pb.ExtendPCRRequest{Index: uint32(index), HashAlg: hashAlg, Data: data})
	if err != nil {
		return ErrCallFailed{Protocol: protocol, Method: "ExtendPCR", Err: err}
	}
	return nil
}

func rpcMakeCredential(ctx context.Context, protocol string, client pb.TPMServiceClient, akName, secret []byte) (*CredentialChallenge, error) {
	resp, err := client.MakeCredential(ctx, &pb.MakeCredentialRequest{AkName: akName, Secret: secret})
	if err != nil {
		return nil, ErrCallFailed{Protocol: protocol, Method: "MakeCredential", Err: err}
	}
	return &CredentialChallenge{
		CredentialBlob:  resp.GetCredentialBlob(),
		EncryptedSecret: resp.GetEncryptedSecret(),
		Secret:          resp.GetSecret(),
	}, nil
}

func rpcActivateCredential(ctx context.Context, protocol string, client pb.TPMServiceClient, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	resp, err := client.ActivateCredential(ctx, &pb.TPMActivateCredentialRequest{
		CredentialBlob:  credentialBlob,
		EncryptedSecret: encryptedSecret,
	})
	if err != nil {
		return nil, ErrCallFailed{Protocol: protocol, Method: "ActivateCredential", Err: err}
	}
	return resp.GetSecret(), nil
}

// tpmService is the TPMService client of the SDK connection.
func (r *RESTAdapter) tpmService() pb.TPMServiceClient { return r.platform.TPM() }

// Capabilities lists the TPM's capabilities via the SDK client over REST.
func (r *RESTAdapter) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	return rpcCapabilities(ctx, r.Name(), r.tpmService())
}

// PlatformAttributes describes the TPM via the SDK client over REST.
func (r *RESTAdapter) PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error) {
	return rpcPlatformAttributes(ctx, r.Name(), r.tpmService())
}

// ExtendPCR extends a PCR via the SDK client over REST.
func (r *RESTAdapter) ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error {
	return rpcExtendPCR(ctx, r.Name(), r.tpmService(), index, hashAlg, data)
}

// MakeCredential makes a credential challenge via the SDK client over REST.
func (r *RESTAdapter) MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error) {
	return rpcMakeCredential(ctx, r.Name(), r.tpmService(), akName, secret)
}

// ActivateCredential activates a credential via the SDK client over REST.
func (r *RESTAdapter) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return rpcActivateCredential(ctx, r.Name(), r.tpmService(), credentialBlob, encryptedSecret)
}

// tpmService is the TPMService client of the gRPC connection.
func (g *GRPCAdapter) tpmService() pb.TPMServiceClient { return pb.NewTPMServiceClient(g.conn) }

// Capabilities lists the TPM's capabilities over gRPC.
func (g *GRPCAdapter) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	return rpcCapabilities(ctx, g.Name(), g.tpmService())
}

// PlatformAttributes describes the TPM over gRPC.
func (g *GRPCAdapter) PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error) {
	return rpcPlatformAttributes(ctx, g.Name(), g.tpmService())
}

// ExtendPCR extends a PCR over gRPC.
func (g *GRPCAdapter) ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error {
	return rpcExtendPCR(ctx, g.Name(), g.tpmService(), index, hashAlg, data)
}

// MakeCredential makes a credential challenge over gRPC.
func (g *GRPCAdapter) MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error) {
	return rpcMakeCredential(ctx, g.Name(), g.tpmService(), akName, secret)
}

// ActivateCredential activates a credential over gRPC.
func (g *GRPCAdapter) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return rpcActivateCredential(ctx, g.Name(), g.tpmService(), credentialBlob, encryptedSecret)
}

// PCRValue reads one sha256 PCR over gRPC; the attribute suite uses it as
// the reference reader for every transport's extend.
func (g *GRPCAdapter) PCRValue(ctx context.Context, index int) ([]byte, error) {
	resp, err := g.tpmService().GetPCRs(ctx, &pb.GetPCRsRequest{
		Indices: []uint32{uint32(index)},
		Bank:    pb.PCRBank_PCR_BANK_SHA256,
	})
	if err != nil {
		return nil, ErrCallFailed{Protocol: g.Name(), Method: "GetPCRs", Err: err}
	}
	for _, value := range resp.GetPcrValues() {
		if value.GetIndex() == uint32(index) {
			return value.GetValue(), nil
		}
	}
	return nil, ErrCallFailed{Protocol: g.Name(), Method: "GetPCRs", Err: ErrPCRNotReturned{Index: index}}
}

// ErrPCRNotReturned is returned when GetPCRs answers without the asked index.
type ErrPCRNotReturned struct {
	Index int
}

func (e ErrPCRNotReturned) Error() string {
	return fmt.Sprintf("GetPCRs did not return PCR %d", e.Index)
}

// tpmService is the TPMService client of the Unix socket connection.
func (u *UnixAdapter) tpmService() pb.TPMServiceClient { return pb.NewTPMServiceClient(u.conn) }

// Capabilities lists the TPM's capabilities over the Unix socket.
func (u *UnixAdapter) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	return rpcCapabilities(ctx, u.Name(), u.tpmService())
}

// PlatformAttributes describes the TPM over the Unix socket.
func (u *UnixAdapter) PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error) {
	return rpcPlatformAttributes(ctx, u.Name(), u.tpmService())
}

// ExtendPCR extends a PCR over the Unix socket.
func (u *UnixAdapter) ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error {
	return rpcExtendPCR(ctx, u.Name(), u.tpmService(), index, hashAlg, data)
}

// MakeCredential makes a credential challenge over the Unix socket.
func (u *UnixAdapter) MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error) {
	return rpcMakeCredential(ctx, u.Name(), u.tpmService(), akName, secret)
}

// ActivateCredential activates a credential over the Unix socket.
func (u *UnixAdapter) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	return rpcActivateCredential(ctx, u.Name(), u.tpmService(), credentialBlob, encryptedSecret)
}

// =============================================================================
// QUIC sub-opcodes
// =============================================================================

// Capabilities lists the TPM's capabilities with QUIC 0x99·0x17.
func (q *QUICAdapter) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Capabilities, nil)
	if err != nil {
		return nil, err
	}
	var caps quicapi.TPM2CapabilitiesResponse
	if err := decodeTPMPayload(resp.Payload, &caps); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Capabilities", Err: err}
	}
	return &CapabilitiesResult{Algorithms: caps.Algorithms, Commands: caps.Commands, ECCCurves: caps.ECCCurves}, nil
}

// PlatformAttributes describes the TPM with QUIC 0x99·0x1E.
func (q *QUICAdapter) PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2PlatformAttrs, nil)
	if err != nil {
		return nil, err
	}
	var attrs quicapi.TPM2PlatformAttributesResponse
	if err := decodeTPMPayload(resp.Payload, &attrs); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "PlatformAttributes", Err: err}
	}
	return &PlatformAttributesResult{
		Device:       attrs.Device,
		IsFIPS:       attrs.IsFIPS,
		PCRExtended:  attrs.PCRExtended,
		CanSeal:      attrs.CanSeal,
		IsSimulator:  attrs.IsSimulator,
		Manufacturer: attrs.Manufacturer,
		EK:           keyRefFromQUIC(attrs.EK),
		SRK:          keyRefFromQUIC(attrs.SRK),
		IAK:          keyRefFromQUIC(attrs.IAK),
	}, nil
}

func keyRefFromQUIC(ref *quicapi.TPM2KeyRef) *KeyRef {
	if ref == nil {
		return nil
	}
	return &KeyRef{Handle: ref.Handle, Algorithm: ref.Algorithm}
}

// ExtendPCR extends a PCR with QUIC 0x99·0x12.
func (q *QUICAdapter) ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error {
	_, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2ExtendPCR, &quicapi.TPM2ExtendPCRRequest{
		PCRIndex: index,
		HashAlg:  hashAlg,
		Data:     data,
	})
	return err
}

// MakeCredential makes a credential challenge with QUIC 0x99·0x20.
func (q *QUICAdapter) MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2MakeCred, &quicapi.TPM2MakeCredentialRequest{
		AKName: akName,
		Secret: secret,
	})
	if err != nil {
		return nil, err
	}
	var made quicapi.TPM2MakeCredentialResponse
	if err := decodeTPMPayload(resp.Payload, &made); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "MakeCredential", Err: err}
	}
	return &CredentialChallenge{
		CredentialBlob:  made.CredentialBlob,
		EncryptedSecret: made.EncryptedSecret,
		Secret:          made.Secret,
	}, nil
}

// ActivateCredential activates a credential with QUIC 0x99·0x21.
func (q *QUICAdapter) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2ActivateCred, &quicapi.TPM2ActivateCredentialRequest{
		CredentialBlob:  credentialBlob,
		EncryptedSecret: encryptedSecret,
	})
	if err != nil {
		return nil, err
	}
	var activated quicapi.TPM2ActivateCredentialResponse
	if err := decodeTPMPayload(resp.Payload, &activated); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "ActivateCredential", Err: err}
	}
	return activated.Secret, nil
}

// =============================================================================
// MCP tools
// =============================================================================

// callToolInto calls an MCP tool and decodes its JSON result into out.
func (m *MCPAdapter) callToolInto(ctx context.Context, tool string, args map[string]interface{}, out interface{}) error {
	result, err := m.callTool(ctx, tool, args)
	if err != nil {
		return err
	}
	data, err := m.extractToolJSON(result)
	if err != nil {
		return ErrMCPTPMResponseParseFailed{Tool: tool, Err: err}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return ErrMCPTPMResponseParseFailed{Tool: tool, Err: err}
	}
	return nil
}

// Capabilities lists the TPM's capabilities with platform_tpm_capabilities.
func (m *MCPAdapter) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	var resp struct {
		Algorithms []string `json:"algorithms"`
		Commands   []string `json:"commands"`
		ECCCurves  []string `json:"ecc_curves"`
	}
	if err := m.callToolInto(ctx, MCPToolTPMCapabilities, nil, &resp); err != nil {
		return nil, err
	}
	return &CapabilitiesResult{Algorithms: resp.Algorithms, Commands: resp.Commands, ECCCurves: resp.ECCCurves}, nil
}

// PlatformAttributes describes the TPM with platform_tpm_platform, which
// carries each provisioned key as <key>_handle and <key>_algorithm.
func (m *MCPAdapter) PlatformAttributes(ctx context.Context) (*PlatformAttributesResult, error) {
	var resp struct {
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
	if err := m.callToolInto(ctx, MCPToolTPMPlatform, nil, &resp); err != nil {
		return nil, err
	}
	return &PlatformAttributesResult{
		Device:       resp.Device,
		IsFIPS:       resp.IsFIPS,
		PCRExtended:  resp.PCRExtended,
		CanSeal:      resp.CanSeal,
		IsSimulator:  resp.IsSimulator,
		Manufacturer: resp.Manufacturer,
		EK:           keyRefFromMCP(resp.EKHandle, resp.EKAlgorithm),
		SRK:          keyRefFromMCP(resp.SRKHandle, resp.SRKAlgorithm),
		IAK:          keyRefFromMCP(resp.IAKHandle, resp.IAKAlgorithm),
	}, nil
}

func keyRefFromMCP(handle *uint32, algorithm string) *KeyRef {
	if handle == nil {
		return nil
	}
	return &KeyRef{Handle: *handle, Algorithm: algorithm}
}

// ExtendPCR extends a PCR with platform_tpm_pcr_extend.
func (m *MCPAdapter) ExtendPCR(ctx context.Context, index int, hashAlg string, data []byte) error {
	var resp struct {
		Success bool `json:"success"`
	}
	return m.callToolInto(ctx, MCPToolTPMPCRExtend, map[string]interface{}{
		"pcr_index": index,
		"hash_alg":  hashAlg,
		"data":      base64.StdEncoding.EncodeToString(data),
	}, &resp)
}

// MakeCredential makes a credential challenge with platform_tpm_make_credential.
func (m *MCPAdapter) MakeCredential(ctx context.Context, akName, secret []byte) (*CredentialChallenge, error) {
	var resp struct {
		CredentialBlob  string `json:"credential_blob"`
		EncryptedSecret string `json:"encrypted_secret"`
		Secret          string `json:"secret"`
	}
	if err := m.callToolInto(ctx, MCPToolTPMMakeCredential, map[string]interface{}{
		"ak_name": base64.StdEncoding.EncodeToString(akName),
		"secret":  base64.StdEncoding.EncodeToString(secret),
	}, &resp); err != nil {
		return nil, err
	}
	fields, err := decodeMCPBase64(MCPToolTPMMakeCredential, resp.CredentialBlob, resp.EncryptedSecret, resp.Secret)
	if err != nil {
		return nil, err
	}
	return &CredentialChallenge{CredentialBlob: fields[0], EncryptedSecret: fields[1], Secret: fields[2]}, nil
}

// ActivateCredential activates a credential with platform_tpm_activate_credential.
func (m *MCPAdapter) ActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	var resp struct {
		Secret string `json:"secret"`
	}
	if err := m.callToolInto(ctx, MCPToolTPMActivateCredential, map[string]interface{}{
		"credential_blob":  base64.StdEncoding.EncodeToString(credentialBlob),
		"encrypted_secret": base64.StdEncoding.EncodeToString(encryptedSecret),
	}, &resp); err != nil {
		return nil, err
	}
	fields, err := decodeMCPBase64(MCPToolTPMActivateCredential, resp.Secret)
	if err != nil {
		return nil, err
	}
	return fields[0], nil
}

// decodeMCPBase64 decodes the base64 fields of an MCP tool result.
func decodeMCPBase64(tool string, encoded ...string) ([][]byte, error) {
	decoded := make([][]byte, 0, len(encoded))
	for _, field := range encoded {
		raw, err := base64.StdEncoding.DecodeString(field)
		if err != nil {
			return nil, ErrMCPTPMResponseParseFailed{Tool: tool, Err: err}
		}
		decoded = append(decoded, raw)
	}
	return decoded, nil
}

var (
	_ TPMAttrCommands = (*RESTAdapter)(nil)
	_ TPMAttrCommands = (*GRPCAdapter)(nil)
	_ TPMAttrCommands = (*UnixAdapter)(nil)
	_ TPMAttrCommands = (*QUICAdapter)(nil)
	_ TPMAttrCommands = (*MCPAdapter)(nil)
)
