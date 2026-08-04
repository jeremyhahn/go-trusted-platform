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

package tpm

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods accept and return domain types instead of proto types,
// enabling callers to avoid importing platformv1 directly.

// InfoDomain returns TPM capabilities and information using domain types.
func (c *Client) InfoDomain(ctx context.Context) (*InfoResponse, error) {
	resp, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}
	return InfoResponseFromProto(resp), nil
}

// ProvisionDomain initializes the TPM with required keys using domain types.
func (c *Client) ProvisionDomain(ctx context.Context, req *ProvisionRequest) (*ProvisionResponse, error) {
	protoReq := &platformv1.TPMProvisionRequest{
		CreateEk:            req.CreateEK,
		CreateSrk:           req.CreateSRK,
		CreateAk:            req.CreateAK,
		OwnerPassword:       req.OwnerPassword,
		EndorsementPassword: req.EndorsementPassword,
	}
	resp, err := c.Provision(ctx, protoReq)
	if err != nil {
		return nil, err
	}
	return ProvisionResponseFromProto(resp), nil
}

// ClearDomain clears the TPM using domain types.
func (c *Client) ClearDomain(ctx context.Context, ownerPassword string, confirm bool) (*ClearResponse, error) {
	_, err := c.grpc.Clear(ctx, &platformv1.TPMClearRequest{
		OwnerPassword: ownerPassword,
		Confirm:       confirm,
	})
	if err != nil {
		return nil, &ErrClearFailed{Cause: err}
	}
	return &ClearResponse{
		Status: &Status{Success: true, Message: "TPM cleared successfully"},
	}, nil
}

// CreateEKDomain creates an Endorsement Key using domain types.
func (c *Client) CreateEKDomain(ctx context.Context, algorithm KeyAlgorithm, persistent bool) (*CreateKeyResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	resp, err := c.CreateEK(ctx, &platformv1.KeyAttributes{
		Algorithm: protoAlg,
	}, persistent)
	if err != nil {
		return nil, err
	}
	return CreateKeyResponseFromEK(resp), nil
}

// GetEKDomain retrieves the Endorsement Key using domain types.
func (c *Client) GetEKDomain(ctx context.Context, algorithm KeyAlgorithm, handle uint32) (*KeyInfoResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	resp, err := c.GetEK(ctx, protoAlg, handle)
	if err != nil {
		return nil, err
	}
	return KeyInfoResponseFromEK(resp), nil
}

// GetEKCertificateDomain retrieves the EK certificate using domain types.
func (c *Client) GetEKCertificateDomain(ctx context.Context, algorithm KeyAlgorithm, handle uint32) (*EKCertificateResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	resp, err := c.GetEKCertificate(ctx, protoAlg, handle)
	if err != nil {
		return nil, err
	}
	return EKCertificateResponseFromProto(resp), nil
}

// DeleteEKDomain deletes the Endorsement Key using domain types.
func (c *Client) DeleteEKDomain(ctx context.Context, handle uint32, algorithm KeyAlgorithm, password string) (*DeleteKeyResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	err := c.DeleteEK(ctx, handle, protoAlg, password)
	if err != nil {
		return nil, err
	}
	return &DeleteKeyResponse{
		Status: &Status{Success: true, Message: "Key deleted successfully"},
	}, nil
}

// CreateSRKDomain creates a Storage Root Key using domain types.
func (c *Client) CreateSRKDomain(ctx context.Context, algorithm KeyAlgorithm, persistent bool, parentHandle uint32, parentPassword string) (*CreateKeyResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	resp, err := c.CreateSRK(ctx, &platformv1.KeyAttributes{
		Algorithm: protoAlg,
	}, persistent, parentHandle, parentPassword)
	if err != nil {
		return nil, err
	}
	return CreateKeyResponseFromSRK(resp), nil
}

// GetSRKDomain retrieves the Storage Root Key using domain types.
func (c *Client) GetSRKDomain(ctx context.Context, algorithm KeyAlgorithm, handle uint32) (*KeyInfoResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	resp, err := c.GetSRK(ctx, protoAlg, handle)
	if err != nil {
		return nil, err
	}
	return KeyInfoResponseFromSRK(resp), nil
}

// DeleteSRKDomain deletes the Storage Root Key using domain types.
func (c *Client) DeleteSRKDomain(ctx context.Context, handle uint32, algorithm KeyAlgorithm, password string) (*DeleteKeyResponse, error) {
	protoAlg := KeyAlgorithmToProto(algorithm)
	err := c.DeleteSRK(ctx, handle, protoAlg, password)
	if err != nil {
		return nil, err
	}
	return &DeleteKeyResponse{
		Status: &Status{Success: true, Message: "Key deleted successfully"},
	}, nil
}

// SealDomain seals data to the TPM using domain types.
func (c *Client) SealDomain(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	protoReq := SealRequestToProto(req)
	resp, err := c.Seal(ctx, protoReq)
	if err != nil {
		return nil, err
	}
	return SealResponseFromProto(resp), nil
}

// UnsealDomain unseals data from the TPM using domain types.
func (c *Client) UnsealDomain(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	protoReq := UnsealRequestToProto(req)
	data, err := c.Unseal(ctx, protoReq)
	if err != nil {
		return nil, err
	}
	return &UnsealResponse{
		Status: &Status{Success: true},
		Data:   data,
	}, nil
}

// GetEventLogDomain retrieves the TPM event log using domain types.
func (c *Client) GetEventLogDomain(ctx context.Context, format string) (*EventLogResponse, error) {
	resp, err := c.GetEventLog(ctx, format)
	if err != nil {
		return nil, err
	}
	return EventLogResponseFromProto(resp), nil
}

// GetPCRsDomain retrieves PCR values using domain types.
func (c *Client) GetPCRsDomain(ctx context.Context, indices []uint32, bank PCRBank) ([]*PCRValue, error) {
	protoBank := PCRBankToProto(bank)
	pcrValues, err := c.GetPCRs(ctx, indices, protoBank)
	if err != nil {
		return nil, err
	}
	result := make([]*PCRValue, 0, len(pcrValues))
	for _, pv := range pcrValues {
		result = append(result, &PCRValue{
			Index: pv.Index,
			Value: pv.Value,
			Bank:  bank,
		})
	}
	return result, nil
}

// DefineNVRAMDomain defines an NVRAM space using domain types.
func (c *Client) DefineNVRAMDomain(ctx context.Context, index, size uint32, password string, attributes []string) (*NVRAMDefineResponse, error) {
	err := c.DefineNVRAM(ctx, index, size, password, attributes)
	if err != nil {
		return nil, err
	}
	return &NVRAMDefineResponse{
		Status: &Status{Success: true, Message: "NVRAM space defined"},
	}, nil
}

// WriteNVRAMDomain writes data to NVRAM using domain types.
func (c *Client) WriteNVRAMDomain(ctx context.Context, index uint32, data []byte, password string, offset uint32) (*NVRAMWriteResponse, error) {
	err := c.WriteNVRAM(ctx, index, data, password, offset)
	if err != nil {
		return nil, err
	}
	return &NVRAMWriteResponse{
		Status: &Status{Success: true, Message: "NVRAM data written"},
	}, nil
}

// ReadNVRAMDomain reads data from NVRAM using domain types.
func (c *Client) ReadNVRAMDomain(ctx context.Context, index uint32, password string, offset, size uint32) (*NVRAMReadResponse, error) {
	data, err := c.ReadNVRAM(ctx, index, password, offset, size)
	if err != nil {
		return nil, err
	}
	return &NVRAMReadResponse{Data: data}, nil
}

// UndefineNVRAMDomain removes an NVRAM space using domain types.
func (c *Client) UndefineNVRAMDomain(ctx context.Context, index uint32, password string) (*NVRAMUndefineResponse, error) {
	err := c.UndefineNVRAM(ctx, index, password)
	if err != nil {
		return nil, err
	}
	return &NVRAMUndefineResponse{
		Status: &Status{Success: true, Message: "NVRAM space undefined"},
	}, nil
}

// GetRandomDomain generates cryptographically secure random bytes using domain types.
func (c *Client) GetRandomDomain(ctx context.Context, numBytes uint32) ([]byte, error) {
	return c.GetRandom(ctx, numBytes)
}
