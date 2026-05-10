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

package piv

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc"
)

// GRPCClient is a PIV Service implementation backed by a gRPC
// PIVServiceClient.
type GRPCClient struct {
	rpc platformv1.PIVServiceClient
}

// NewGRPCClient returns a PIV Service backed by the supplied gRPC
// connection.
func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	return &GRPCClient{rpc: platformv1.NewPIVServiceClient(conn)}
}

// NewGRPCClientFromClient returns a PIV Service backed by a raw proto client.
func NewGRPCClientFromClient(c platformv1.PIVServiceClient) *GRPCClient {
	return &GRPCClient{rpc: c}
}

var algorithmToProto = map[Algorithm]platformv1.PIVAlgorithm{
	AlgorithmUnspecified: platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED,
	AlgorithmRSA:         platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA,
	AlgorithmECDSA:       platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA,
	AlgorithmEd25519:     platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519,
}

var algorithmFromProto = map[platformv1.PIVAlgorithm]Algorithm{
	platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED: AlgorithmUnspecified,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA:         AlgorithmRSA,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA:       AlgorithmECDSA,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519:     AlgorithmEd25519,
}

func deviceFromProto(p *platformv1.PIVDevice) Device {
	if p == nil {
		return Device{}
	}
	return Device{
		ID:              p.GetId(),
		Name:            p.GetName(),
		Manufacturer:    p.GetManufacturer(),
		Model:           p.GetModel(),
		Serial:          p.GetSerial(),
		FirmwareVersion: p.GetFirmwareVersion(),
	}
}

func slotFromProto(p *platformv1.PIVSlot) Slot {
	if p == nil {
		return Slot{}
	}
	return Slot{
		ID:             p.GetId(),
		Name:           p.GetName(),
		Algorithm:      algorithmFromProto[p.GetAlgorithm()],
		HasKey:         p.GetHasKey(),
		HasCertificate: p.GetHasCertificate(),
	}
}

// ListDevices proxies ListDevices to the gRPC server.
func (c *GRPCClient) ListDevices(ctx context.Context, _ *ListDevicesRequest) (*ListDevicesResponse, error) {
	resp, err := c.rpc.ListDevices(ctx, &platformv1.PIVListDevicesRequest{})
	if err != nil {
		return nil, &ErrListDevicesFailed{Cause: err}
	}
	out := &ListDevicesResponse{Devices: make([]Device, 0, len(resp.GetDevices()))}
	for _, d := range resp.GetDevices() {
		out.Devices = append(out.Devices, deviceFromProto(d))
	}
	return out, nil
}

// ListSlots proxies ListSlots to the gRPC server.
func (c *GRPCClient) ListSlots(ctx context.Context, req *ListSlotsRequest) (*ListSlotsResponse, error) {
	if req == nil {
		req = &ListSlotsRequest{}
	}
	resp, err := c.rpc.ListSlots(ctx, &platformv1.PIVListSlotsRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrListSlotsFailed{Cause: err}
	}
	out := &ListSlotsResponse{Slots: make([]Slot, 0, len(resp.GetSlots()))}
	for _, s := range resp.GetSlots() {
		out.Slots = append(out.Slots, slotFromProto(s))
	}
	return out, nil
}

// SlotInfo proxies SlotInfo to the gRPC server.
func (c *GRPCClient) SlotInfo(ctx context.Context, req *SlotInfoRequest) (*SlotInfoResponse, error) {
	if req == nil {
		req = &SlotInfoRequest{}
	}
	resp, err := c.rpc.SlotInfo(ctx, &platformv1.PIVSlotInfoRequest{
		Slot:   req.Slot,
		Device: req.Device,
	})
	if err != nil {
		return nil, &ErrSlotInfoFailed{Cause: err}
	}
	return &SlotInfoResponse{
		Slot:           slotFromProto(resp.GetSlot()),
		PublicKeyPEM:   resp.GetPublicKeyPem(),
		CertificatePEM: resp.GetCertificatePem(),
	}, nil
}

// Generate proxies Generate to the gRPC server.
func (c *GRPCClient) Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error) {
	if req == nil {
		req = &GenerateRequest{}
	}
	resp, err := c.rpc.Generate(ctx, &platformv1.PIVGenerateRequest{
		Slot:      req.Slot,
		Algorithm: algorithmToProto[req.Algorithm],
		Pin:       req.PIN,
	})
	if err != nil {
		return nil, &ErrGenerateFailed{Cause: err}
	}
	return &GenerateResponse{PublicKeyPEM: resp.GetPublicKeyPem()}, nil
}

// Import proxies Import to the gRPC server.
func (c *GRPCClient) Import(ctx context.Context, req *ImportRequest) (*ImportResponse, error) {
	if req == nil {
		req = &ImportRequest{}
	}
	resp, err := c.rpc.Import(ctx, &platformv1.PIVImportRequest{
		Slot:          req.Slot,
		PrivateKeyPem: req.PrivateKeyPEM,
		Pin:           req.PIN,
	})
	if err != nil {
		return nil, &ErrImportFailed{Cause: err}
	}
	return &ImportResponse{Imported: resp.GetImported()}, nil
}

// Sign proxies Sign to the gRPC server.
func (c *GRPCClient) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	if req == nil {
		req = &SignRequest{}
	}
	resp, err := c.rpc.Sign(ctx, &platformv1.PIVSignRequest{
		Slot:    req.Slot,
		Payload: req.Payload,
		Pin:     req.PIN,
	})
	if err != nil {
		return nil, &ErrSignFailed{Cause: err}
	}
	return &SignResponse{Signature: resp.GetSignature()}, nil
}

// Attest proxies Attest to the gRPC server.
func (c *GRPCClient) Attest(ctx context.Context, req *AttestRequest) (*AttestResponse, error) {
	if req == nil {
		req = &AttestRequest{}
	}
	resp, err := c.rpc.Attest(ctx, &platformv1.PIVAttestRequest{Slot: req.Slot})
	if err != nil {
		return nil, &ErrAttestFailed{Cause: err}
	}
	return &AttestResponse{
		AttestationCertPEM:  resp.GetAttestationCertPem(),
		AttestationChainPEM: resp.GetAttestationChainPem(),
	}, nil
}

// Reset proxies Reset to the gRPC server.
func (c *GRPCClient) Reset(ctx context.Context, req *ResetRequest) (*ResetResponse, error) {
	if req == nil {
		req = &ResetRequest{}
	}
	resp, err := c.rpc.Reset(ctx, &platformv1.PIVResetRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrResetFailed{Cause: err}
	}
	return &ResetResponse{Reset: resp.GetReset_()}, nil
}

// Compile-time interface check.
var _ Service = (*GRPCClient)(nil)
