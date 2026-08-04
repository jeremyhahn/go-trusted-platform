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

package fido2

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
)

// GRPCClient is a FIDO2 Service implementation backed by a gRPC
// FIDO2ServiceClient.
type GRPCClient struct {
	rpc platformv1.FIDO2ServiceClient
}

// NewGRPCClient returns a FIDO2 Service backed by the supplied gRPC
// connection.
func NewGRPCClient(conn *grpc.ClientConn) *GRPCClient {
	return &GRPCClient{rpc: platformv1.NewFIDO2ServiceClient(conn)}
}

// NewGRPCClientFromClient returns a FIDO2 Service backed by a raw proto client.
func NewGRPCClientFromClient(c platformv1.FIDO2ServiceClient) *GRPCClient {
	return &GRPCClient{rpc: c}
}

var roleToProtoMap = map[Role]platformv1.FIDO2Role{
	RoleUnspecified: platformv1.FIDO2Role_FIDO2_ROLE_UNSPECIFIED,
	RoleSO:          platformv1.FIDO2Role_FIDO2_ROLE_SO,
	RoleAdmin:       platformv1.FIDO2Role_FIDO2_ROLE_ADMIN,
	RoleUser:        platformv1.FIDO2Role_FIDO2_ROLE_USER,
}

func deviceFromProto(p *platformv1.FIDO2Device) Device {
	if p == nil {
		return Device{}
	}
	return Device{
		ID:           p.GetId(),
		Path:         p.GetPath(),
		Manufacturer: p.GetManufacturer(),
		Product:      p.GetProduct(),
		ProductID:    p.GetProductId(),
		VendorID:     p.GetVendorId(),
	}
}

// ListDevices proxies ListDevices to the gRPC server.
func (c *GRPCClient) ListDevices(ctx context.Context, _ *ListDevicesRequest) (*ListDevicesResponse, error) {
	resp, err := c.rpc.ListDevices(ctx, &platformv1.FIDO2ListDevicesRequest{})
	if err != nil {
		return nil, &ErrListDevicesFailed{Cause: err}
	}
	out := &ListDevicesResponse{Devices: make([]Device, 0, len(resp.GetDevices()))}
	for _, d := range resp.GetDevices() {
		out.Devices = append(out.Devices, deviceFromProto(d))
	}
	return out, nil
}

// WaitDevice proxies WaitDevice to the gRPC server.
func (c *GRPCClient) WaitDevice(ctx context.Context, req *WaitDeviceRequest) (*WaitDeviceResponse, error) {
	if req == nil {
		req = &WaitDeviceRequest{}
	}
	resp, err := c.rpc.WaitDevice(ctx, &platformv1.FIDO2WaitDeviceRequest{
		TimeoutSeconds: req.TimeoutSeconds,
	})
	if err != nil {
		return nil, &ErrWaitDeviceFailed{Cause: err}
	}
	return &WaitDeviceResponse{Device: deviceFromProto(resp.GetDevice())}, nil
}

// Info proxies Info to the gRPC server.
func (c *GRPCClient) Info(ctx context.Context, req *InfoRequest) (*InfoResponse, error) {
	if req == nil {
		req = &InfoRequest{}
	}
	resp, err := c.rpc.Info(ctx, &platformv1.FIDO2InfoRequest{Device: req.Device})
	if err != nil {
		return nil, &ErrDeviceInfoFailed{Cause: err}
	}
	info := resp.GetInfo()
	return &InfoResponse{
		Info: Info{
			Device:          deviceFromProto(info.GetDevice()),
			AAGUID:          info.GetAaguid(),
			FirmwareVersion: info.GetFirmwareVersion(),
			Extensions:      info.GetExtensions(),
			Options:         info.GetOptions(),
			MaxMsgSize:      info.GetMaxMsgSize(),
		},
	}, nil
}

// Register proxies Register to the gRPC server.
func (c *GRPCClient) Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	if req == nil {
		req = &RegisterRequest{}
	}
	resp, err := c.rpc.Register(ctx, &platformv1.FIDO2RegisterRequest{
		Username:   req.Username,
		Role:       roleToProtoMap[req.Role],
		RequirePin: req.RequirePIN,
		RequireUv:  req.RequireUV,
		RpId:       req.RPID,
	})
	if err != nil {
		return nil, &ErrRegisterFailed{Cause: err}
	}
	return &RegisterResponse{
		CredentialID: resp.GetCredentialId(),
		AAGUID:       resp.GetAaguid(),
		PublicKeyPEM: resp.GetPublicKeyPem(),
	}, nil
}

// Authenticate proxies Authenticate to the gRPC server.
func (c *GRPCClient) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	if req == nil {
		req = &AuthenticateRequest{}
	}
	resp, err := c.rpc.Authenticate(ctx, &platformv1.FIDO2AuthenticateRequest{
		CredentialId: req.CredentialID,
	})
	if err != nil {
		return nil, &ErrAuthenticateFailed{Cause: err}
	}
	return &AuthenticateResponse{
		Authenticated: resp.GetAuthenticated(),
		Counter:       resp.GetCounter(),
	}, nil
}

// Compile-time interface check.
var _ Service = (*GRPCClient)(nil)
