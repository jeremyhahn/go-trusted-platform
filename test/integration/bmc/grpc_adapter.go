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

// This file implements the BMCCommands interface using gRPC calls.

//go:build integration

package bmc_integration

import (
	"context"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements BMCCommands using gRPC calls to platformd.
type GRPCAdapter struct {
	conn   *grpc.ClientConn
	bmc    pb.BMCServiceClient
	client *bmcsvc.Client
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := getEnvOrDefault(EnvPlatformGRPCEndpoint, DefaultPlatformGRPCEndpoint)

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.bmc = pb.NewBMCServiceClient(conn)
	g.client = bmcsvc.NewClientFromGRPC(g.bmc)

	// Verify connectivity by calling power status
	_, err = g.bmc.PowerStatus(ctx, &pb.BMCPowerStatusRequest{ProfileId: DefaultTestProfileID})
	if err != nil {
		conn.Close()
		return ErrGRPCConnectionFailed{Endpoint: endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// Power Operations
// =============================================================================

// PowerOn powers on a BMC-managed system via gRPC.
func (g *GRPCAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := g.client.PowerOn(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "PowerOn", Err: err}
	}
	return resp, nil
}

// PowerOff powers off a BMC-managed system via gRPC.
func (g *GRPCAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := g.client.PowerOff(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "PowerOff", Err: err}
	}
	return resp, nil
}

// PowerStatus queries the current power state via gRPC.
func (g *GRPCAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	state, err := g.client.PowerStatus(ctx, profileID)
	if err != nil {
		return bmcsvc.PowerStateUnspecified, ErrGRPCCallFailed{Method: "PowerStatus", Err: err}
	}
	return state, nil
}

// =============================================================================
// Boot Device Operations
// =============================================================================

// SetBootDevice sets the boot device via gRPC.
func (g *GRPCAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	err := g.client.SetBootDevice(ctx, profileID, device, persistent)
	if err != nil {
		return ErrGRPCCallFailed{Method: "SetBootDevice", Err: err}
	}
	return nil
}

// GetBootDevice queries the current boot device via gRPC.
func (g *GRPCAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	device, err := g.client.GetBootDevice(ctx, profileID)
	if err != nil {
		return bmcsvc.BootDeviceUnspecified, ErrGRPCCallFailed{Method: "GetBootDevice", Err: err}
	}
	return device, nil
}

// =============================================================================
// Virtual Media Operations
// =============================================================================

// MountISO mounts an ISO via gRPC.
func (g *GRPCAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	err := g.client.MountISO(ctx, profileID, isoURL)
	if err != nil {
		return ErrGRPCCallFailed{Method: "MountISO", Err: err}
	}
	return nil
}

// UnmountISO unmounts virtual media via gRPC.
func (g *GRPCAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	err := g.client.UnmountISO(ctx, profileID)
	if err != nil {
		return ErrGRPCCallFailed{Method: "UnmountISO", Err: err}
	}
	return nil
}

// VirtualMediaStatus queries virtual media status via gRPC.
func (g *GRPCAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	info, err := g.client.VirtualMediaStatus(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VirtualMediaStatus", Err: err}
	}
	return info, nil
}

// =============================================================================
// Sensor Operations
// =============================================================================

// GetSensors queries sensor readings via gRPC.
func (g *GRPCAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	sensors, err := g.client.GetSensors(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSensors", Err: err}
	}
	return sensors, nil
}

// =============================================================================
// System Info Operations
// =============================================================================

// GetSystemInfo queries system information via gRPC.
func (g *GRPCAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	info, err := g.client.GetSystemInfo(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSystemInfo", Err: err}
	}
	return info, nil
}

// =============================================================================
// Certificate Operations
// =============================================================================

// GetWebCertificate queries the BMC web certificate via gRPC.
func (g *GRPCAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	info, err := g.client.GetWebCertificate(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetWebCertificate", Err: err}
	}
	return info, nil
}

// =============================================================================
// User Management Operations
// =============================================================================

// ListUsers lists BMC users via gRPC.
func (g *GRPCAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	users, err := g.client.ListUsers(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListUsers", Err: err}
	}
	return users, nil
}

// =============================================================================
// Enrollment Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony via gRPC (BMCService/EnrollBMC).
// It delegates to the SDK client which translates between the local EnrollOptions
// and the proto BMCEnrollRequest.
func (g *GRPCAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	sdkOpts := enrollOptionsToSDK(opts)
	resp, err := g.client.EnrollBMC(ctx, profileID, sdkOpts)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "EnrollBMC", Err: err}
	}
	return sdkEnrollResultToDomain(resp), nil
}

// =============================================================================
// Factory Certificate Restore Operations
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony via gRPC
// (BMCService/RestoreFactoryCert). It delegates to the SDK client.
func (g *GRPCAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	resp, err := g.client.RestoreFactoryCert(ctx, profileID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RestoreFactoryCert", Err: err}
	}
	return sdkRestoreResultToDomain(resp), nil
}

// Ensure GRPCAdapter implements BMCCommands interface.
var _ BMCCommands = (*GRPCAdapter)(nil)
