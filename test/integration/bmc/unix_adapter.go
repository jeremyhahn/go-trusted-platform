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

// This file implements the BMCCommands interface using gRPC over Unix socket.

//go:build integration

package bmc_integration

import (
	"context"
	"net"

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements BMCCommands using gRPC over Unix domain socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *bmcsvc.Client
}

// NewUnixAdapter creates a new UnixAdapter instance.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix socket.
// Unix domain sockets use insecure transport credentials because TLS is not
// needed for local IPC -- the kernel enforces access control via file permissions.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	u.socketPath = getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket)

	conn, err := grpc.DialContext(ctx, "unix://"+u.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", u.socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		return ErrUnixConnectionFailed{Path: u.socketPath, Err: err}
	}

	u.conn = conn
	bmcGRPC := pb.NewBMCServiceClient(conn)
	u.client = bmcsvc.NewClientFromGRPC(bmcGRPC)

	// Verify connectivity with a power status call
	_, err = bmcGRPC.PowerStatus(ctx, &pb.BMCPowerStatusRequest{ProfileId: DefaultTestProfileID})
	if err != nil {
		u.conn.Close()
		return ErrUnixBackendUnavailable{Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// =============================================================================
// Power Operations
// =============================================================================

// PowerOn powers on a BMC-managed system via Unix socket.
func (u *UnixAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := u.client.PowerOn(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "PowerOn", Err: err}
	}
	return resp, nil
}

// PowerOff powers off a BMC-managed system via Unix socket.
func (u *UnixAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := u.client.PowerOff(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "PowerOff", Err: err}
	}
	return resp, nil
}

// PowerStatus queries the current power state via Unix socket.
func (u *UnixAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	state, err := u.client.PowerStatus(ctx, profileID)
	if err != nil {
		return bmcsvc.PowerStateUnspecified, ErrUnixRPCFailed{Method: "PowerStatus", Err: err}
	}
	return state, nil
}

// =============================================================================
// Boot Device Operations
// =============================================================================

// SetBootDevice sets the boot device via Unix socket.
func (u *UnixAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	err := u.client.SetBootDevice(ctx, profileID, device, persistent)
	if err != nil {
		return ErrUnixRPCFailed{Method: "SetBootDevice", Err: err}
	}
	return nil
}

// GetBootDevice queries the current boot device via Unix socket.
func (u *UnixAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	device, err := u.client.GetBootDevice(ctx, profileID)
	if err != nil {
		return bmcsvc.BootDeviceUnspecified, ErrUnixRPCFailed{Method: "GetBootDevice", Err: err}
	}
	return device, nil
}

// =============================================================================
// Virtual Media Operations
// =============================================================================

// MountISO mounts an ISO via Unix socket.
func (u *UnixAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	err := u.client.MountISO(ctx, profileID, isoURL)
	if err != nil {
		return ErrUnixRPCFailed{Method: "MountISO", Err: err}
	}
	return nil
}

// UnmountISO unmounts virtual media via Unix socket.
func (u *UnixAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	err := u.client.UnmountISO(ctx, profileID)
	if err != nil {
		return ErrUnixRPCFailed{Method: "UnmountISO", Err: err}
	}
	return nil
}

// VirtualMediaStatus queries virtual media status via Unix socket.
func (u *UnixAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	info, err := u.client.VirtualMediaStatus(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VirtualMediaStatus", Err: err}
	}
	return info, nil
}

// =============================================================================
// Sensor Operations
// =============================================================================

// GetSensors queries sensor readings via Unix socket.
func (u *UnixAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	sensors, err := u.client.GetSensors(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSensors", Err: err}
	}
	return sensors, nil
}

// =============================================================================
// System Info Operations
// =============================================================================

// GetSystemInfo queries system information via Unix socket.
func (u *UnixAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	info, err := u.client.GetSystemInfo(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSystemInfo", Err: err}
	}
	return info, nil
}

// =============================================================================
// Certificate Operations
// =============================================================================

// GetWebCertificate queries the BMC web certificate via Unix socket.
func (u *UnixAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	info, err := u.client.GetWebCertificate(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetWebCertificate", Err: err}
	}
	return info, nil
}

// =============================================================================
// User Management Operations
// =============================================================================

// ListUsers lists BMC users via Unix socket.
func (u *UnixAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	users, err := u.client.ListUsers(ctx, profileID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListUsers", Err: err}
	}
	return users, nil
}

// Ensure UnixAdapter implements BMCCommands interface.
var _ BMCCommands = (*UnixAdapter)(nil)
