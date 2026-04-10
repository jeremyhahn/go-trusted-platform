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

// Package pxe provides integration test adapters for PXE provisioning services.
// This file implements the PXECommands interface using gRPC.

//go:build integration

package pxe

import (
	"context"
	"os"
	"time"
)

// =============================================================================
// gRPC Adapter Implementation
// =============================================================================

// GRPCAdapter implements PXECommands using gRPC calls to platformd.
// This adapter makes gRPC calls to the platformd server for testing
// the gRPC transport layer consistency with other protocol adapters.
type GRPCAdapter struct {
	endpoint string
	// TODO: Add gRPC connection and client fields when proto definitions are available
	// conn *grpc.ClientConn
	// pxe  pb.PXEServiceClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}

	return &GRPCAdapter{
		endpoint: endpoint,
	}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	// TODO: Implement gRPC connection setup when proto definitions are available
	// conn, err := grpc.NewClient(g.endpoint,
	// 	helpers.GRPCTransportCredentials(),
	// )
	// if err != nil {
	// 	return ErrConnectionFailed{Protocol: "gRPC", Endpoint: g.endpoint, Err: err}
	// }
	// g.conn = conn
	// g.pxe = pb.NewPXEServiceClient(conn)
	//
	// // Verify connectivity
	// _, err = g.pxe.GetStatus(ctx, &pb.GetStatusRequest{})
	// if err != nil {
	// 	conn.Close()
	// 	return ErrConnectionFailed{Protocol: "gRPC", Endpoint: g.endpoint, Err: err}
	// }

	return ErrConnectionFailed{
		Protocol: "gRPC",
		Endpoint: g.endpoint,
		Err:      ErrInvalidOperation{Operation: "Setup", Reason: "gRPC adapter not yet implemented - awaiting proto definitions"},
	}
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	// TODO: Implement when proto definitions are available
	// if g.conn != nil {
	// 	return g.conn.Close()
	// }
	return nil
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device via gRPC.
func (g *GRPCAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	// TODO: Implement when proto definitions are available
	// req := &pb.RegisterDeviceRequest{
	// 	MacAddress: opts.MACAddress,
	// 	PortId:     opts.PortID,
	// }
	// resp, err := g.pxe.RegisterDevice(ctx, req)
	// if err != nil {
	// 	return nil, ErrRequestFailed{Protocol: "gRPC", Method: "RegisterDevice", Err: err}
	// }
	// return &RegisterDeviceResult{...}, nil

	return nil, ErrInvalidOperation{Operation: "RegisterDevice", Reason: "gRPC adapter not yet implemented"}
}

// GetDevice retrieves device information via gRPC.
func (g *GRPCAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "GetDevice", Reason: "gRPC adapter not yet implemented"}
}

// GetDeviceByMAC retrieves a device by MAC address via gRPC.
func (g *GRPCAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "GetDeviceByMAC", Reason: "gRPC adapter not yet implemented"}
}

// ListDevices lists devices via gRPC.
func (g *GRPCAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "ListDevices", Reason: "gRPC adapter not yet implemented"}
}

// RemoveDevice removes a device via gRPC.
func (g *GRPCAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "RemoveDevice", Reason: "gRPC adapter not yet implemented"}
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via gRPC.
func (g *GRPCAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "UpdateDeviceState", Reason: "gRPC adapter not yet implemented"}
}

// SetDeviceEnrolled sets a device as enrolled via gRPC.
func (g *GRPCAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "SetDeviceEnrolled", Reason: "gRPC adapter not yet implemented"}
}

// AuthorizeDevice authorizes a device via gRPC.
func (g *GRPCAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "AuthorizeDevice", Reason: "gRPC adapter not yet implemented"}
}

// QuarantineDevice quarantines a device via gRPC.
func (g *GRPCAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "QuarantineDevice", Reason: "gRPC adapter not yet implemented"}
}

// RetryDevice retries a device via gRPC.
func (g *GRPCAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "RetryDevice", Reason: "gRPC adapter not yet implemented"}
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via gRPC.
func (g *GRPCAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "GetEvents", Reason: "gRPC adapter not yet implemented"}
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via gRPC.
func (g *GRPCAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	// TODO: Implement when proto definitions are available
	return nil, ErrInvalidOperation{Operation: "GetStatus", Reason: "gRPC adapter not yet implemented"}
}

// =============================================================================
// Helper Functions
// =============================================================================

// convertStateToProto converts a string state to proto enum.
// TODO: Implement when proto definitions are available
func convertStateToProto(state string) int32 {
	stateMap := map[string]int32{
		StateDiscovered:      1,
		StateBooting:         2,
		StateInstalling:      3,
		StateInstallComplete: 4,
		StateEnrolling:       5,
		StateEnrolled:        6,
		StateAuthorizing:     7,
		StateAuthorized:      8,
		StateFailed:          9,
		StateQuarantined:     10,
	}
	return stateMap[state]
}

// convertProtoToState converts a proto enum to string state.
// TODO: Implement when proto definitions are available
func convertProtoToState(state int32) string {
	stateMap := map[int32]string{
		1:  StateDiscovered,
		2:  StateBooting,
		3:  StateInstalling,
		4:  StateInstallComplete,
		5:  StateEnrolling,
		6:  StateEnrolled,
		7:  StateAuthorizing,
		8:  StateAuthorized,
		9:  StateFailed,
		10: StateQuarantined,
	}
	return stateMap[state]
}

// protoTimeToTime converts proto timestamp to time.Time.
// TODO: Implement when proto definitions are available
func protoTimeToTime(seconds int64) time.Time {
	return time.Unix(seconds, 0)
}

// Ensure GRPCAdapter implements PXECommands interface.
var _ PXECommands = (*GRPCAdapter)(nil)
