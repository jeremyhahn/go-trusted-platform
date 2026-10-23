// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DeviceLifecycle is the device operation behind DeviceService.DisableDevice
// and EnableDevice on every transport. The single implementation is
// device.LifecycleService; the interface exists so the transports can be
// tested against a stand-in.
type DeviceLifecycle interface {
	Disable(ctx context.Context, deviceID uint64, reason string) (*device.LifecycleResult, error)
	Enable(ctx context.Context, deviceID uint64) (*device.LifecycleResult, error)
}

// WithDeviceLifecycle supplies the operator Enable/Disable flow. Without it
// DisableDevice and EnableDevice answer FailedPrecondition.
func WithDeviceLifecycle(lifecycle DeviceLifecycle) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.lifecycle = lifecycle }
}

// DisableDevice cuts the device's switch port and records it suspended.
func (s *DeviceGRPCService) DisableDevice(ctx context.Context, req *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	if s.lifecycle == nil {
		return nil, status.Error(codes.FailedPrecondition, device.ErrLifecycleUnenforced{}.Error())
	}
	deviceID, err := parseLifecycleDeviceID(req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	res, err := s.lifecycle.Disable(ctx, deviceID, req.GetReason())
	if err != nil {
		return nil, lifecycleErrorToGRPC(err)
	}
	return lifecycleResponse(deviceID, res, "device disabled"), nil
}

// EnableDevice re-admits a disabled device to the quarantine zone pending a
// re-attestation.
func (s *DeviceGRPCService) EnableDevice(ctx context.Context, req *platformv1.EnableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	if s.lifecycle == nil {
		return nil, status.Error(codes.FailedPrecondition, device.ErrLifecycleUnenforced{}.Error())
	}
	deviceID, err := parseLifecycleDeviceID(req.GetDeviceId())
	if err != nil {
		return nil, err
	}
	res, err := s.lifecycle.Enable(ctx, deviceID)
	if err != nil {
		return nil, lifecycleErrorToGRPC(err)
	}
	return lifecycleResponse(deviceID, res, "device re-enabled into quarantine pending re-attestation"), nil
}

// parseLifecycleDeviceID parses the decimal device ID every transport sends.
func parseLifecycleDeviceID(raw string) (uint64, error) {
	if raw == "" {
		return 0, status.Error(codes.InvalidArgument, "device_id is required")
	}
	deviceID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || deviceID == 0 {
		return 0, status.Error(codes.InvalidArgument, "invalid device ID")
	}
	return deviceID, nil
}

func lifecycleResponse(deviceID uint64, res *device.LifecycleResult, message string) *platformv1.DeviceLifecycleResponse {
	resp := &platformv1.DeviceLifecycleResponse{
		Status:                 &platformv1.Status{Success: true, Message: message},
		DeviceId:               deviceID,
		PreviousState:          res.PreviousState.String(),
		ReattestationRequested: res.ReattestationRequested,
	}
	if res.Device != nil {
		resp.State = res.Device.State.String()
		resp.StateReason = res.Device.StateReason
	}
	return resp
}

// lifecycleErrorToGRPC maps the lifecycle flow's typed errors onto gRPC
// codes. A device whose state or wiring does not permit the transition is
// FailedPrecondition: the request was well formed and the device exists.
func lifecycleErrorToGRPC(err error) error {
	var (
		tooLong      device.ErrLifecycleReasonTooLong
		notOnFabric  device.ErrDeviceNotOnFabric
		transition   entities.ErrInvalidTransition
		notSuspended policy.ErrDeviceNotSuspended
		noZone       policy.ErrNoQuarantineZone
		noPort       policy.ErrUnknownDevicePort
	)
	switch {
	case errors.Is(err, device.ErrInvalidDeviceID), errors.As(err, &tooLong):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &notOnFabric), errors.As(err, &transition), errors.As(err, &notSuspended),
		errors.As(err, &noZone), errors.As(err, &noPort):
		return status.Error(codes.FailedPrecondition, err.Error())
	case containsNotFound(err.Error()):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// deviceLifecycleForMCP runs an MCP device_disable or device_enable call
// through the gRPC method, so argument validation, error codes and the
// response shape are the ones every other transport uses.
func deviceLifecycleForMCP(ctx context.Context, lifecycle DeviceLifecycle, deviceID, reason string, enable bool, logger *slog.Logger) (interface{}, error) {
	svc := &DeviceGRPCService{lifecycle: lifecycle, logger: logger}
	if svc.logger == nil {
		svc.logger = slog.Default()
	}
	var (
		resp *platformv1.DeviceLifecycleResponse
		err  error
	)
	if enable {
		resp, err = svc.EnableDevice(ctx, &platformv1.EnableDeviceRequest{DeviceId: deviceID})
	} else {
		resp, err = svc.DisableDevice(ctx, &platformv1.DisableDeviceRequest{DeviceId: deviceID, Reason: reason})
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}
