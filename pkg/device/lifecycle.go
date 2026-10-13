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

package device

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// MaxLifecycleReasonLength bounds the operator's disable reason, which is
// stored on the device record as its state reason.
const MaxLifecycleReasonLength = 256

// PortEnforcer is the SDN half of an operator Enable/Disable: it cuts or
// re-admits the device's switch port and records the resulting state.
// policy.QuarantineManager implements it.
type PortEnforcer interface {
	// OperatorSuspend blocks the port and records the device suspended.
	OperatorSuspend(ctx context.Context, deviceID uint64, portID, reason string) (*entities.Device, error)
	// OperatorReadmit unblocks the port into the quarantine zone and
	// records the device quarantined, pending re-attestation.
	OperatorReadmit(ctx context.Context, deviceID uint64, portID string) (*entities.Device, error)
}

// ReattestationRequester asks the attestation collector to quote a device
// now instead of at its next scheduled cycle. reporting.Collector implements
// it; the device ID is the decimal device ID.
type ReattestationRequester interface {
	Refresh(deviceID string) error
}

// LifecycleResult is the outcome of an operator Enable or Disable.
type LifecycleResult struct {
	// Device is the device record as saved.
	Device *entities.Device
	// PreviousState is the state the device held before the call.
	PreviousState entities.DeviceState
	// ReattestationRequested reports whether an Enable queued a
	// re-attestation. When false the device is re-attested on the
	// collector's next scheduled cycle, or never if no collector runs.
	ReattestationRequested bool
}

// LifecycleOption configures a LifecycleService.
type LifecycleOption func(*LifecycleService)

// WithLifecycleReattestation supplies the collector an Enable asks for an
// immediate re-attestation. Without it the device waits for the collector's
// scheduled cycle.
func WithLifecycleReattestation(requester ReattestationRequester) LifecycleOption {
	return func(s *LifecycleService) { s.reattest = requester }
}

// WithLifecycleLogger supplies the logger.
func WithLifecycleLogger(logger *slog.Logger) LifecycleOption {
	return func(s *LifecycleService) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// LifecycleService is the operator Enable/Disable Device flow (issue #250).
//
// Disable cuts the device's switch port and records it suspended. Enable
// never vouches for the device: it re-admits the port to the quarantine zone,
// records the device quarantined and asks for a re-attestation; only a
// passing verdict restores the device's recorded placement and state. Both
// refuse a device that has no switch port rather than record a state nothing
// enforces.
type LifecycleService struct {
	devices  DeviceService
	enforcer PortEnforcer
	reattest ReattestationRequester
	logger   *slog.Logger
}

// NewLifecycleService constructs the service over the device service and the
// SDN port enforcer. Both are required.
func NewLifecycleService(devices DeviceService, enforcer PortEnforcer, opts ...LifecycleOption) (*LifecycleService, error) {
	if devices == nil {
		return nil, ErrLifecycleDependency{Name: "device service"}
	}
	if enforcer == nil {
		return nil, ErrLifecycleDependency{Name: "port enforcer"}
	}
	s := &LifecycleService{devices: devices, enforcer: enforcer, logger: slog.Default()}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Disable cuts the device's network and records it suspended, with reason
// stored as its state reason.
func (s *LifecycleService) Disable(ctx context.Context, id uint64, reason string) (*LifecycleResult, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > MaxLifecycleReasonLength {
		return nil, ErrLifecycleReasonTooLong{Max: MaxLifecycleReasonLength}
	}
	dev, err := s.onFabric(ctx, id)
	if err != nil {
		return nil, err
	}
	updated, err := s.enforcer.OperatorSuspend(ctx, id, dev.NetworkPortID, reason)
	if err != nil {
		return nil, err
	}
	s.logger.Info("device disabled by operator",
		slog.Uint64("device_id", id),
		slog.String("previous_state", dev.State.String()),
		slog.String("reason", reason))
	return &LifecycleResult{Device: updated, PreviousState: dev.State}, nil
}

// Enable re-admits a disabled device to the quarantine zone and requests a
// re-attestation. The device stays quarantined until a verdict passes.
func (s *LifecycleService) Enable(ctx context.Context, id uint64) (*LifecycleResult, error) {
	dev, err := s.onFabric(ctx, id)
	if err != nil {
		return nil, err
	}
	updated, err := s.enforcer.OperatorReadmit(ctx, id, dev.NetworkPortID)
	if err != nil {
		return nil, err
	}
	requested := s.requestReattestation(id)
	s.logger.Info("device re-enabled by operator into quarantine",
		slog.Uint64("device_id", id),
		slog.Bool("reattestation_requested", requested))
	return &LifecycleResult{Device: updated, PreviousState: dev.State, ReattestationRequested: requested}, nil
}

// onFabric loads the device and confirms it has a switch port to enforce.
func (s *LifecycleService) onFabric(ctx context.Context, id uint64) (*entities.Device, error) {
	if id == 0 {
		return nil, ErrInvalidDeviceID
	}
	dev, err := s.devices.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if dev.NetworkPortID == "" {
		return nil, ErrDeviceNotOnFabric{DeviceID: id}
	}
	return dev, nil
}

// requestReattestation queues an immediate re-attestation. A failure is
// logged, not returned: the device is already re-admitted to quarantine and
// the collector's scheduled cycle re-attests it.
func (s *LifecycleService) requestReattestation(id uint64) bool {
	if s.reattest == nil {
		return false
	}
	if err := s.reattest.Refresh(strconv.FormatUint(id, 10)); err != nil {
		s.logger.Warn("re-enabled device: re-attestation request failed; the scheduled cycle will re-attest it",
			slog.Uint64("device_id", id),
			slog.String("error", err.Error()))
		return false
	}
	return true
}
