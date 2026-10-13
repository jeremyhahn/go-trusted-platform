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
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// stubDeviceLifecycle records the calls the transports make and answers
// with a fixed result or error.
type stubDeviceLifecycle struct {
	disabled []uint64
	enabled  []uint64
	reason   string
	result   *device.LifecycleResult
	err      error
}

func (s *stubDeviceLifecycle) Disable(_ context.Context, deviceID uint64, reason string) (*device.LifecycleResult, error) {
	s.disabled = append(s.disabled, deviceID)
	s.reason = reason
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func (s *stubDeviceLifecycle) Enable(_ context.Context, deviceID uint64) (*device.LifecycleResult, error) {
	s.enabled = append(s.enabled, deviceID)
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func suspendedResult() *device.LifecycleResult {
	return &device.LifecycleResult{
		Device: &entities.Device{
			ID:          42,
			State:       entities.DeviceStateSuspended,
			StateReason: "operator: rma pending",
		},
		PreviousState: entities.DeviceStateActivated,
	}
}

func TestDeviceGRPCService_DisableDevice(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: suspendedResult()}
	svc := NewDeviceGRPCService(nil, nil, nil, WithDeviceLifecycle(lifecycle))

	resp, err := svc.DisableDevice(context.Background(), &platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"})
	require.NoError(t, err)

	assert.Equal(t, []uint64{42}, lifecycle.disabled)
	assert.Equal(t, "rma pending", lifecycle.reason)
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, uint64(42), resp.GetDeviceId())
	assert.Equal(t, entities.DeviceStateSuspended.String(), resp.GetState())
	assert.Equal(t, entities.DeviceStateActivated.String(), resp.GetPreviousState())
	assert.Equal(t, "operator: rma pending", resp.GetStateReason())
	assert.False(t, resp.GetReattestationRequested())
}

func TestDeviceGRPCService_EnableDevice(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: &device.LifecycleResult{
		Device:                 &entities.Device{ID: 42, State: entities.DeviceStateQuarantined},
		PreviousState:          entities.DeviceStateSuspended,
		ReattestationRequested: true,
	}}
	svc := NewDeviceGRPCService(nil, nil, nil, WithDeviceLifecycle(lifecycle))

	resp, err := svc.EnableDevice(context.Background(), &platformv1.EnableDeviceRequest{DeviceId: "42"})
	require.NoError(t, err)

	assert.Equal(t, []uint64{42}, lifecycle.enabled)
	assert.Equal(t, entities.DeviceStateQuarantined.String(), resp.GetState())
	assert.Equal(t, entities.DeviceStateSuspended.String(), resp.GetPreviousState())
	assert.True(t, resp.GetReattestationRequested())
}

func TestDeviceGRPCService_LifecycleWithoutEnforcement(t *testing.T) {
	svc := NewDeviceGRPCService(nil, nil, nil)

	_, err := svc.DisableDevice(context.Background(), &platformv1.DisableDeviceRequest{DeviceId: "42"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	_, err = svc.EnableDevice(context.Background(), &platformv1.EnableDeviceRequest{DeviceId: "42"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestDeviceGRPCService_LifecycleRejectsBadIDs(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: suspendedResult()}
	svc := NewDeviceGRPCService(nil, nil, nil, WithDeviceLifecycle(lifecycle))

	for _, id := range []string{"", "0", "abc", "-1"} {
		_, err := svc.DisableDevice(context.Background(), &platformv1.DisableDeviceRequest{DeviceId: id})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "disable %q", id)

		_, err = svc.EnableDevice(context.Background(), &platformv1.EnableDeviceRequest{DeviceId: id})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "enable %q", id)
	}
	assert.Empty(t, lifecycle.disabled, "a bad id never reaches the lifecycle")
	assert.Empty(t, lifecycle.enabled)
}

func TestLifecycleErrorToGRPC(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"invalid id", fmt.Errorf("wrap: %w", device.ErrInvalidDeviceID), codes.InvalidArgument},
		{"reason too long", device.ErrLifecycleReasonTooLong{Max: 256}, codes.InvalidArgument},
		{"not on fabric", device.ErrDeviceNotOnFabric{DeviceID: 42}, codes.FailedPrecondition},
		{"invalid transition", entities.ErrInvalidTransition{From: entities.DeviceStateRevoked, To: entities.DeviceStateSuspended}, codes.FailedPrecondition},
		{"not suspended", policy.ErrDeviceNotSuspended{DeviceID: 42, State: entities.DeviceStateActivated}, codes.FailedPrecondition},
		{"no quarantine zone", policy.ErrNoQuarantineZone{}, codes.FailedPrecondition},
		{"unknown port", policy.ErrUnknownDevicePort{DeviceID: 42}, codes.FailedPrecondition},
		{"not found", errors.New("device 42 not found"), codes.NotFound},
		{"other", errors.New("store down"), codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lifecycle := &stubDeviceLifecycle{err: tc.err}
			svc := NewDeviceGRPCService(nil, nil, nil, WithDeviceLifecycle(lifecycle))

			_, err := svc.DisableDevice(context.Background(), &platformv1.DisableDeviceRequest{DeviceId: "42"})
			assert.Equal(t, tc.want, status.Code(err), "disable: %v", err)

			_, err = svc.EnableDevice(context.Background(), &platformv1.EnableDeviceRequest{DeviceId: "42"})
			assert.Equal(t, tc.want, status.Code(err), "enable: %v", err)
		})
	}
}

func newQUICLifecycleHandler(t *testing.T, lifecycle DeviceLifecycle) *QUICServiceHandler {
	t.Helper()
	handler := newTestQUICServiceHandler(
		logging.DefaultLogger(),
		WithQUICDeviceService(newMockDeviceService()),
		WithQUICDeviceProfileService(newMockProfileService()),
	)
	handler.SetDeviceLifecycle(lifecycle)
	return handler
}

func TestQUICDeviceDisable(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: suspendedResult()}
	handler := newQUICLifecycleHandler(t, lifecycle)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubDisable,
		&platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"})
	resp := handler.HandleRequest(context.Background(), req)

	var out platformv1.DeviceLifecycleResponse
	decodeQUICResponse(t, resp, &out)
	assert.Equal(t, uint64(42), out.GetDeviceId())
	assert.Equal(t, entities.DeviceStateSuspended.String(), out.GetState())
	assert.Equal(t, "rma pending", lifecycle.reason)
}

func TestQUICDeviceEnable(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: &device.LifecycleResult{
		Device:                 &entities.Device{ID: 42, State: entities.DeviceStateQuarantined},
		PreviousState:          entities.DeviceStateSuspended,
		ReattestationRequested: true,
	}}
	handler := newQUICLifecycleHandler(t, lifecycle)

	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubEnable,
		&platformv1.EnableDeviceRequest{DeviceId: "42"})
	resp := handler.HandleRequest(context.Background(), req)

	var out platformv1.DeviceLifecycleResponse
	decodeQUICResponse(t, resp, &out)
	assert.Equal(t, entities.DeviceStateQuarantined.String(), out.GetState())
	assert.True(t, out.GetReattestationRequested())
	assert.Equal(t, []uint64{42}, lifecycle.enabled)
}

func TestQUICDeviceLifecycle_Errors(t *testing.T) {
	refused := newQUICLifecycleHandler(t, &stubDeviceLifecycle{err: policy.ErrDeviceNotSuspended{DeviceID: 42}})
	req := encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubEnable,
		&platformv1.EnableDeviceRequest{DeviceId: "42"})
	assert.Equal(t, quicwire.StatusInvalidRequest, refused.HandleRequest(context.Background(), req).Status,
		"FailedPrecondition maps to the QUIC invalid-request status")

	missing := newQUICLifecycleHandler(t, &stubDeviceLifecycle{err: errors.New("device 42 not found")})
	req = encodeQUICCategoryRequest(t, quicwire.OpProvisioningCategory, quicwire.DeviceSubDisable,
		&platformv1.DisableDeviceRequest{DeviceId: "42"})
	assert.Equal(t, quicwire.StatusNotFound, missing.HandleRequest(context.Background(), req).Status)

	for _, sub := range []byte{quicwire.DeviceSubDisable, quicwire.DeviceSubEnable} {
		resp := refused.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpProvisioningCategory,
			Payload: []byte{sub, 0xff, 0xfe, 0xfd},
		})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status, "malformed payload for sub-opcode %#x", sub)
	}
}

func TestDeviceLifecycleForMCP(t *testing.T) {
	lifecycle := &stubDeviceLifecycle{result: suspendedResult()}

	out, err := deviceLifecycleForMCP(context.Background(), lifecycle, "42", "rma pending", false, nil)
	require.NoError(t, err)
	resp, ok := out.(*platformv1.DeviceLifecycleResponse)
	require.True(t, ok)
	assert.Equal(t, uint64(42), resp.GetDeviceId())
	assert.Equal(t, []uint64{42}, lifecycle.disabled)

	_, err = deviceLifecycleForMCP(context.Background(), lifecycle, "42", "", true, nil)
	require.NoError(t, err)
	assert.Equal(t, []uint64{42}, lifecycle.enabled)
}

// lifecycleProvider is the MCP surface both service providers implement.
type lifecycleProvider interface {
	DeviceDisable(ctx context.Context, deviceID, reason string) (interface{}, error)
	DeviceEnable(ctx context.Context, deviceID string) (interface{}, error)
}

func lifecycleProviders(lifecycle DeviceLifecycle) map[string]lifecycleProvider {
	return map[string]lifecycleProvider{
		"mcp": NewMCPServiceProvider(&MCPServiceProviderConfig{
			DeviceService:   newMockDeviceService(),
			DeviceLifecycle: lifecycle,
			Logger:          slog.Default(),
		}),
		"platform": NewPlatformServiceProvider(&PlatformServiceProviderConfig{
			DeviceService:   newMockDeviceService(),
			ProfileService:  newMockProfileService(),
			DeviceLifecycle: lifecycle,
		}),
	}
}

func TestServiceProviders_DeviceLifecycle(t *testing.T) {
	for name, provider := range lifecycleProviders(&stubDeviceLifecycle{result: suspendedResult()}) {
		t.Run(name, func(t *testing.T) {
			out, err := provider.DeviceDisable(context.Background(), "42", "rma pending")
			require.NoError(t, err)
			assert.Equal(t, entities.DeviceStateSuspended.String(), out.(*platformv1.DeviceLifecycleResponse).GetState())

			_, err = provider.DeviceEnable(context.Background(), "42")
			require.NoError(t, err)
		})
	}
}

func TestServiceProviders_DeviceLifecycleUnenforced(t *testing.T) {
	for name, provider := range lifecycleProviders(nil) {
		t.Run(name, func(t *testing.T) {
			_, err := provider.DeviceDisable(context.Background(), "42", "")
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))

			_, err = provider.DeviceEnable(context.Background(), "42")
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		})
	}
}

func TestDeviceLifecycleForMCP_Errors(t *testing.T) {
	out, err := deviceLifecycleForMCP(context.Background(), nil, "42", "", false, nil)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Nil(t, out, "a refusal returns an untyped nil, not a nil *DeviceLifecycleResponse")

	_, err = deviceLifecycleForMCP(context.Background(), &stubDeviceLifecycle{}, "x", "", true, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
