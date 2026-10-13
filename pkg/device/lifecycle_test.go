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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

var errEnforcer = errors.New("enforcer failed")

// recordingEnforcer records the calls the lifecycle service makes and moves
// the device to the state the real quarantine manager would.
type recordingEnforcer struct {
	devices    DeviceService
	err        error
	suspended  []string
	readmitted []string
	reason     string
}

func (e *recordingEnforcer) OperatorSuspend(ctx context.Context, deviceID uint64, portID, reason string) (*entities.Device, error) {
	if e.err != nil {
		return nil, e.err
	}
	e.suspended = append(e.suspended, portID)
	e.reason = reason
	return e.move(ctx, deviceID, entities.DeviceStateSuspended)
}

func (e *recordingEnforcer) OperatorReadmit(ctx context.Context, deviceID uint64, portID string) (*entities.Device, error) {
	if e.err != nil {
		return nil, e.err
	}
	e.readmitted = append(e.readmitted, portID)
	return e.move(ctx, deviceID, entities.DeviceStateQuarantined)
}

func (e *recordingEnforcer) move(ctx context.Context, deviceID uint64, state entities.DeviceState) (*entities.Device, error) {
	dev, err := e.devices.Get(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	dev.State = state
	if err := e.devices.Save(ctx, dev); err != nil {
		return nil, err
	}
	return dev, nil
}

type recordingRequester struct {
	err       error
	requested []string
}

func (r *recordingRequester) Refresh(deviceID string) error {
	r.requested = append(r.requested, deviceID)
	return r.err
}

type lifecycleFixture struct {
	devices  *Service
	enforcer *recordingEnforcer
}

func newLifecycleFixture(t *testing.T, devs ...*entities.Device) *lifecycleFixture {
	t.Helper()
	svc, err := NewService(testServiceDatastore(t))
	require.NoError(t, err)
	for _, dev := range devs {
		require.NoError(t, svc.Save(context.Background(), dev))
	}
	return &lifecycleFixture{devices: svc, enforcer: &recordingEnforcer{devices: svc}}
}

func (f *lifecycleFixture) service(t *testing.T, opts ...LifecycleOption) *LifecycleService {
	t.Helper()
	svc, err := NewLifecycleService(f.devices, f.enforcer, opts...)
	require.NoError(t, err)
	return svc
}

func fabricDevice(id uint64, state entities.DeviceState) *entities.Device {
	return &entities.Device{ID: id, Hostname: "node-07", State: state, NetworkPortID: "port-7"}
}

func TestNewLifecycleService_RequiresDependencies(t *testing.T) {
	f := newLifecycleFixture(t)
	var dep ErrLifecycleDependency

	_, err := NewLifecycleService(nil, f.enforcer)
	require.True(t, errors.As(err, &dep))
	assert.Equal(t, "device service", dep.Name)

	_, err = NewLifecycleService(f.devices, nil)
	require.True(t, errors.As(err, &dep))
	assert.Equal(t, "port enforcer", dep.Name)

	svc, err := NewLifecycleService(f.devices, f.enforcer, WithLifecycleLogger(nil))
	require.NoError(t, err)
	assert.NotNil(t, svc.logger, "a nil logger keeps the default")
}

func TestLifecycleService_DisableSuspendsThePort(t *testing.T) {
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateActivated))

	res, err := f.service(t).Disable(context.Background(), 7, "  rma pending  ")
	require.NoError(t, err)

	assert.Equal(t, []string{"port-7"}, f.enforcer.suspended)
	assert.Equal(t, "rma pending", f.enforcer.reason, "the reason is trimmed")
	assert.Equal(t, entities.DeviceStateActivated, res.PreviousState)
	assert.Equal(t, entities.DeviceStateSuspended, res.Device.State)
	assert.False(t, res.ReattestationRequested)
}

func TestLifecycleService_DisableErrors(t *testing.T) {
	ctx := context.Background()
	offFabric := &entities.Device{ID: 8, Hostname: "node-08", State: entities.DeviceStateActivated}
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateActivated), offFabric)
	svc := f.service(t)

	_, err := svc.Disable(ctx, 7, strings.Repeat("x", MaxLifecycleReasonLength+1))
	var tooLong ErrLifecycleReasonTooLong
	require.True(t, errors.As(err, &tooLong))
	assert.Equal(t, MaxLifecycleReasonLength, tooLong.Max)

	_, err = svc.Disable(ctx, 0, "")
	assert.ErrorIs(t, err, ErrInvalidDeviceID)

	_, err = svc.Disable(ctx, 404, "")
	var wrapped *WrappedError
	assert.True(t, errors.As(err, &wrapped), "an unknown device surfaces the device service's error: %v", err)

	_, err = svc.Disable(ctx, 8, "")
	var notOnFabric ErrDeviceNotOnFabric
	require.True(t, errors.As(err, &notOnFabric))
	assert.Equal(t, uint64(8), notOnFabric.DeviceID)

	assert.Empty(t, f.enforcer.suspended, "no rejected call reaches the port")

	f.enforcer.err = errEnforcer
	_, err = svc.Disable(ctx, 7, "")
	assert.ErrorIs(t, err, errEnforcer)
}

func TestLifecycleService_EnableReadmitsAndRequestsReattestation(t *testing.T) {
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateSuspended))
	requester := &recordingRequester{}

	res, err := f.service(t, WithLifecycleReattestation(requester)).Enable(context.Background(), 7)
	require.NoError(t, err)

	assert.Equal(t, []string{"port-7"}, f.enforcer.readmitted)
	assert.Equal(t, []string{"7"}, requester.requested)
	assert.Equal(t, entities.DeviceStateSuspended, res.PreviousState)
	assert.Equal(t, entities.DeviceStateQuarantined, res.Device.State)
	assert.True(t, res.ReattestationRequested)
}

func TestLifecycleService_EnableWithoutACollectorWaitsForTheSchedule(t *testing.T) {
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateSuspended))

	res, err := f.service(t).Enable(context.Background(), 7)
	require.NoError(t, err)
	assert.False(t, res.ReattestationRequested)
	assert.Equal(t, entities.DeviceStateQuarantined, res.Device.State)
}

func TestLifecycleService_EnableSurvivesAFailedReattestationRequest(t *testing.T) {
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateSuspended))
	requester := &recordingRequester{err: errors.New("collector stopped")}

	res, err := f.service(t, WithLifecycleReattestation(requester)).Enable(context.Background(), 7)
	require.NoError(t, err, "the device is already re-admitted; the request failure is logged")
	assert.False(t, res.ReattestationRequested)
	assert.Equal(t, entities.DeviceStateQuarantined, res.Device.State)
}

func TestLifecycleService_EnableErrors(t *testing.T) {
	ctx := context.Background()
	offFabric := &entities.Device{ID: 8, Hostname: "node-08", State: entities.DeviceStateSuspended}
	f := newLifecycleFixture(t, fabricDevice(7, entities.DeviceStateSuspended), offFabric)
	requester := &recordingRequester{}
	svc := f.service(t, WithLifecycleReattestation(requester))

	_, err := svc.Enable(ctx, 0)
	assert.ErrorIs(t, err, ErrInvalidDeviceID)

	_, err = svc.Enable(ctx, 8)
	var notOnFabric ErrDeviceNotOnFabric
	assert.True(t, errors.As(err, &notOnFabric))

	f.enforcer.err = errEnforcer
	_, err = svc.Enable(ctx, 7)
	assert.ErrorIs(t, err, errEnforcer)

	assert.Empty(t, requester.requested, "a refused enable requests no re-attestation")
}

func TestLifecycleErrors_Error(t *testing.T) {
	assert.Contains(t, ErrLifecycleUnenforced{}.Error(), "no SDN policy engine")
	assert.Contains(t, ErrLifecycleDependency{Name: "port enforcer"}.Error(), "port enforcer")
	assert.Contains(t, ErrDeviceNotOnFabric{DeviceID: 9}.Error(), "9")
	assert.Contains(t, ErrLifecycleReasonTooLong{Max: 256}.Error(), "256")
}
