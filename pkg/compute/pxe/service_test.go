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

package pxe

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEventHandler implements EventHandler for testing
type testEventHandler struct {
	events []*ProvisioningEvent
	mu     sync.Mutex

	// delivered signals each event so a test can wait for the dispatch
	// goroutine instead of sleeping (#262).
	delivered *eventSignal
}

func (h *testEventHandler) OnEvent(ctx context.Context, event *ProvisioningEvent) {
	h.mu.Lock()
	h.events = append(h.events, event)
	sig := h.delivered
	h.mu.Unlock()

	if sig != nil {
		sig.fire()
	}
}

func (h *testEventHandler) getEvents() []*ProvisioningEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.events
}

// createTestConfig creates a valid test configuration
func createTestConfig() *ServiceConfig {
	cfg := testServiceConfig()
	cfg.BridgeName = "br-test"
	// IPXEConfig is set but we won't use the real iPXE server in tests
	return cfg
}

// initializeTestService creates and initializes a test service with
// direct manipulation to avoid network operations
func initializeTestService(t *testing.T) (Service, *ServiceConfig) {
	t.Helper()
	cfg := createTestConfig()

	logger := logging.DefaultLogger()
	stateManager := NewStateManager()

	// Create the service with components injected
	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		vlanManager:  NewNoopVLANIntegration(testNetPlan),
		config:       cfg,
	}
	svc.initialized.Store(true)

	return svc, cfg
}

func TestNewService_DefaultOptions(t *testing.T) {
	svc := NewService()

	assert.NotNil(t, svc)
	assert.False(t, svc.IsRunning())
}

func TestNewService_WithLogger(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewService(WithLogger(logger))

	assert.NotNil(t, svc)
}

func TestNewService_WithStateManager(t *testing.T) {
	sm := NewStateManager()
	svc := NewService(WithStateManager(sm))

	assert.NotNil(t, svc)
}

func TestNewService_WithVLANIntegration(t *testing.T) {
	vi := NewNoopVLANIntegration(testNetPlan)
	svc := NewService(WithVLANIntegration(vi))

	assert.NotNil(t, svc)
}

func TestNewService_WithAllOptions(t *testing.T) {
	logger := logging.DefaultLogger()
	sm := NewStateManager()
	vi := NewNoopVLANIntegration(testNetPlan)

	svc := NewService(
		WithLogger(logger),
		WithStateManager(sm),
		WithVLANIntegration(vi),
	)
	assert.NotNil(t, svc)
	assert.False(t, svc.IsRunning())
}

func TestNewService_WithIPXEServer(t *testing.T) {
	// Test the WithIPXEServer option
	svc := NewService(
		WithIPXEServer(nil), // nil is acceptable for the option
	)
	assert.NotNil(t, svc)
}

func TestService_Initialize_NilConfig(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.Initialize(ctx, nil)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestService_Initialize_InvalidConfig(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	cfg := testServiceConfig()
	cfg.BridgeName = "" // Invalid - required

	err := svc.Initialize(ctx, cfg)
	assert.Error(t, err)

	var configErr ErrInvalidConfiguration
	assert.True(t, errors.As(err, &configErr))
}

func TestService_Initialize_AlreadyInitialized(t *testing.T) {
	svc, cfg := initializeTestService(t)
	ctx := context.Background()

	err := svc.Initialize(ctx, cfg)
	assert.Error(t, err)

	var runningErr ErrServiceAlreadyRunning
	assert.True(t, errors.As(err, &runningErr))
}

func TestService_Start_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.Start(ctx)
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_Start_AlreadyRunning(t *testing.T) {
	cfg := createTestConfig()
	logger := logging.DefaultLogger()
	stateManager := NewStateManager()

	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		vlanManager:  NewNoopVLANIntegration(testNetPlan),
		config:       cfg,
	}
	svc.initialized.Store(true)
	svc.running.Store(true)

	ctx := context.Background()
	err := svc.Start(ctx)
	assert.Error(t, err)

	var runningErr ErrServiceAlreadyRunning
	assert.True(t, errors.As(err, &runningErr))
}

func TestService_Stop_NotRunning(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.Stop(ctx)
	assert.Error(t, err)

	var notRunningErr ErrServiceNotRunning
	assert.True(t, errors.As(err, &notRunningErr))
}

func TestService_IsRunning(t *testing.T) {
	svc := NewService()

	assert.False(t, svc.IsRunning())
}

func TestService_RegisterDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_RegisterDevice_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	assert.NoError(t, err)
	assert.NotNil(t, device)
	assert.Equal(t, StateDiscovered, device.State)
	assert.Equal(t, "port-1", device.PortID)
	assert.NotEmpty(t, device.ID)
}

func TestService_RegisterDevice_InvalidMAC(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "invalid-mac", "port-1")
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestService_RegisterDevice_Duplicate(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	_, err = svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-2")
	assert.Error(t, err)

	var existsErr ErrDeviceAlreadyExists
	assert.True(t, errors.As(err, &existsErr))
}

func TestService_GetDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	_, err := svc.GetDevice(ctx, "device-123")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_GetDevice_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	registered, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, registered.ID)
	assert.NoError(t, err)
	assert.Equal(t, registered.ID, retrieved.ID)
}

func TestService_GetDevice_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.GetDevice(ctx, "nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_GetDeviceByMAC_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	_, err := svc.GetDeviceByMAC(ctx, "00:11:22:33:44:55")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_GetDeviceByMAC_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	retrieved, err := svc.GetDeviceByMAC(ctx, "00:11:22:33:44:55")
	assert.NoError(t, err)
	assert.Equal(t, "00:11:22:33:44:55", retrieved.MACAddress.String())
}

func TestService_GetDeviceByMAC_InvalidMAC(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.GetDeviceByMAC(ctx, "invalid-mac")
	assert.Error(t, err)

	var macErr ErrInvalidMACAddress
	assert.True(t, errors.As(err, &macErr))
}

func TestService_GetDeviceByMAC_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.GetDeviceByMAC(ctx, "00:11:22:33:44:55")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_ListDevices_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	_, err := svc.ListDevices(ctx, nil)
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_ListDevices_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	_, err = svc.RegisterDevice(ctx, "00:11:22:33:44:66", "port-2")
	require.NoError(t, err)

	devices, err := svc.ListDevices(ctx, nil)
	assert.NoError(t, err)
	assert.Len(t, devices, 2)
}

func TestService_ListDevices_WithFilter(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	devices, err := svc.ListDevices(ctx, &DeviceFilter{State: StateDiscovered})
	assert.NoError(t, err)
	assert.Len(t, devices, 1)

	devices, err = svc.ListDevices(ctx, &DeviceFilter{State: StateBooting})
	assert.NoError(t, err)
	assert.Len(t, devices, 0)
}

func TestService_RemoveDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.RemoveDevice(ctx, "device-123")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_RemoveDevice_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.RemoveDevice(ctx, device.ID)
	assert.NoError(t, err)

	_, err = svc.GetDevice(ctx, device.ID)
	assert.Error(t, err)
}

func TestService_RemoveDevice_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.RemoveDevice(ctx, "nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_UpdateDeviceState_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.UpdateDeviceState(ctx, "device-123", StateBooting, "test")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_UpdateDeviceState_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "test transition")
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateBooting, retrieved.State)
}

func TestService_UpdateDeviceState_InvalidState(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.UpdateDeviceState(ctx, device.ID, ProvisioningState("invalid"), "test")
	assert.Error(t, err)

	var invalidErr ErrInvalidState
	assert.True(t, errors.As(err, &invalidErr))
}

func TestService_UpdateDeviceState_InvalidTransition(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Try to skip from discovered to authorized
	err = svc.UpdateDeviceState(ctx, device.ID, StateAuthorized, "test")
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

func TestService_UpdateDeviceState_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.UpdateDeviceState(ctx, "nonexistent", StateBooting, "test")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_SetDeviceEnrolled_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.SetDeviceEnrolled(ctx, "device-123", "serial-123")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_SetDeviceEnrolled_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Progress device to enrolling state
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstalling, "installing")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolling, "enrolling")
	require.NoError(t, err)

	err = svc.SetDeviceEnrolled(ctx, device.ID, "serial-123")
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateEnrolled, retrieved.State)
	assert.Equal(t, "serial-123", retrieved.CertificateSerial)
}

func TestService_SetDeviceEnrolled_InvalidTransition(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Device is in discovered state, cannot go to enrolled
	err = svc.SetDeviceEnrolled(ctx, device.ID, "serial-123")
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

// TestService_RecordIDevIDFingerprint pins ruling 673 (per ruling 70): the
// IDevID fingerprint is stored at enrolment, before install completion, so
// it is accepted while the device boots and installs, leaves the state
// alone, and is refused once the install is complete.
func TestService_RecordIDevIDFingerprint(t *testing.T) {
	const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const otherFP = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	ctx := context.Background()

	// advance moves a fresh device through the given states in order.
	advance := func(t *testing.T, svc Service, id string, states ...ProvisioningState) {
		t.Helper()
		for _, st := range states {
			require.NoError(t, svc.UpdateDeviceState(ctx, id, st, string(st)))
		}
	}

	for name, path := range map[string][]ProvisioningState{
		"discovered": nil,
		"booting":    {StateBooting},
		"installing": {StateBooting, StateInstalling},
	} {
		t.Run("accepted while "+name, func(t *testing.T) {
			svc, _ := initializeTestService(t)
			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)
			advance(t, svc, device.ID, path...)
			before, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)

			require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fp))

			got, err := svc.GetDeviceByMAC(ctx, "00:11:22:33:44:55")
			require.NoError(t, err)
			assert.Equal(t, fp, got.IDevIDFingerprint)
			assert.Equal(t, before.State, got.State, "recording the fingerprint changed the state")
		})
	}

	for name, path := range map[string][]ProvisioningState{
		"install_complete": {StateBooting, StateInstalling, StateInstallComplete},
		"enrolling":        {StateBooting, StateInstalling, StateInstallComplete, StateEnrolling},
	} {
		t.Run("refused once "+name, func(t *testing.T) {
			svc, _ := initializeTestService(t)
			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)
			advance(t, svc, device.ID, path...)

			err = svc.RecordIDevIDFingerprint(ctx, device.ID, fp)
			var transitionErr ErrInvalidStateTransition
			assert.True(t, errors.As(err, &transitionErr), "got %v", err)

			got, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Empty(t, got.IDevIDFingerprint)
		})
	}

	t.Run("refuses a value that is not a SHA-256 hex digest", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
		require.NoError(t, err)
		for _, bad := range []string{"", "abc", fp[:63], fp + "0", "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"} {
			assert.Error(t, svc.RecordIDevIDFingerprint(ctx, device.ID, bad), "accepted %q", bad)
		}
		got, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		assert.Empty(t, got.IDevIDFingerprint)
	})

	t.Run("a re-enrolment before install completion replaces the fingerprint", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
		require.NoError(t, err)
		require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fp))

		assert.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fp), "re-recording the same fingerprint is a no-op")
		assert.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, otherFP), "a re-enrolment in discovered is refused")

		got, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		assert.Equal(t, otherFP, got.IDevIDFingerprint)
	})

	t.Run("needs an initialized service", func(t *testing.T) {
		err := NewService().RecordIDevIDFingerprint(ctx, "device-123", fp)
		var notInitErr ErrServiceNotInitialized
		assert.True(t, errors.As(err, &notInitErr))
	})

	t.Run("unknown device", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		err := svc.RecordIDevIDFingerprint(ctx, "nonexistent", fp)
		var notFoundErr ErrDeviceNotFound
		assert.True(t, errors.As(err, &notFoundErr))
	})
}

// TestService_RecordIDevIDFingerprint_ReEnrolmentWhileInstallingReplaces:
// the finalize hook records the fingerprint before the CA commits the
// certificate, so a delivery failure is followed by a re-enrolment that
// issues a different IDevID. While the device is still installing (it has
// not reported any certificate in use) the later fingerprint replaces the
// earlier one; once the device is past installing it is fixed.
func TestService_RecordIDevIDFingerprint_ReEnrolmentWhileInstallingReplaces(t *testing.T) {
	const fpA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const fpB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	paths := map[ProvisioningState][]ProvisioningState{
		StateDiscovered: nil,
		StateBooting:    {StateBooting},
		StateInstalling: {StateBooting, StateInstalling},
	}
	for _, want := range []ProvisioningState{StateDiscovered, StateBooting, StateInstalling} {
		t.Run(string(want), func(t *testing.T) {
			svc, _ := initializeTestService(t)
			ctx := context.Background()

			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)
			for _, st := range paths[want] {
				require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, st, string(st)))
			}

			require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fpA))
			require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fpB), "a re-enrolment in %s is refused", want)
			got, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, fpB, got.IDevIDFingerprint)
			assert.Equal(t, want, got.State)

			if want != StateInstalling {
				for _, st := range []ProvisioningState{StateBooting, StateInstalling} {
					if st == want {
						continue
					}
					require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, st, string(st)))
				}
			}
			require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete"))
			assert.Error(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fpA), "a re-enrolment past install completion is accepted")
			got, err = svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, fpB, got.IDevIDFingerprint)
		})
	}
}

func TestService_AuthorizeDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.AuthorizeDevice(ctx, "device-123", 100)
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_AuthorizeDevice_InvalidVLAN(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.AuthorizeDevice(ctx, device.ID, 0)
	assert.Error(t, err)

	var vlanErr ErrVLANTransitionFailed
	assert.True(t, errors.As(err, &vlanErr))
}

func TestService_AuthorizeDevice_InvalidVLANRange(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.AuthorizeDevice(ctx, device.ID, 4095)
	assert.Error(t, err)

	var vlanErr ErrVLANTransitionFailed
	assert.True(t, errors.As(err, &vlanErr))
}

func TestService_AuthorizeDevice_InvalidTransition(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Device is in discovered state, cannot go to authorized
	err = svc.AuthorizeDevice(ctx, device.ID, testControlPlaneVLAN)
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

func TestService_AuthorizeDevice_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Progress device to authorizing state
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstalling, "installing")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolling, "enrolling")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolled, "enrolled")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateAuthorizing, "authorizing")
	require.NoError(t, err)

	err = svc.AuthorizeDevice(ctx, device.ID, testControlPlaneVLAN)
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateAuthorized, retrieved.State)
}

func TestService_QuarantineDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.QuarantineDevice(ctx, "device-123", "security violation")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_QuarantineDevice_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.QuarantineDevice(ctx, device.ID, "security violation")
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateQuarantined, retrieved.State)
}

func TestService_GetEvents_ListsAQuarantine(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	require.NoError(t, svc.QuarantineDevice(ctx, device.ID, "security violation"))

	events, err := svc.GetEvents(ctx, device.ID)
	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, EventDeviceDiscovered, events[0].EventType)
	assert.Equal(t, EventQuarantined, events[1].EventType)
	assert.Equal(t, StateQuarantined, events[1].ToState)
	assert.Equal(t, "security violation", events[1].Details["reason"])
}

func TestService_QuarantineDevice_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.QuarantineDevice(ctx, "nonexistent", "test")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_RetryDevice_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	err := svc.RetryDevice(ctx, "device-123")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_RetryDevice_Valid(t *testing.T) {
	svc, cfg := initializeTestService(t)
	ctx := context.Background()

	// Set max retries for this test
	cfg.MaxRetries = DefaultMaxRetries

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Put device in failed state
	err = svc.UpdateDeviceState(ctx, device.ID, StateFailed, "test failure")
	require.NoError(t, err)

	err = svc.RetryDevice(ctx, device.ID)
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateDiscovered, retrieved.State)
	assert.Equal(t, 1, retrieved.RetryCount)
}

// TestService_RetryDevice_ReEnrolmentRecordsTheNewIDevID: a retry is a new
// provisioning attempt, so the IDevID the retried install enrols is recorded
// even though the failed attempt recorded a different one.
func TestService_RetryDevice_ReEnrolmentRecordsTheNewIDevID(t *testing.T) {
	const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const otherFP = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	svc, cfg := initializeTestService(t)
	ctx := context.Background()
	cfg.MaxRetries = DefaultMaxRetries

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	for _, st := range []ProvisioningState{StateBooting, StateInstalling} {
		require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, st, string(st)))
	}
	require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fp))
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateFailed, "install failed"))

	require.NoError(t, svc.RetryDevice(ctx, device.ID))
	retried, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateDiscovered, retried.State)
	assert.Empty(t, retried.IDevIDFingerprint, "a retry keeps the previous attempt's fingerprint")

	for _, st := range []ProvisioningState{StateBooting, StateInstalling} {
		require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, st, string(st)))
	}
	require.NoError(t, svc.RecordIDevIDFingerprint(ctx, device.ID, otherFP))
	got, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, otherFP, got.IDevIDFingerprint)

	// Within the same attempt a different fingerprint is refused once the
	// install is complete (a re-enrolment while installing replaces it, see
	// TestService_RecordIDevIDFingerprint_ReEnrolmentWhileInstallingReplaces).
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete"))
	assert.Error(t, svc.RecordIDevIDFingerprint(ctx, device.ID, fp))
}

func TestService_RetryDevice_MaxRetriesExceeded(t *testing.T) {
	cfg := createTestConfig()
	cfg.MaxRetries = 2
	ctx := context.Background()

	logger := logging.DefaultLogger()
	stateManager := NewStateManager()
	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		vlanManager:  NewNoopVLANIntegration(testNetPlan),
		config:       cfg,
	}
	svc.initialized.Store(true)

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Put device in failed state and retry multiple times
	for i := 0; i < cfg.MaxRetries; i++ {
		err = svc.UpdateDeviceState(ctx, device.ID, StateFailed, "test failure")
		require.NoError(t, err)
		err = svc.RetryDevice(ctx, device.ID)
		require.NoError(t, err)
	}

	// One more failure
	err = svc.UpdateDeviceState(ctx, device.ID, StateFailed, "test failure")
	require.NoError(t, err)

	// This should fail - max retries exceeded
	err = svc.RetryDevice(ctx, device.ID)
	assert.Error(t, err)

	var maxRetriesErr ErrMaxRetriesExceeded
	assert.True(t, errors.As(err, &maxRetriesErr))
}

func TestService_RetryDevice_InvalidTransition(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Device is in discovered state, cannot retry
	err = svc.RetryDevice(ctx, device.ID)
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

func TestService_GetEvents_NotInitialized(t *testing.T) {
	svc := NewService()
	ctx := context.Background()

	_, err := svc.GetEvents(ctx, "device-123")
	assert.Error(t, err)

	var notInitErr ErrServiceNotInitialized
	assert.True(t, errors.As(err, &notInitErr))
}

func TestService_GetEvents_Valid(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	events, err := svc.GetEvents(ctx, device.ID)
	assert.NoError(t, err)
	assert.NotEmpty(t, events) // Should have at least the registration event
}

func TestService_GetEvents_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.GetEvents(ctx, "nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_RegisterEventHandler(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()
	handler := &testEventHandler{delivered: newEventSignal()}

	svc.RegisterEventHandler(handler)

	// Trigger an event by registering a device and transitioning state
	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "test")
	require.NoError(t, err)

	// Wait for the dispatch goroutine, not for 100ms (#262).
	handler.delivered.await(t, 1)

	// Verify handler received the event
	events := handler.getEvents()
	assert.NotEmpty(t, events)
}

func TestService_Status(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	// Check status of initialized but not running service
	status := svc.Status()
	assert.False(t, status.Running)
	assert.Equal(t, testQuarantineVLAN, status.QuarantineVLAN)
	assert.Equal(t, testProvisioningVLAN, status.ProvisioningVLAN)

	// Register some devices
	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	_, err = svc.RegisterDevice(ctx, "00:11:22:33:44:66", "port-2")
	require.NoError(t, err)

	status = svc.Status()
	assert.Equal(t, 2, status.DeviceCount)
}

func TestService_Status_NotInitialized(t *testing.T) {
	svc := NewService()

	status := svc.Status()
	assert.False(t, status.Running)
	assert.Equal(t, uint16(0), status.QuarantineVLAN)
	assert.Equal(t, uint16(0), status.ProvisioningVLAN)
	assert.Equal(t, 0, status.DeviceCount)
}

func TestService_Status_WithRunningService(t *testing.T) {
	cfg := createTestConfig()
	logger := logging.DefaultLogger()
	stateManager := NewStateManager()

	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		vlanManager:  NewNoopVLANIntegration(testNetPlan),
		config:       cfg,
		startTime:    time.Now(),
	}
	svc.initialized.Store(true)
	svc.running.Store(true)

	status := svc.Status()
	assert.True(t, status.Running)
	assert.False(t, status.StartTime.IsZero())
}

func TestService_Status_WithNilIPXEConfig(t *testing.T) {
	cfg := createTestConfig()
	cfg.IPXEConfig = nil // Test nil IPXEConfig path
	logger := logging.DefaultLogger()
	stateManager := NewStateManager()

	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		vlanManager:  NewNoopVLANIntegration(testNetPlan),
		config:       cfg,
	}
	svc.initialized.Store(true)

	status := svc.Status()
	assert.NotNil(t, status)
	assert.Empty(t, status.IPXEServerAddr)
}

func TestService_Close_NotRunning(t *testing.T) {
	svc, _ := initializeTestService(t)

	err := svc.Close()
	assert.NoError(t, err)
}

func TestGenerateDeviceID(t *testing.T) {
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")

	id1 := generateDeviceID(mac1)
	id2 := generateDeviceID(mac2)

	assert.True(t, len(id1) > 0)
	assert.True(t, len(id2) > 0)
	assert.NotEqual(t, id1, id2)
	assert.True(t, len(id1) > 7)                 // "device-" prefix + hash
	assert.Equal(t, "device-", id1[:7])          // Check prefix
	assert.Equal(t, generateDeviceID(mac1), id1) // Same MAC should produce same ID
}

func TestService_ConcurrentDeviceRegistration(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	numDevices := 50

	for i := 0; i < numDevices; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			mac := make(net.HardwareAddr, 6)
			mac[0] = 0x00
			mac[1] = 0x11
			mac[2] = 0x22
			mac[3] = 0x33
			mac[4] = byte(idx / 256)
			mac[5] = byte(idx % 256)

			svc.RegisterDevice(ctx, mac.String(), "port-"+string(rune('0'+idx)))
		}(i)
	}

	wg.Wait()

	devices, err := svc.ListDevices(ctx, nil)
	assert.NoError(t, err)
	assert.Equal(t, numDevices, len(devices))
}

func TestService_QuarantineDevice_FromQuarantined(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// First quarantine
	err = svc.QuarantineDevice(ctx, device.ID, "first quarantine")
	require.NoError(t, err)

	// Cannot quarantine an already quarantined device
	err = svc.QuarantineDevice(ctx, device.ID, "second quarantine")
	assert.Error(t, err)

	var transitionErr ErrInvalidStateTransition
	assert.True(t, errors.As(err, &transitionErr))
}

func TestService_AuthorizeDevice_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.AuthorizeDevice(ctx, "nonexistent", 100)
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_SetDeviceEnrolled_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.SetDeviceEnrolled(ctx, "nonexistent", "serial-123")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_RetryDevice_NotFound(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	err := svc.RetryDevice(ctx, "nonexistent")
	assert.Error(t, err)

	var notFoundErr ErrDeviceNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

func TestService_FullProvisioningWorkflow(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	// Register device
	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	assert.Equal(t, StateDiscovered, device.State)

	// Progress through full workflow
	transitions := []struct {
		state  ProvisioningState
		reason string
	}{
		{StateBooting, "PXE boot started"},
		{StateInstalling, "OS installation started"},
		{StateInstallComplete, "OS installation completed"},
		{StateEnrolling, "TPM enrollment started"},
	}

	for _, trans := range transitions {
		err = svc.UpdateDeviceState(ctx, device.ID, trans.state, trans.reason)
		require.NoError(t, err)
	}

	// Complete enrollment
	err = svc.SetDeviceEnrolled(ctx, device.ID, "cert-serial-12345")
	require.NoError(t, err)

	device, err = svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateEnrolled, device.State)
	assert.Equal(t, "cert-serial-12345", device.CertificateSerial)

	// Continue to authorization
	err = svc.UpdateDeviceState(ctx, device.ID, StateAuthorizing, "authorization started")
	require.NoError(t, err)

	err = svc.AuthorizeDevice(ctx, device.ID, testControlPlaneVLAN)
	require.NoError(t, err)

	device, err = svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateAuthorized, device.State)
	assert.Equal(t, testControlPlaneVLAN, device.TargetVLAN)

	// Verify events were recorded
	events, err := svc.GetEvents(ctx, device.ID)
	require.NoError(t, err)
	assert.True(t, len(events) > 0)
}

func TestService_ListDevices_FilterByMAC(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	_, err = svc.RegisterDevice(ctx, "00:11:22:33:44:66", "port-2")
	require.NoError(t, err)

	devices, err := svc.ListDevices(ctx, &DeviceFilter{MACAddress: "00:11:22:33:44:55"})
	assert.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "00:11:22:33:44:55", devices[0].MACAddress.String())
}

func TestService_ListDevices_FilterByVLAN(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	// Register devices - they start in quarantine VLAN (testQuarantineVLAN=202)
	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	_, err = svc.RegisterDevice(ctx, "00:11:22:33:44:66", "port-2")
	require.NoError(t, err)

	devices, err := svc.ListDevices(ctx, &DeviceFilter{VLAN: testQuarantineVLAN})
	assert.NoError(t, err)
	assert.Len(t, devices, 2)

	devices, err = svc.ListDevices(ctx, &DeviceFilter{VLAN: 100})
	assert.NoError(t, err)
	assert.Len(t, devices, 0)
}

func TestService_ApplyVLANForState_NoVLANManager(t *testing.T) {
	cfg := createTestConfig()

	logger := logging.DefaultLogger()
	stateManager := NewStateManager()
	// Note: no vlanManager set
	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		config:       cfg,
	}
	svc.initialized.Store(true)

	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Should succeed even without VLAN manager
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	assert.NoError(t, err)
}

func TestService_AuthorizeDevice_NoVLANManager(t *testing.T) {
	cfg := createTestConfig()

	logger := logging.DefaultLogger()
	stateManager := NewStateManager()
	// Note: no vlanManager set
	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		config:       cfg,
	}
	svc.initialized.Store(true)

	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Progress to authorizing state
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstalling, "installing")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolling, "enrolling")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolled, "enrolled")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateAuthorizing, "authorizing")
	require.NoError(t, err)

	// Should succeed even without VLAN manager
	err = svc.AuthorizeDevice(ctx, device.ID, testControlPlaneVLAN)
	assert.NoError(t, err)
}

func TestService_QuarantineDevice_NoVLANManager(t *testing.T) {
	cfg := createTestConfig()

	logger := logging.DefaultLogger()
	stateManager := NewStateManager()
	// Note: no vlanManager set
	svc := &service{
		logger:       logger,
		stateManager: stateManager,
		config:       cfg,
	}
	svc.initialized.Store(true)

	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Should succeed even without VLAN manager
	err = svc.QuarantineDevice(ctx, device.ID, "test quarantine")
	assert.NoError(t, err)
}

func TestService_ApplyVLANForState_AllStates(t *testing.T) {
	// Test all VLAN state transitions
	tests := []struct {
		name       string
		state      ProvisioningState
		prevStates []ProvisioningState
	}{
		{"install_complete", StateInstallComplete, []ProvisioningState{StateBooting, StateInstalling}},
		{"enrolling", StateEnrolling, []ProvisioningState{StateBooting, StateInstalling, StateInstallComplete}},
		{"enrolled", StateEnrolled, []ProvisioningState{StateBooting, StateInstalling, StateInstallComplete, StateEnrolling}},
		{"authorizing", StateAuthorizing, []ProvisioningState{StateBooting, StateInstalling, StateInstallComplete, StateEnrolling, StateEnrolled}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := initializeTestService(t)
			ctx := context.Background()

			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)

			// Progress through prerequisite states
			for _, state := range tt.prevStates {
				err = svc.UpdateDeviceState(ctx, device.ID, state, "transition")
				require.NoError(t, err)
			}

			// Apply the target state
			err = svc.UpdateDeviceState(ctx, device.ID, tt.state, "test")
			assert.NoError(t, err)

			retrieved, err := svc.GetDevice(ctx, device.ID)
			assert.NoError(t, err)
			assert.Equal(t, tt.state, retrieved.State)
		})
	}
}

func TestService_QuarantineDevice_FromAuthorized(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Progress to authorized state (terminal state that can still be quarantined)
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstalling, "installing")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateInstallComplete, "complete")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolling, "enrolling")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateEnrolled, "enrolled")
	require.NoError(t, err)
	err = svc.UpdateDeviceState(ctx, device.ID, StateAuthorizing, "authorizing")
	require.NoError(t, err)
	err = svc.AuthorizeDevice(ctx, device.ID, testControlPlaneVLAN)
	require.NoError(t, err)

	// Quarantine the authorized device (this should work)
	err = svc.QuarantineDevice(ctx, device.ID, "security issue")
	assert.NoError(t, err)

	// Verify state changed
	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateQuarantined, retrieved.State)
}

func TestService_RetryDevice_FromQuarantined(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Quarantine the device
	err = svc.QuarantineDevice(ctx, device.ID, "test quarantine")
	require.NoError(t, err)

	// Retry should work from quarantined state
	err = svc.RetryDevice(ctx, device.ID)
	assert.NoError(t, err)

	retrieved, err := svc.GetDevice(ctx, device.ID)
	assert.NoError(t, err)
	assert.Equal(t, StateDiscovered, retrieved.State)
	assert.Equal(t, 1, retrieved.RetryCount)
}

func TestService_Status_NilStateManager(t *testing.T) {
	cfg := createTestConfig()
	logger := logging.DefaultLogger()

	svc := &service{
		logger:      logger,
		vlanManager: NewNoopVLANIntegration(testNetPlan),
		config:      cfg,
		// stateManager is nil
	}
	svc.initialized.Store(true)

	status := svc.Status()
	assert.NotNil(t, status)
	assert.Equal(t, 0, status.DeviceCount)
}

// failingFlowVLAN is a flow manager whose flow moves fail on demand.
type failingFlowVLAN struct {
	VLANIntegration
	fail atomic.Bool
}

var errFlowMove = errors.New("flow manager unavailable")

func (f *failingFlowVLAN) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if f.fail.Load() {
		return errFlowMove
	}
	return f.VLANIntegration.ApplyQuarantineFlows(ctx, portID, mac)
}

func (f *failingFlowVLAN) ApplyProvisioningFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	if f.fail.Load() {
		return errFlowMove
	}
	return f.VLANIntegration.ApplyProvisioningFlows(ctx, portID, mac)
}

// TestService_UpdateDeviceState_VLANFailureFailsClosed checks that a
// failed VLAN move fails the transition: the device keeps its old state
// and the caller sees the error.
func TestService_UpdateDeviceState_VLANFailureFailsClosed(t *testing.T) {
	for _, target := range []ProvisioningState{StateQuarantined, StateFailed, StateBooting} {
		t.Run(string(target), func(t *testing.T) {
			vlan := &failingFlowVLAN{VLANIntegration: NewNoopVLANIntegration(testNetPlan)}
			svc := &service{
				logger:       logging.DefaultLogger(),
				stateManager: NewStateManager(),
				vlanManager:  vlan,
				config:       createTestConfig(),
			}
			svc.initialized.Store(true)
			ctx := context.Background()

			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)

			vlan.fail.Store(true)
			err = svc.UpdateDeviceState(ctx, device.ID, target, "test")
			require.Error(t, err)
			var provErr ErrProvisioningFailed
			require.ErrorAs(t, err, &provErr)
			assert.ErrorIs(t, err, errFlowMove)

			got, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, StateDiscovered, got.State)
		})
	}
}

// TestService_RegisterDevice_QuarantineFailureFailsClosed: a registration
// whose quarantine move fails registers nothing, so a retry once the flow
// manager recovers succeeds (#1896 P1).
func TestService_RegisterDevice_QuarantineFailureFailsClosed(t *testing.T) {
	vlan := &failingFlowVLAN{VLANIntegration: NewNoopVLANIntegration(testNetPlan)}
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  vlan,
		config:       createTestConfig(),
	}
	svc.initialized.Store(true)
	ctx := context.Background()

	vlan.fail.Store(true)
	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, errFlowMove)

	_, err = svc.GetDeviceByMAC(ctx, "00:11:22:33:44:55")
	require.Error(t, err, "a device whose quarantine move failed is registered")

	vlan.fail.Store(false)
	device, err = svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	require.NotNil(t, device)
}

// TestService_UpdateDeviceState_CommitsCurrentVLAN: a state move records the
// VLAN it enforced, so GetDevice and a VLAN filter see the device where its
// port is (#1896 P1).
func TestService_UpdateDeviceState_CommitsCurrentVLAN(t *testing.T) {
	cfg := createTestConfig()
	require.NotEqual(t, cfg.QuarantineVLAN, cfg.ProvisioningVLAN)
	vlan := &failingFlowVLAN{VLANIntegration: NewNoopVLANIntegration(testNetPlan)}
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  vlan,
		config:       cfg,
	}
	svc.initialized.Store(true)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	assert.Equal(t, cfg.QuarantineVLAN, device.CurrentVLAN)

	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "test"))
	got, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, cfg.ProvisioningVLAN, got.CurrentVLAN)

	inProvisioning, err := svc.ListDevices(ctx, &DeviceFilter{VLAN: cfg.ProvisioningVLAN})
	require.NoError(t, err)
	require.Len(t, inProvisioning, 1)
	assert.Equal(t, device.ID, inProvisioning[0].ID)
	inQuarantine, err := svc.ListDevices(ctx, &DeviceFilter{VLAN: cfg.QuarantineVLAN})
	require.NoError(t, err)
	assert.Empty(t, inQuarantine)

	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateFailed, "test"))
	got, err = svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, cfg.QuarantineVLAN, got.CurrentVLAN)
}

// deleteFailingPort is a recordingPort whose DeleteFlowsByPort fails on
// demand while flow installation keeps succeeding.
type deleteFailingPort struct {
	recordingPort
	failDelete bool
}

var errFlowDelete = errors.New("flow deletion failed")

func (d *deleteFailingPort) DeleteFlowsByPort(string, string) error {
	if d.failDelete {
		return errFlowDelete
	}
	return nil
}

// TestService_UpdateDeviceState_FlowDeletionFailureFailsClosed: through the
// real VLAN wrapper and zone flow manager, a failure to delete the port's
// provisioning flows leaves the device in its old state, because the
// provisioning allow rules would outrank quarantine's default drop.
func TestService_UpdateDeviceState_FlowDeletionFailureFailsClosed(t *testing.T) {
	port := &deleteFailingPort{}
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName: "br-fabric", FlowController: port, PortController: port, Plan: testNetPlan,
	})
	require.NoError(t, err)
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  NewVLANIntegrationWrapper(WithFlowManager(zfm)),
		config:       createTestConfig(),
	}
	svc.initialized.Store(true)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "test"))
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateInstalling, "test"))

	port.failDelete = true
	err = svc.UpdateDeviceState(ctx, device.ID, StateQuarantined, "test")
	require.Error(t, err)
	assert.ErrorIs(t, err, errFlowDelete)

	got, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateInstalling, got.State)
}

// blockingFlowVLAN blocks ApplyQuarantineFlows until release is closed.
type blockingFlowVLAN struct {
	VLANIntegration
	entered chan struct{}
	release chan struct{}
}

func (b *blockingFlowVLAN) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	close(b.entered)
	<-b.release
	return nil
}

// TestService_Close_WaitsForInFlightOperations checks that Close waits
// for a RegisterDevice in flight before it clears the config, so the
// call returns cleanly, and later calls see ErrServiceNotInitialized.
func TestService_Close_WaitsForInFlightOperations(t *testing.T) {
	vlan := &blockingFlowVLAN{
		VLANIntegration: NewNoopVLANIntegration(testNetPlan),
		entered:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  vlan,
		config:       createTestConfig(),
	}
	svc.initialized.Store(true)
	ctx := context.Background()

	type result struct {
		device *DeviceInfo
		err    error
	}
	registered := make(chan result, 1)
	go func() {
		d, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
		registered <- result{d, err}
	}()
	<-vlan.entered

	closed := make(chan error, 1)
	go func() { closed <- svc.Close() }()

	select {
	case <-closed:
		t.Fatal("Close returned while RegisterDevice was in flight")
	case <-time.After(100 * time.Millisecond):
	}

	close(vlan.release)
	r := <-registered
	require.NoError(t, r.err)
	require.NotNil(t, r.device)
	require.NoError(t, <-closed)

	_, err := svc.RegisterDevice(ctx, "00:11:22:33:44:66", "port-2")
	var notInit ErrServiceNotInitialized
	assert.ErrorAs(t, err, &notInit)
}

// gatedQuarantineVLAN blocks ApplyQuarantineFlows while armed, and
// records the last flow set it installed, so a test can see which
// flows a device's port is left with.
type gatedQuarantineVLAN struct {
	VLANIntegration
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}

	mu        sync.Mutex
	lastFlows string
}

func (g *gatedQuarantineVLAN) ApplyQuarantineFlows(ctx context.Context, portID string, mac net.HardwareAddr) error {
	// The flows are installed first; the block stands for the time the
	// call takes to return to the service.
	g.mu.Lock()
	g.lastFlows = "quarantine"
	g.mu.Unlock()
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
	return nil
}

func (g *gatedQuarantineVLAN) ApplyAuthorizedFlows(ctx context.Context, portID string, mac net.HardwareAddr, vlanID uint16) error {
	g.mu.Lock()
	g.lastFlows = "authorized"
	g.mu.Unlock()
	return nil
}

func (g *gatedQuarantineVLAN) flows() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastFlows
}

// TestService_QuarantineAuthorize_Serialized checks that an
// AuthorizeDevice started while a QuarantineDevice of the same device is
// inside its flow change waits for it, so the device never ends
// quarantined with production flows on its port.
func TestService_QuarantineAuthorize_Serialized(t *testing.T) {
	vlan := &gatedQuarantineVLAN{
		VLANIntegration: NewNoopVLANIntegration(testNetPlan),
		entered:         make(chan struct{}),
		release:         make(chan struct{}),
	}
	svc := &service{
		logger:       logging.DefaultLogger(),
		stateManager: NewStateManager(),
		vlanManager:  vlan,
		config:       createTestConfig(),
	}
	svc.initialized.Store(true)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:77", "port-7")
	require.NoError(t, err)
	require.NoError(t, svc.stateManager.UpdateDevice(device.ID, func(d *DeviceInfo) error {
		d.State = StateAuthorizing
		return nil
	}))

	vlan.armed.Store(true)
	quarantined := make(chan error, 1)
	go func() { quarantined <- svc.QuarantineDevice(ctx, device.ID, "test") }()
	<-vlan.entered

	authorized := make(chan error, 1)
	go func() { authorized <- svc.AuthorizeDevice(ctx, device.ID, 200) }()

	authReturned := false
	select {
	case <-authorized:
		// The old code lets authorize run to the end here; the
		// release below still lets the quarantine commit.
		authReturned = true
	case <-time.After(200 * time.Millisecond):
	}
	close(vlan.release)
	require.NoError(t, <-quarantined)

	if !authReturned {
		select {
		case <-authorized:
		case <-time.After(5 * time.Second):
			t.Fatal("AuthorizeDevice did not return after the quarantine finished")
		}
	}

	got, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateQuarantined, got.State)
	assert.Equal(t, svc.config.QuarantineVLAN, got.CurrentVLAN)
	assert.Equal(t, "quarantine", vlan.flows(),
		"a quarantined device must not be left with production flows")
}
