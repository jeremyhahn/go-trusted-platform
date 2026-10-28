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
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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

func TestService_SetDeviceInstalling_BindsTheInstallerCertificate(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()
	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting"))
	fingerprint := CertificateSHA256([]byte("installer certificate"))

	// An upper-case fingerprint is stored in the form the webhook computes.
	require.NoError(t, svc.SetDeviceInstalling(ctx, device.ID, strings.ToUpper(fingerprint), "installing"))

	retrieved, err := svc.GetDevice(ctx, device.ID)
	require.NoError(t, err)
	assert.Equal(t, StateInstalling, retrieved.State)
	assert.Equal(t, fingerprint, retrieved.InstallCertificateSHA256)
	found, err := svc.ListDevices(ctx, &DeviceFilter{InstallCertificateSHA256: fingerprint})
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, device.ID, found[0].ID)
}

// TestService_SetDeviceInstalling_RejectedCallKeepsTheAcceptedBinding races
// installers with different certificates against one booting device. Only one
// call may move the device to installing, and the bound certificate must be
// that call's: a rejected call must not rebind the webhook's identity.
func TestService_SetDeviceInstalling_RejectedCallKeepsTheAcceptedBinding(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()
	const rounds = 50
	const installers = 16

	for round := 0; round < rounds; round++ {
		mac := fmt.Sprintf("02:00:00:00:%02x:%02x", round/256, round%256)
		device, err := svc.RegisterDevice(ctx, mac, "port-1")
		require.NoError(t, err)
		require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting"))

		start := make(chan struct{})
		accepted := make(chan string, installers)
		var wg sync.WaitGroup
		for i := 0; i < installers; i++ {
			fingerprint := CertificateSHA256([]byte(fmt.Sprintf("installer %d/%d", round, i)))
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if svc.SetDeviceInstalling(ctx, device.ID, fingerprint, "installing") == nil {
					accepted <- fingerprint
				}
			}()
		}
		close(start)
		wg.Wait()
		close(accepted)

		require.Len(t, accepted, 1, "round %d", round)
		winner := <-accepted
		retrieved, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		assert.Equal(t, StateInstalling, retrieved.State)
		require.Equal(t, winner, retrieved.InstallCertificateSHA256, "round %d", round)
	}
}

func TestService_SetDeviceInstalling_Refusals(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	cases := map[string]struct {
		fingerprint string
		booted      bool
		deviceID    string
		wantErr     error
	}{
		"not hex":            {fingerprint: strings.Repeat("zz", 32), booted: true, wantErr: ErrInvalidCertificateFingerprint{}},
		"wrong length":       {fingerprint: fingerprint[:62], booted: true, wantErr: ErrInvalidCertificateFingerprint{}},
		"empty":              {fingerprint: "", booted: true, wantErr: ErrInvalidCertificateFingerprint{}},
		"device not booting": {fingerprint: fingerprint, booted: false, wantErr: ErrInvalidStateTransition{}},
		"unknown device":     {fingerprint: fingerprint, booted: true, deviceID: "nonexistent", wantErr: ErrDeviceNotFound{}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _ := initializeTestService(t)
			ctx := context.Background()
			device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
			require.NoError(t, err)
			if tc.booted {
				require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting"))
			}
			deviceID := device.ID
			if tc.deviceID != "" {
				deviceID = tc.deviceID
			}

			err = svc.SetDeviceInstalling(ctx, deviceID, tc.fingerprint, "installing")

			require.Error(t, err)
			assert.IsType(t, tc.wantErr, err)
			retrieved, getErr := svc.GetDevice(ctx, device.ID)
			require.NoError(t, getErr)
			assert.Empty(t, retrieved.InstallCertificateSHA256, "a refused call must not bind a certificate")
			assert.NotEqual(t, StateInstalling, retrieved.State)
		})
	}
}

func TestService_SetDeviceInstalling_NotInitialized(t *testing.T) {
	svc := NewService()

	err := svc.SetDeviceInstalling(context.Background(), "device-123", CertificateSHA256([]byte("c")), "installing")

	assert.IsType(t, ErrServiceNotInitialized{}, err)
}

// installingTestDevice registers a device and moves it to installing under
// the installer certificate fingerprint.
func installingTestDevice(t *testing.T, svc Service, fingerprint string) *DeviceInfo {
	t.Helper()
	ctx := context.Background()
	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting"))
	require.NoError(t, svc.SetDeviceInstalling(ctx, device.ID, fingerprint, "installing"))
	return device
}

func TestService_CompleteInstallation_EndsTheBoundInstallation(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	outcomes := map[bool]ProvisioningState{true: StateInstallComplete, false: StateFailed}
	for success, want := range outcomes {
		t.Run(string(want), func(t *testing.T) {
			svc, _ := initializeTestService(t)
			ctx := context.Background()
			device := installingTestDevice(t, svc, fingerprint)

			require.NoError(t, svc.CompleteInstallation(ctx, device.ID, strings.ToUpper(fingerprint), success, "done"))

			retrieved, err := svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, want, retrieved.State)
			assert.Empty(t, retrieved.InstallCertificateSHA256, "the ended installation's binding must be cleared")
			found, err := svc.ListDevices(ctx, &DeviceFilter{InstallCertificateSHA256: fingerprint})
			require.NoError(t, err)
			assert.Empty(t, found)

			// The same certificate cannot end it again, either way.
			for _, again := range []bool{true, false} {
				var notBound ErrInstallationNotBound
				require.ErrorAs(t, svc.CompleteInstallation(ctx, device.ID, fingerprint, again, "replay"), &notBound)
			}
			retrieved, err = svc.GetDevice(ctx, device.ID)
			require.NoError(t, err)
			assert.Equal(t, want, retrieved.State)
		})
	}
}

func TestService_CompleteInstallation_Refusals(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	other := CertificateSHA256([]byte("another installer certificate"))

	t.Run("another certificate", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		device := installingTestDevice(t, svc, fingerprint)

		err := svc.CompleteInstallation(context.Background(), device.ID, other, false, "failed")

		var notBound ErrInstallationNotBound
		require.ErrorAs(t, err, &notBound)
		retrieved, err := svc.GetDevice(context.Background(), device.ID)
		require.NoError(t, err)
		assert.Equal(t, StateInstalling, retrieved.State)
		assert.Equal(t, fingerprint, retrieved.InstallCertificateSHA256)
	})

	t.Run("not installing", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		ctx := context.Background()
		device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
		require.NoError(t, err)

		err = svc.CompleteInstallation(ctx, device.ID, fingerprint, false, "failed")

		var notBound ErrInstallationNotBound
		require.ErrorAs(t, err, &notBound)
		assert.Equal(t, string(StateDiscovered), notBound.State)
	})

	t.Run("malformed fingerprint", func(t *testing.T) {
		svc, _ := initializeTestService(t)
		device := installingTestDevice(t, svc, fingerprint)

		err := svc.CompleteInstallation(context.Background(), device.ID, "not-hex", true, "done")

		assert.IsType(t, ErrInvalidCertificateFingerprint{}, err)
	})

	t.Run("unknown device", func(t *testing.T) {
		svc, _ := initializeTestService(t)

		err := svc.CompleteInstallation(context.Background(), "nonexistent", fingerprint, true, "done")

		assert.IsType(t, ErrDeviceNotFound{}, err)
	})

	t.Run("not initialized", func(t *testing.T) {
		err := NewService().CompleteInstallation(context.Background(), "device-123", fingerprint, true, "done")

		assert.IsType(t, ErrServiceNotInitialized{}, err)
	})
}

// Concurrent completions of one installation: exactly one ends it, and the
// state is the winner's outcome.
func TestService_CompleteInstallation_OneConcurrentCompletionWins(t *testing.T) {
	fingerprint := CertificateSHA256([]byte("installer certificate"))
	for round := 0; round < 20; round++ {
		svc, _ := initializeTestService(t)
		ctx := context.Background()
		device := installingTestDevice(t, svc, fingerprint)

		results := make([]error, 8)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = svc.CompleteInstallation(ctx, device.ID, fingerprint, i%2 == 0, "done")
			}(i)
		}
		wg.Wait()

		winners := 0
		var winnerState ProvisioningState
		for i, err := range results {
			if err == nil {
				winners++
				winnerState = map[bool]ProvisioningState{true: StateInstallComplete, false: StateFailed}[i%2 == 0]
				continue
			}
			var notBound ErrInstallationNotBound
			require.ErrorAs(t, err, &notBound, "round %d", round)
		}
		require.Equal(t, 1, winners, "round %d", round)
		retrieved, err := svc.GetDevice(ctx, device.ID)
		require.NoError(t, err)
		assert.Equal(t, winnerState, retrieved.State, "round %d", round)
	}
}

func TestCertificateSHA256_IsTheLowercaseDigestOfTheDER(t *testing.T) {
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", CertificateSHA256(nil))
	assert.NotEqual(t, CertificateSHA256([]byte("a")), CertificateSHA256([]byte("b")))
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

func TestService_ApplyVLANForState(t *testing.T) {
	svc, _ := initializeTestService(t)
	ctx := context.Background()

	device, err := svc.RegisterDevice(ctx, "00:11:22:33:44:55", "port-1")
	require.NoError(t, err)

	// Progress through states that should change VLAN
	err = svc.UpdateDeviceState(ctx, device.ID, StateBooting, "booting")
	assert.NoError(t, err)

	err = svc.UpdateDeviceState(ctx, device.ID, StateQuarantined, "quarantine test")
	assert.NoError(t, err)
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

func TestService_UpdateDeviceState_VLANTransitions(t *testing.T) {
	tests := []struct {
		name         string
		toState      ProvisioningState
		prevStates   []ProvisioningState
		expectedVLAN string // "provisioning", "quarantine", or "none"
	}{
		{
			name:         "booting_applies_provisioning",
			toState:      StateBooting,
			prevStates:   []ProvisioningState{},
			expectedVLAN: "provisioning",
		},
		{
			name:         "installing_applies_provisioning",
			toState:      StateInstalling,
			prevStates:   []ProvisioningState{StateBooting},
			expectedVLAN: "provisioning",
		},
		{
			name:         "failed_applies_quarantine",
			toState:      StateFailed,
			prevStates:   []ProvisioningState{StateBooting},
			expectedVLAN: "quarantine",
		},
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
			err = svc.UpdateDeviceState(ctx, device.ID, tt.toState, "test")
			assert.NoError(t, err)
		})
	}
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
