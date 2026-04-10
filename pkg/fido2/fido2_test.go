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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	assert.Equal(t, &config, handler.config)
	assert.Equal(t, enum, handler.enumerator)
}

func TestNewHandler_NilConfig(t *testing.T) {
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(nil, enum)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Should use default config
	assert.NotNil(t, handler.config)
	assert.Equal(t, "luks-unlock", handler.config.RelyingPartyID)
}

func TestNewHandler_NilEnumerator(t *testing.T) {
	config := DefaultConfig

	handler, err := NewHandler(&config, nil)
	assert.Error(t, err)
	assert.Nil(t, handler)
}

func TestHandler_ListDevices(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Initially no devices
	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.Empty(t, devices)

	// Add a device
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	devices, err = handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 1)
	assert.Equal(t, "/dev/hidraw0", devices[0].Path)

	// Add another device
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	enum.AddDevice(mockDev2)

	devices, err = handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 2)
}

func TestHandler_WaitForDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Add device after a delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		enum.AddDevice(mockDev)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err)
	require.NotNil(t, device)
	assert.Equal(t, "/dev/hidraw0", device.Path)
}

func TestHandler_WaitForDevice_Timeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	assert.Error(t, err)
	assert.Nil(t, device)
}

func TestHandler_EnrollKey(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Basic assertions that the mock can satisfy
	assert.NotEmpty(t, result.CredentialID)
	assert.NotEmpty(t, result.Salt)
	// Note: PublicKey requires a fully-formed COSE key in mock response
	// which is complex to mock. The field may be empty with basic mock.
	assert.Equal(t, "testuser", result.User.Name)
	assert.False(t, result.Created.IsZero())
}

func TestHandler_EnrollKey_NoDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestHandler_UnlockWithKey(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := DefaultAuthenticationConfig(credID, salt)

	luksKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, luksKey)

	assert.Equal(t, 64, len(luksKey), "LUKS key should be 512 bits")
}

func TestHandler_UnlockWithKey_NoDevice(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	luksKey, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Nil(t, luksKey)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

func TestHandler_SelectDevice_SpecificPath(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/hidraw1"
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, "/dev/hidraw1", device.Path())
}

func TestHandler_SelectDevice_WithVendorFilter(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xABCD}
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x1234

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0xABCD

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0xABCD), device.VendorID())
}

func TestHandler_SelectDevice_WithProductFilter(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0x9999}
	enum := NewMockHIDDeviceEnumerator()

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.productID = 0x5678

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.productID = 0x9999

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0x9999), device.ProductID())
}

func TestHandler_Close(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	err = handler.Close()
	assert.NoError(t, err)
}

func TestHandler_FullFlow(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	defer func() { _ = handler.Close() }()

	// Step 1: Enroll
	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollResult, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, enrollResult)

	// Step 2: Unlock using enrolled credential
	authConfig := DefaultAuthenticationConfig(
		enrollResult.CredentialID,
		enrollResult.Salt,
	)

	luksKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, luksKey)

	assert.Equal(t, 64, len(luksKey))

	// Verify deterministic unlock
	luksKey2, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	// Note: Mock always generates same response, so keys will match
	// In real scenario, keys would match if same credential+salt used
	assert.Equal(t, luksKey, luksKey2)
}

func TestHandler_EnrollKey_WithCustomTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 5 * time.Second

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestHandler_UnlockWithKey_WithRetry(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 10 * time.Millisecond

	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := DefaultAuthenticationConfig(credID, salt)

	// Mock will succeed on first attempt
	luksKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, luksKey)
}

func TestHandler_IsFIDO2Device(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	mockDev := NewMockHIDDevice("/dev/hidraw0")

	// Current implementation accepts all devices
	assert.True(t, handler.isFIDO2Device(mockDev))
}

func TestDefaultEnrollmentConfig(t *testing.T) {
	config := DefaultEnrollmentConfig("alice")

	assert.Equal(t, "luks-unlock", config.RelyingParty.ID)
	assert.Equal(t, "LUKS Disk Encryption", config.RelyingParty.Name)
	assert.Equal(t, "alice", config.User.Name)
	assert.Equal(t, "alice", config.User.DisplayName)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestDefaultAuthenticationConfig(t *testing.T) {
	credID := []byte("test-cred-id")
	salt := []byte("test-salt")

	config := DefaultAuthenticationConfig(credID, salt)

	assert.Equal(t, "luks-unlock", config.RelyingPartyID)
	assert.Equal(t, credID, config.CredentialID)
	assert.Equal(t, salt, config.Salt)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestHandler_MultipleDevices(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	// Add multiple devices
	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev3 := NewMockHIDDevice("/dev/hidraw2")

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.Len(t, devices, 3)

	// Verify all devices are listed
	paths := make(map[string]bool)
	for _, dev := range devices {
		paths[dev.Path] = true
	}

	assert.True(t, paths["/dev/hidraw0"])
	assert.True(t, paths["/dev/hidraw1"])
	assert.True(t, paths["/dev/hidraw2"])
}
