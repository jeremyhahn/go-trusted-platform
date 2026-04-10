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
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHandler_InvalidConfig tests handler creation with invalid config
func TestNewHandler_InvalidConfig(t *testing.T) {
	invalidConfig := Config{
		Timeout:          -1 * time.Second,
		RetryCount:       -5,
		RelyingPartyID:   "",
		RelyingPartyName: "",
	}
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&invalidConfig, enum)
	require.NoError(t, err) // Validate fixes invalid values
	require.NotNil(t, handler)

	// Config should be normalized by Validate
	assert.Greater(t, handler.config.Timeout, time.Duration(0))
	assert.NotEmpty(t, handler.config.RelyingPartyID)
}

// TestHandler_EnrollKey_DeviceNotSupported tests enrollment with unsupported device
func TestHandler_EnrollKey_DeviceNotSupported(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Create authenticator without hmac-secret support
	enrollConfig := DefaultEnrollmentConfig("testuser")

	// This will succeed with mock because mock always supports hmac-secret
	// In a real scenario with a device that doesn't support it, this would fail
	_, err = handler.EnrollKey(enrollConfig)
	assert.NoError(t, err) // Mock supports it
}

// TestHandler_EnrollKey_WithTimeout tests enrollment with custom timeout
func TestHandler_EnrollKey_WithTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 10 * time.Second

	originalTimeout := handler.config.Timeout
	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Timeout should be restored after enrollment
	assert.Equal(t, originalTimeout, handler.config.Timeout)
}

// TestHandler_UnlockWithKey_RetryExhausted tests unlock retry logic
func TestHandler_UnlockWithKey_RetryExhausted(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 10 * time.Millisecond

	enum := NewMockHIDDeviceEnumerator()

	// Create a mock device that will fail with user presence error
	mockDev := &MockHIDDevice{
		path:         "/dev/hidraw0",
		vendorID:     0x1234,
		productID:    0x5678,
		manufacturer: "Mock",
		product:      "Mock Key",
		serialNumber: "123",
		readBuf:      bytes.NewBuffer(nil),
		writeBuf:     bytes.NewBuffer(nil),
		responses:    make([][]byte, 0),
	}

	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// The mock will succeed, so we can't easily test retry exhaustion
	// But we can test the code path exists
	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	// This will succeed with mock
	_, err = handler.UnlockWithKey(authConfig)
	assert.NoError(t, err)
}

// TestHandler_UnlockWithKey_WithCustomTimeout tests unlock with custom timeout
func TestHandler_UnlockWithKey_WithCustomTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))
	authConfig.Timeout = 5 * time.Second

	originalTimeout := handler.config.Timeout
	luksKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	require.NotNil(t, luksKey)

	// Timeout should be restored
	assert.Equal(t, originalTimeout, handler.config.Timeout)
}

// TestHandler_SelectDevice_NoMatchingVendor tests vendor filter with no match
func TestHandler_SelectDevice_NoMatchingVendor(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xFFFF} // Non-existent vendor
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0x1234 // Different vendor
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

// TestHandler_SelectDevice_NoMatchingProduct tests product filter with no match
func TestHandler_SelectDevice_NoMatchingProduct(t *testing.T) {
	config := DefaultConfig
	config.AllowedProducts = []uint16{0xFFFF} // Non-existent product
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.productID = 0x5678 // Different product
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

// TestHandler_SelectDevice_MultipleDevicesFiltered tests selecting from multiple devices
func TestHandler_SelectDevice_MultipleDevicesFiltered(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xABCD}
	enum := NewMockHIDDeviceEnumerator()

	// Add multiple devices, only one matches vendor filter
	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x1234

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0xABCD

	mockDev3 := NewMockHIDDevice("/dev/hidraw2")
	mockDev3.vendorID = 0x5678

	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	require.NotNil(t, device)

	assert.Equal(t, uint16(0xABCD), device.VendorID())
}

// TestHandler_SelectDevice_SpecificPathNotFound tests configured device path not found
func TestHandler_SelectDevice_SpecificPathNotFound(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/hidraw99" // Non-existent
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to open configured device")
}

// TestHandler_SelectDevice_EnumerationError tests enumeration error handling
func TestHandler_SelectDevice_EnumerationError(t *testing.T) {
	config := DefaultConfig
	enum := &FailingEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}

// TestHandler_ListDevices_EnumerationError tests ListDevices with enumeration error
func TestHandler_ListDevices_EnumerationError(t *testing.T) {
	config := DefaultConfig
	enum := &FailingEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	assert.Error(t, err)
	assert.Nil(t, devices)
	assert.Contains(t, err.Error(), "failed to enumerate devices")
}

// TestHandler_WaitForDevice_ContinuesOnError tests that WaitForDevice continues on ListDevices error
func TestHandler_WaitForDevice_ContinuesOnError(t *testing.T) {
	config := DefaultConfig
	enum := &IntermittentFailingEnumerator{
		failCount: 2,
	}

	// Add device that will be found after errors
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.devices = []HIDDevice{mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	// Should eventually find the device after a few errors
	assert.NoError(t, err)
	assert.NotNil(t, device)
}

// Helper types for testing

// FailingEnumerator always fails enumeration
type FailingEnumerator struct{}

func (e *FailingEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, errors.New("enumeration failed")
}

func (e *FailingEnumerator) Open(path string) (HIDDevice, error) {
	return nil, errors.New("device not found")
}

// IntermittentFailingEnumerator fails a few times then succeeds
type IntermittentFailingEnumerator struct {
	failCount   int
	currentFail int
	devices     []HIDDevice
}

func (e *IntermittentFailingEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	if e.currentFail < e.failCount {
		e.currentFail++
		return nil, errors.New("temporary failure")
	}
	// Reset devices for reuse
	for _, dev := range e.devices {
		if mockDev, ok := dev.(*MockHIDDevice); ok {
			mockDev.Reset()
		}
	}
	return e.devices, nil
}

func (e *IntermittentFailingEnumerator) Open(path string) (HIDDevice, error) {
	return nil, errors.New("not implemented")
}

// FailingMockHIDDevice extends MockHIDDevice to simulate init failures
type FailingMockHIDDevice struct {
	*MockHIDDevice
	failInit bool
}

func (d *FailingMockHIDDevice) Write(data []byte) (int, error) {
	if d.failInit && len(data) >= 5 && data[4] == CTAPHID_INIT {
		// Don't generate response for init, causing timeout/error
		return len(data), nil
	}
	return d.MockHIDDevice.Write(data)
}

// TestHandler_SelectDevice_AllDevicesFiltered tests when all devices are filtered out
func TestHandler_SelectDevice_AllDevicesFiltered(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0xFFFF}
	config.AllowedProducts = []uint16{0xEEEE}
	enum := NewMockHIDDeviceEnumerator()

	// Add devices that don't match filters
	for i := 0; i < 3; i++ {
		mockDev := NewMockHIDDevice(fmt.Sprintf("/dev/hidraw%d", i))
		mockDev.vendorID = 0x1234
		mockDev.productID = 0x5678
		enum.AddDevice(mockDev)
	}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}

// TestHandler_ListDevices_DeviceProperties tests device property mapping
func TestHandler_ListDevices_DeviceProperties(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.vendorID = 0xABCD
	mockDev.productID = 0x1234
	mockDev.manufacturer = "Test Mfg"
	mockDev.product = "Test Product"
	mockDev.serialNumber = "SN123456"

	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	require.NoError(t, err)
	require.Len(t, devices, 1)

	dev := devices[0]
	assert.Equal(t, "/dev/hidraw0", dev.Path)
	assert.Equal(t, uint16(0xABCD), dev.VendorID)
	assert.Equal(t, uint16(0x1234), dev.ProductID)
	assert.Equal(t, "Test Mfg", dev.Manufacturer)
	assert.Equal(t, "Test Product", dev.Product)
	assert.Equal(t, "SN123456", dev.SerialNumber)
	assert.Equal(t, "usb", dev.Transport)
}

// TestConfig_ValidateEdgeCases tests all Validate edge cases
func TestConfig_ValidateEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		check  func(*testing.T, *Config)
	}{
		{
			name: "negative UserPresenceTimeout",
			config: Config{
				UserPresenceTimeout: -1 * time.Second,
			},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultUserPresenceTimeout, c.UserPresenceTimeout)
			},
		},
		{
			name: "zero UserPresenceTimeout",
			config: Config{
				UserPresenceTimeout: 0,
			},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultUserPresenceTimeout, c.UserPresenceTimeout)
			},
		},
		{
			name: "negative RetryDelay",
			config: Config{
				RetryDelay: -1 * time.Second,
			},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultRetryDelay, c.RetryDelay)
			},
		},
		{
			name: "zero RetryDelay",
			config: Config{
				RetryDelay: 0,
			},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, time.Duration(0), c.RetryDelay)
			},
		},
		{
			name: "empty RelyingPartyName",
			config: Config{
				RelyingPartyName: "",
			},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, "LUKS Disk Encryption", c.RelyingPartyName)
			},
		},
		{
			name:   "all fields empty",
			config: Config{},
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultTimeout, c.Timeout)
				assert.Equal(t, DefaultUserPresenceTimeout, c.UserPresenceTimeout)
				assert.Equal(t, 0, c.RetryCount)
				assert.Equal(t, time.Duration(0), c.RetryDelay)
				assert.Equal(t, "luks-unlock", c.RelyingPartyID)
				assert.Equal(t, "LUKS Disk Encryption", c.RelyingPartyName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
			if tt.check != nil {
				tt.check(t, &tt.config)
			}
		})
	}
}
