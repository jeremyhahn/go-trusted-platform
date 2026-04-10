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
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCTAPHIDDevice(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	require.NotNil(t, ctapDev)

	assert.NotEqual(t, uint32(0), ctapDev.cid)
	assert.Equal(t, mockDev, ctapDev.device)

	err = ctapDev.Close()
	assert.NoError(t, err)
}

func TestCTAPHIDDevice_Init(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
	}

	err := ctapDev.init()
	require.NoError(t, err)

	// Verify a CID was assigned
	assert.NotEqual(t, uint32(0), ctapDev.cid)
	assert.NotEqual(t, CIDBroadcast, ctapDev.cid)
}

func TestCTAPHIDDevice_Ping(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	testData := []byte("ping test data")
	response, err := ctapDev.Ping(testData)
	require.NoError(t, err)

	// Mock should echo the data
	assert.Equal(t, testData, response)
}

func TestCTAPHIDDevice_CreatePackets(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	tests := []struct {
		name            string
		data            []byte
		expectedPackets int
	}{
		{
			name:            "empty data",
			data:            []byte{},
			expectedPackets: 1,
		},
		{
			name:            "small data - single packet",
			data:            make([]byte, 50),
			expectedPackets: 1,
		},
		{
			name:            "exactly first packet size",
			data:            make([]byte, 57), // HIDPacketSize - 7
			expectedPackets: 1,
		},
		{
			name:            "requires continuation packet",
			data:            make([]byte, 100),
			expectedPackets: 2,
		},
		{
			name:            "multiple continuation packets",
			data:            make([]byte, 200),
			expectedPackets: 4, // 57 + 59 + 59 + 25 = 200
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packets := ctapDev.createPackets(ctapDev.cid, CTAPHID_CBOR, tt.data)
			assert.Equal(t, tt.expectedPackets, len(packets))

			// Verify all packets are correct size
			for _, packet := range packets {
				assert.Equal(t, HIDPacketSize, len(packet))
			}
		})
	}
}

func TestCTAPHIDDevice_SendCBOR_GetInfo(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Send GetInfo command
	resp, err := ctapDev.SendCBOR(CmdGetInfo, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
}

func TestCTAPHIDDevice_HandleCTAPError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
	}

	tests := []struct {
		status       byte
		expectedErr  error
		errSubstring string
	}{
		{status: StatusInvalidCommand, errSubstring: "invalid CTAP command"},
		{status: StatusInvalidParameter, errSubstring: "invalid parameter"},
		{status: StatusTimeout, expectedErr: ErrOperationTimeout},
		{status: StatusInvalidCBOR, expectedErr: ErrInvalidCBOR},
		{status: StatusUnsupportedExtension, expectedErr: ErrUnsupportedExtension},
		{status: StatusUserActionPending, expectedErr: ErrUserPresenceRequired},
		{status: StatusNoCredentials, expectedErr: ErrCredentialNotFound},
		{status: StatusPINInvalid, expectedErr: ErrInvalidPIN},
		{status: StatusPINBlocked, expectedErr: ErrPINBlocked},
		{status: StatusPINRequired, expectedErr: ErrPINRequired},
		{status: StatusUPRequired, expectedErr: ErrUserPresenceRequired},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.status)), func(t *testing.T) {
			err := ctapDev.handleCTAPError(tt.status)
			require.Error(t, err)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else if tt.errSubstring != "" {
				assert.Contains(t, err.Error(), tt.errSubstring)
			}
		})
	}
}

func TestCTAPHIDDevice_Info(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.manufacturer = "Test Manufacturer"
	mockDev.product = "Test FIDO2 Key"

	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	info := ctapDev.Info()
	assert.Equal(t, "/dev/hidraw0", info.Path)
	assert.Equal(t, uint16(0x1234), info.VendorID)
	assert.Equal(t, uint16(0x5678), info.ProductID)
	assert.Equal(t, "Test Manufacturer", info.Manufacturer)
	assert.Equal(t, "Test FIDO2 Key", info.Product)
	assert.Equal(t, "usb", info.Transport)
}

func TestMockHIDDevice(t *testing.T) {
	dev := NewMockHIDDevice("/dev/hidraw0")

	assert.Equal(t, "/dev/hidraw0", dev.Path())
	assert.Equal(t, uint16(0x1234), dev.VendorID())
	assert.Equal(t, uint16(0x5678), dev.ProductID())
	assert.Equal(t, "Mock Manufacturer", dev.Manufacturer())
	assert.Equal(t, "Mock FIDO2 Key", dev.Product())

	// Test write
	data := []byte("test data")
	n, err := dev.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), n)

	// Test close
	err = dev.Close()
	assert.NoError(t, err)

	// Write after close should fail
	_, err = dev.Write(data)
	assert.Error(t, err)
}

func TestMockHIDDeviceEnumerator(t *testing.T) {
	enum := NewMockHIDDeviceEnumerator()

	// Initially empty
	devices, err := enum.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Empty(t, devices)

	// Add a device
	dev1 := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(dev1)

	devices, err = enum.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Add another device
	dev2 := NewMockHIDDevice("/dev/hidraw1")
	dev2.vendorID = 0xABCD
	enum.AddDevice(dev2)

	devices, err = enum.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 2)

	// Filter by vendor ID
	devices, err = enum.Enumerate(0xABCD, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)

	// Open specific device
	openedDev, err := enum.Open("/dev/hidraw0")
	require.NoError(t, err)
	assert.NotNil(t, openedDev)
	assert.Equal(t, "/dev/hidraw0", openedDev.Path())

	// Open non-existent device
	_, err = enum.Open("/dev/hidraw99")
	assert.Error(t, err)

	// Remove device
	enum.RemoveDevice("/dev/hidraw0")
	devices, err = enum.Enumerate(0, 0)
	require.NoError(t, err)
	assert.Len(t, devices, 1)
}

func TestCTAPHIDPacketStructure(t *testing.T) {
	// Verify packet size constants
	assert.Equal(t, 64, HIDPacketSize)
	assert.Equal(t, 8, InitNonceSize)
	assert.Equal(t, 4, CIDSize)
	assert.Equal(t, 0xFFFFFFFF, CIDBroadcast)

	// Verify command constants
	assert.Equal(t, 0x81, CTAPHID_PING)
	assert.Equal(t, 0x86, CTAPHID_INIT)
	assert.Equal(t, 0x90, CTAPHID_CBOR)
	assert.Equal(t, 0xBB, CTAPHID_KEEPALIVE)
	assert.Equal(t, 0xBF, CTAPHID_ERROR)
}

func TestStatusCodeConstants(t *testing.T) {
	// Verify important status codes
	assert.Equal(t, 0x00, StatusOK)
	assert.Equal(t, 0x01, StatusInvalidCommand)
	assert.Equal(t, 0x12, StatusInvalidCBOR)
	assert.Equal(t, 0x16, StatusUnsupportedExtension)
	assert.Equal(t, 0x2E, StatusNoCredentials)
	assert.Equal(t, 0x31, StatusPINInvalid)
	assert.Equal(t, 0x36, StatusPINRequired)
	assert.Equal(t, 0x3B, StatusUPRequired)
}

// TestCTAPHIDDevice_InitErrors tests various init failure scenarios
func TestCTAPHIDDevice_InitErrors(t *testing.T) {
	t.Run("nonce mismatch", func(t *testing.T) {
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		config := DefaultConfig

		// Create invalid init response with wrong nonce
		invalidResp := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(invalidResp[0:4], CIDBroadcast)
		invalidResp[4] = CTAPHID_INIT
		binary.BigEndian.PutUint16(invalidResp[5:7], 17)
		// Wrong nonce (all zeros instead of matching request)
		copy(invalidResp[7:15], make([]byte, 8))
		binary.BigEndian.PutUint32(invalidResp[15:19], 0x12345678)

		mockDev.SetResponse(invalidResp)

		ctapDev := &CTAPHIDDevice{
			device: mockDev,
			config: &config,
		}

		err := ctapDev.init()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce mismatch")
	})

	t.Run("invalid response length", func(t *testing.T) {
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		config := DefaultConfig

		// Create response that's too short
		shortResp := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(shortResp[0:4], CIDBroadcast)
		shortResp[4] = CTAPHID_INIT
		binary.BigEndian.PutUint16(shortResp[5:7], 10) // Too short

		mockDev.SetResponse(shortResp)

		ctapDev := &CTAPHIDDevice{
			device: mockDev,
			config: &config,
		}

		err := ctapDev.init()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid CTAPHID_INIT response length")
	})
}

// TestCTAPHIDDevice_HandleCTAPError_AllCodes tests all error code paths
func TestCTAPHIDDevice_HandleCTAPError_AllCodes(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
	}

	// Test additional error codes
	additionalTests := []struct {
		status       byte
		expectedErr  error
		errSubstring string
	}{
		{status: StatusInvalidLength, errSubstring: "invalid length"},
		{status: StatusInvalidSeq, errSubstring: "invalid sequence"},
		{status: StatusChannelBusy, errSubstring: "channel busy"},
		{status: StatusCredentialExcluded, errSubstring: "credential excluded"},
		{status: StatusOperationDenied, errSubstring: "operation denied"},
		{status: StatusUserActionTimeout, expectedErr: ErrOperationTimeout},
		{status: StatusNotAllowed, errSubstring: "operation not allowed"},
		{status: StatusPINBlocked, expectedErr: ErrPINBlocked},
		{status: StatusUVBlocked, errSubstring: "user verification blocked"},
		{status: 0xFF, errSubstring: "CTAP error: 0xFF"},
	}

	for _, tt := range additionalTests {
		t.Run(fmt.Sprintf("status_0x%02X", tt.status), func(t *testing.T) {
			err := ctapDev.handleCTAPError(tt.status)
			require.Error(t, err)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
			} else if tt.errSubstring != "" {
				assert.Contains(t, err.Error(), tt.errSubstring)
			}
		})
	}
}

// TestNewCTAPHIDDevice_InitFailure tests device creation when init fails
func TestNewCTAPHIDDevice_InitFailure(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	// Set up a response that will cause init to fail
	badResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(badResp[0:4], CIDBroadcast)
	badResp[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(badResp[5:7], 5) // Too short

	mockDev.SetResponse(badResp)

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err)
	assert.Nil(t, ctapDev)
	assert.Contains(t, err.Error(), "failed to initialize CTAP channel")
}

// TestCTAPHIDDevice_SendCBOR_Errors tests SendCBOR error paths
func TestCTAPHIDDevice_SendCBOR_Errors(t *testing.T) {
	t.Run("empty response", func(t *testing.T) {
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		config := DefaultConfig

		ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
		require.NoError(t, err)
		defer func() {
			if err := ctapDev.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		// Create empty CBOR response
		emptyResp := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(emptyResp[0:4], ctapDev.cid)
		emptyResp[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(emptyResp[5:7], 0)

		mockDev.Reset()
		mockDev.SetResponse(emptyResp)

		_, err = ctapDev.SendCBOR(CmdGetInfo, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty CBOR response")
	})

	t.Run("status OK with empty payload", func(t *testing.T) {
		mockDev := NewMockHIDDevice("/dev/hidraw0")
		config := DefaultConfig

		ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
		require.NoError(t, err)
		defer func() {
			if err := ctapDev.Close(); err != nil {
				t.Logf("cleanup: %v", err)
			}
		}()

		okResp := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(okResp[0:4], ctapDev.cid)
		okResp[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(okResp[5:7], 1)
		okResp[7] = StatusOK

		mockDev.Reset()
		mockDev.SetResponse(okResp)

		resp, err := ctapDev.SendCBOR(CmdReset, nil)
		assert.NoError(t, err)
		assert.Empty(t, resp)
	})
}
