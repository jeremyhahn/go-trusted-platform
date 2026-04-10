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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetInfo_WithNonStringVersions tests GetInfo handling non-string versions
func TestGetInfo_WithNonStringVersions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	// Create GetInfo response with non-string versions (should be skipped)
	info := map[int]interface{}{
		0x01: []interface{}{"FIDO_2_0", 123, "U2F_V2"}, // Mix of string and int
		0x02: []interface{}{"hmac-secret", 456},        // Mix of string and int
	}

	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], ctapDev.cid)
	response[4] = CTAPHID_CBOR
	fullPayload := append([]byte{StatusOK}, encoded...)
	binary.BigEndian.PutUint16(response[5:7], uint16(len(fullPayload)))
	copy(response[7:], fullPayload)

	mockDev.SetResponse(response)

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	parsedInfo, err := auth.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, parsedInfo)
	// Should only contain string versions
	assert.Contains(t, parsedInfo.Versions, "FIDO_2_0")
	assert.Contains(t, parsedInfo.Versions, "U2F_V2")
	// Non-string should be skipped
	assert.Len(t, parsedInfo.Versions, 2)
}

// TestGetInfo_WithNonUint64PinProtocols tests GetInfo with non-uint64 PIN protocols
func TestGetInfo_WithNonUint64PinProtocols(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x06: []interface{}{uint64(1), "invalid", uint64(2)}, // Mix
	}

	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], ctapDev.cid)
	response[4] = CTAPHID_CBOR
	fullPayload := append([]byte{StatusOK}, encoded...)
	binary.BigEndian.PutUint16(response[5:7], uint16(len(fullPayload)))
	copy(response[7:], fullPayload)

	mockDev.SetResponse(response)

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	parsedInfo, err := auth.GetInfo()
	require.NoError(t, err)
	assert.Len(t, parsedInfo.PINProtocols, 2) // Only valid ones
}

// TestGetInfo_WithNonStringTransports tests GetInfo with non-string transports
func TestGetInfo_WithNonStringTransports(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x09: []interface{}{"usb", 123, "nfc"}, // Mix
	}

	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], ctapDev.cid)
	response[4] = CTAPHID_CBOR
	fullPayload := append([]byte{StatusOK}, encoded...)
	binary.BigEndian.PutUint16(response[5:7], uint16(len(fullPayload)))
	copy(response[7:], fullPayload)

	mockDev.SetResponse(response)

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	parsedInfo, err := auth.GetInfo()
	require.NoError(t, err)
	assert.Len(t, parsedInfo.Transports, 2) // Only strings
}

// TestGetAssertion_WithInvalidCredentialTransports tests GetAssertion with invalid transport types
func TestGetAssertion_WithInvalidCredentialTransports(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer ctapDev.Close()

	// First, need to make auth with GetInfo response
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoResponse := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(infoResponse[0:4], ctapDev.cid)
	infoResponse[4] = CTAPHID_CBOR
	infoFullPayload := append([]byte{StatusOK}, infoEncoded...)
	binary.BigEndian.PutUint16(infoResponse[5:7], uint16(len(infoFullPayload)))
	copy(infoResponse[7:], infoFullPayload)

	mockDev.SetResponse(infoResponse)

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Now set up GetAssertion response with invalid transports
	authData := make([]byte, 69)
	authData[32] = 0x81
	binary.BigEndian.PutUint32(authData[33:37], 5)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type":       "public-key",
			"id":         make([]byte, 32),
			"transports": []interface{}{"usb", 123}, // Mix
		},
		0x02: authData,
		0x03: make([]byte, 64),
	}

	encoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	// Use the mock's multi-packet response method to properly handle large payloads
	fullPayload := append([]byte{StatusOK}, encoded...)

	// Calculate if we need multiple packets
	firstPayloadSize := HIDPacketSize - 7 // 57 bytes
	if len(fullPayload) <= firstPayloadSize {
		// Single packet response
		response := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(response[0:4], ctapDev.cid)
		response[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(response[5:7], uint16(len(fullPayload)))
		copy(response[7:], fullPayload)
		mockDev.SetResponse(response)
	} else {
		// Multi-packet response needed
		var packets [][]byte

		// First packet
		firstPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(firstPacket[0:4], ctapDev.cid)
		firstPacket[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(firstPacket[5:7], uint16(len(fullPayload)))
		copy(firstPacket[7:], fullPayload[:firstPayloadSize])
		packets = append(packets, firstPacket)

		// Continuation packets
		remaining := fullPayload[firstPayloadSize:]
		seq := byte(0)
		contPayloadSize := HIDPacketSize - 5 // 59 bytes

		for len(remaining) > 0 {
			contPacket := make([]byte, HIDPacketSize)
			binary.BigEndian.PutUint32(contPacket[0:4], ctapDev.cid)
			contPacket[4] = seq

			n := contPayloadSize
			if len(remaining) < n {
				n = len(remaining)
			}
			copy(contPacket[5:], remaining[:n])
			packets = append(packets, contPacket)

			remaining = remaining[n:]
			seq++
		}

		mockDev.SetMultiPacketResponse(packets)
	}

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
	}

	parsedResp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	// Should only contain valid strings
	assert.Len(t, parsedResp.Credential.Transports, 1)
}

// TestUnlockWithKey_WithNoLastError tests UnlockWithKey path where lastErr is nil
func TestUnlockWithKey_WithNoLastError(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 0 // No retries
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Remove device to force immediate failure
	enum.RemoveDevice("/dev/hidraw0")

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	luksKey, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Nil(t, luksKey)
}

// TestEnrollKey_CreateAuthenticatorError tests error path in EnrollKey when no devices are found
func TestEnrollKey_CreateAuthenticatorError(t *testing.T) {
	config := DefaultConfig

	// Create an empty enumerator with no devices
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Don't add any devices to the enumerator
	// This will cause selectDevice to fail with ErrNoDeviceFound

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNoDeviceFound)
}
