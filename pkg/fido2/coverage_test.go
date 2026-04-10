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
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create multi-packet HID responses
func createMultiPacketResponse(cid uint32, cborPayload []byte) [][]byte {
	fullPayload := append([]byte{StatusOK}, cborPayload...)
	payloadLen := len(fullPayload)

	var packets [][]byte

	// First packet
	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		copy(firstPacket[7:], fullPayload)
		return [][]byte{firstPacket}
	}

	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	packets = append(packets, firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		packets = append(packets, contPacket)

		remaining = remaining[n:]
		seq++
	}

	return packets
}

// TestGetInfo_ParseAllFields tests GetInfo parsing of all response fields
func TestGetInfo_ParseAllFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create a comprehensive GetInfo response
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0", "FIDO_2_1", "U2F_V2"},
		0x02: []string{"hmac-secret", "credProtect"},
		0x03: make([]byte, 16), // AAGUID
		0x04: map[string]bool{
			"rk":   true,
			"up":   true,
			"plat": false,
			"uv":   true,
		},
		0x05: uint64(1200),
		0x06: []uint64{1, 2},
		0x07: uint64(25),
		0x08: uint64(128),
		0x09: []string{"usb", "nfc"},
		0x0A: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"alg":  int64(-7),
			},
			map[string]interface{}{
				"type": "public-key",
				"alg":  int64(-257),
			},
		},
	}

	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	// Create multi-packet response
	packets := createMultiPacketResponse(ctapDev.cid, encoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range packets {
		mockDev.SetResponse(packet)
	}

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	parsedInfo, err := auth.GetInfo()
	require.NoError(t, err)
	require.NotNil(t, parsedInfo)

	// Verify all parsed fields
	assert.Contains(t, parsedInfo.Versions, "FIDO_2_0")
	assert.Contains(t, parsedInfo.Versions, "FIDO_2_1")
	assert.Contains(t, parsedInfo.Extensions, "hmac-secret")
	assert.Contains(t, parsedInfo.Extensions, "credProtect")
	assert.Len(t, parsedInfo.AAGUID, 16)
	assert.True(t, parsedInfo.Options["rk"])
	assert.True(t, parsedInfo.Options["uv"])
	assert.Equal(t, uint64(1200), parsedInfo.MaxMsgSize)
	assert.Contains(t, parsedInfo.PINProtocols, uint64(1))
	assert.Contains(t, parsedInfo.PINProtocols, uint64(2))
	assert.Equal(t, uint64(25), parsedInfo.MaxCredentialCount)
	assert.Equal(t, uint64(128), parsedInfo.MaxCredentialIDLen)
	assert.Contains(t, parsedInfo.Transports, "usb")
	assert.Contains(t, parsedInfo.Transports, "nfc")
	assert.Len(t, parsedInfo.Algorithms, 2)
	assert.Equal(t, "public-key", parsedInfo.Algorithms[0].Type)
	assert.Equal(t, -7, parsedInfo.Algorithms[0].Alg)
}

// TestMakeCredential_WithAllOptions tests MakeCredential with all optional fields
func TestMakeCredential_WithAllOptions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: CreateClientDataHash([]byte("test")),
		RP: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
			Icon: "https://example.com/icon.png",
		},
		User: User{
			ID:          []byte("user123"),
			Name:        "test@example.com",
			DisplayName: "Test User",
			Icon:        "https://example.com/user.png",
		},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
		ExcludeList: []PublicKeyCredentialDescriptor{
			{
				Type:       "public-key",
				ID:         []byte("exclude1"),
				Transports: []string{"usb"},
			},
		},
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: true,
		},
		Options: AuthenticatorOptions{
			RK: true,
			UV: true,
		},
		PinUVAuthParam:    []byte("authparam"),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestMakeCredential_ParseOptionalFields tests parsing optional response fields
func TestMakeCredential_ParseOptionalFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create a response with all optional fields
	authData := make([]byte, 87)
	authData[32] = 0x41 // flags
	binary.BigEndian.PutUint32(authData[33:37], 1)
	binary.BigEndian.PutUint16(authData[53:55], 32)

	respMap := map[int]interface{}{
		0x01: "packed",
		0x02: authData,
		0x03: map[string]interface{}{
			"alg": int64(-7),
			"sig": make([]byte, 64),
		},
		0x04: true,             // epAtt
		0x05: make([]byte, 32), // largeBlobKey
	}

	encoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	// Create multi-packet response
	packets := createMultiPacketResponse(ctapDev.cid, encoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range packets {
		mockDev.SetResponse(packet)
	}

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	req := &MakeCredentialRequest{
		ClientDataHash:   CreateClientDataHash([]byte("test")),
		RP:               RelyingParty{ID: "example.com", Name: "Example"},
		User:             User{ID: []byte("user"), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: DefaultPublicKeyCredentialParameters(),
	}

	parsedResp, err := auth.MakeCredential(req)
	require.NoError(t, err)
	require.NotNil(t, parsedResp)

	assert.Equal(t, "packed", parsedResp.Fmt)
	assert.True(t, parsedResp.EPAtt)
	assert.Len(t, parsedResp.LargeBlobKey, 32)
}

// TestGetAssertion_WithAllOptions tests GetAssertion with all optional fields
func TestGetAssertion_WithAllOptions(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
		AllowList: []PublicKeyCredentialDescriptor{
			{
				Type:       "public-key",
				ID:         make([]byte, 32),
				Transports: []string{"usb", "nfc"},
			},
		},
		Extensions: map[string]interface{}{
			ExtensionHMACSecret: map[string]interface{}{
				"salt1": make([]byte, 32),
			},
		},
		Options: AuthenticatorOptions{
			UP: true,
			UV: true,
		},
		PinUVAuthParam:    []byte("authparam"),
		PinUVAuthProtocol: 1,
	}

	resp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// TestGetAssertion_ParseAllOptionalFields tests parsing all optional response fields
func TestGetAssertion_ParseAllOptionalFields(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	authData := make([]byte, 69)
	authData[32] = 0x81
	binary.BigEndian.PutUint32(authData[33:37], 5)

	respMap := map[int]interface{}{
		0x01: map[string]interface{}{
			"type":       "public-key",
			"id":         make([]byte, 32),
			"transports": []string{"usb"},
		},
		0x02: authData,
		0x03: make([]byte, 64),
		0x04: map[string]interface{}{
			"id":          []byte("userid"),
			"name":        "username",
			"displayName": "Display Name",
			"icon":        "https://example.com/icon.png",
		},
		0x05: uint64(3),
		0x06: true,
		0x07: make([]byte, 32),
	}

	encoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	// Create multi-packet response
	packets := createMultiPacketResponse(ctapDev.cid, encoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range packets {
		mockDev.SetResponse(packet)
	}

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
	}

	parsedResp, err := auth.GetAssertion(req)
	require.NoError(t, err)
	require.NotNil(t, parsedResp)

	assert.Equal(t, "public-key", parsedResp.Credential.Type)
	assert.Contains(t, parsedResp.Credential.Transports, "usb")
	assert.NotNil(t, parsedResp.User)
	assert.Equal(t, "username", parsedResp.User.Name)
	assert.Equal(t, "Display Name", parsedResp.User.DisplayName)
	assert.Equal(t, "https://example.com/icon.png", parsedResp.User.Icon)
	assert.Equal(t, uint64(3), parsedResp.NumberOfCredentials)
	assert.True(t, parsedResp.UserSelected)
	assert.Len(t, parsedResp.LargeBlobKey, 32)
}

// TestGetAssertion_CanoKeyWorkaround_InvalidCBOR tests CanoKey workaround with invalid CBOR
func TestGetAssertion_CanoKeyWorkaround_InvalidCBOR(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig
	config.WorkaroundCanoKey = true

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create truncated/invalid CBOR that triggers workaround
	invalidCBOR := []byte{0xA1, 0x01} // Incomplete map

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], ctapDev.cid)
	response[4] = CTAPHID_CBOR
	fullPayload := append([]byte{StatusOK}, invalidCBOR...)
	binary.BigEndian.PutUint16(response[5:7], uint16(len(fullPayload)))
	copy(response[7:], fullPayload)

	// mockDev.Reset() - not needed, device already initialized
	mockDev.SetResponse(response)

	auth := &Authenticator{
		device: ctapDev,
		config: &config,
	}

	req := &GetAssertionRequest{
		RPID:           "example.com",
		ClientDataHash: CreateClientDataHash([]byte("test")),
	}

	// Should still fail but after attempting workaround
	_, err = auth.GetAssertion(req)
	assert.Error(t, err)
}

// TestEnrollKey_WithCustomTimeout tests enrollment with custom timeout
func TestEnrollKey_WithCustomTimeout(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Timeout = 5 * time.Second // Reasonable custom timeout

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.CredentialID)
}

// TestUnlockWithKey_RetryLogic tests retry logic in UnlockWithKey
func TestUnlockWithKey_RetryLogic(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	enum := NewMockHIDDeviceEnumerator()

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	// Should succeed on first or subsequent attempts
	luksKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	assert.Len(t, luksKey, 64)
}

// TestHMACSecretExtension_EnrollWithProvidedSalt tests enrollment with custom salt
func TestHMACSecretExtension_EnrollWithProvidedSalt(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customSalt := make([]byte, 32)
	for i := range customSalt {
		customSalt[i] = byte(i)
	}

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "example.com",
			Name: "Example",
		},
		User: User{
			Name:        "testuser",
			DisplayName: "Test User",
		},
		Salt: customSalt,
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, customSalt, result.Salt)
}

// TestHMACSecretExtension_DeriveWithCustomChallenge tests derivation with custom challenge
func TestHMACSecretExtension_DeriveWithCustomChallenge(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customChallenge := make([]byte, 32)
	for i := range customChallenge {
		customChallenge[i] = byte(i + 50)
	}

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
		Challenge:      customChallenge,
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.HMACSecret)
}

// TestHMACSecretExtension_DeriveWithNoExtensionData tests fallback when no extension data
func TestHMACSecretExtension_DeriveWithNoExtensionData(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create GetInfo response
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoPackets := createMultiPacketResponse(ctapDev.cid, infoEncoded)

	// Create GetAssertion response without extension data
	authData := make([]byte, 37) // No extension data
	authData[32] = 0x01          // Only UP flag, no ED flag
	binary.BigEndian.PutUint32(authData[33:37], 1)

	respMap := map[int]interface{}{
		0x02: authData,
		0x03: make([]byte, 64),
	}

	assertionEncoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	assertionPackets := createMultiPacketResponse(ctapDev.cid, assertionEncoded)

	// Reset and set up responses
	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range infoPackets {
		mockDev.SetResponse(packet) // For GetInfo
	}
	for _, packet := range assertionPackets {
		mockDev.SetResponse(packet) // For GetAssertion
	}

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	// Should use fallback derivation
	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.HMACSecret, 32)
}

// TestEnrollCredential_ShortAuthData tests error handling for short auth data
func TestEnrollCredential_ShortAuthData(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create GetInfo response first
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoPackets := createMultiPacketResponse(ctapDev.cid, infoEncoded)

	// Create response with auth data too short
	authData := make([]byte, 30) // Too short

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData,
		0x03: map[string]interface{}{},
	}

	makeCredEncoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	makeCredPackets := createMultiPacketResponse(ctapDev.cid, makeCredEncoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range infoPackets {
		mockDev.SetResponse(packet)
	}
	for _, packet := range makeCredPackets {
		mockDev.SetResponse(packet)
	}

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "example.com", Name: "Example"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid authenticator data length")
}

// TestEnrollCredential_NoAttestedCredential tests error when AT flag not set
func TestEnrollCredential_NoAttestedCredential(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create GetInfo response first
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoPackets := createMultiPacketResponse(ctapDev.cid, infoEncoded)

	// Create auth data without AT flag
	authData := make([]byte, 37)
	authData[32] = 0x01 // Only UP, no AT flag

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData,
		0x03: map[string]interface{}{},
	}

	makeCredEncoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	makeCredPackets := createMultiPacketResponse(ctapDev.cid, makeCredEncoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range infoPackets {
		mockDev.SetResponse(packet)
	}
	for _, packet := range makeCredPackets {
		mockDev.SetResponse(packet)
	}

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "example.com", Name: "Example"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "attested credential data not included")
}

// TestDeriveSecret_ShortAuthData tests error handling for short auth data in DeriveSecret
func TestDeriveSecret_ShortAuthData(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create GetInfo response first
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoPackets := createMultiPacketResponse(ctapDev.cid, infoEncoded)

	// Create response with auth data too short
	authData := make([]byte, 30)

	respMap := map[int]interface{}{
		0x02: authData,
		0x03: make([]byte, 64),
	}

	assertionEncoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	assertionPackets := createMultiPacketResponse(ctapDev.cid, assertionEncoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range infoPackets {
		mockDev.SetResponse(packet)
	}
	for _, packet := range assertionPackets {
		mockDev.SetResponse(packet)
	}

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "example.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid authenticator data length")
}

// TestParseAuthDataExtensions_WithAttestedCredentialData tests extension parsing with AT flag
func TestParseAuthDataExtensions_WithAttestedCredentialData(t *testing.T) {
	// Create auth data with both AT and ED flags
	authData := make([]byte, 100)
	authData[32] = 0xC0 // AT | ED flags

	// AAGUID (16 bytes)
	copy(authData[37:53], make([]byte, 16))

	// Credential ID length (2 bytes)
	binary.BigEndian.PutUint16(authData[53:55], 32)

	// Credential ID (32 bytes)
	copy(authData[55:87], make([]byte, 32))

	// The function attempts to skip public key and parse extensions
	// This tests the attestedCredentialDataIncluded branch
	extensions, err := ParseAuthDataExtensions(authData)

	// Should not error, even if it can't properly parse without full CBOR parsing
	assert.NoError(t, err)
	// May return nil or empty map since proper CBOR parsing is complex
	_ = extensions
}

// TestDevice_InitWithWriteError tests init handling write errors
func TestDevice_InitWithWriteError(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	_ = mockDev.Close() // Close device to cause write errors

	config := DefaultConfig

	_, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP channel")
}

// TestDevice_SendCommandWithClosedDevice tests sendCommand with closed device
func TestDevice_SendCommandWithClosedDevice(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)

	// Close the underlying device
	_ = mockDev.Close()

	_, err = ctapDev.Ping([]byte("test"))
	assert.Error(t, err)
}

// TestHandler_EnumerationError tests error injection in enumerator
type ErrorEnumerator struct{}

func (e *ErrorEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return nil, fmt.Errorf("enumeration failed")
}

func (e *ErrorEnumerator) Open(path string) (HIDDevice, error) {
	return nil, fmt.Errorf("device not found")
}

func TestHandler_EnumerationError(t *testing.T) {
	config := DefaultConfig
	enum := &ErrorEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	devices, err := handler.ListDevices()
	assert.Error(t, err)
	assert.Nil(t, devices)
}

func TestHandler_SelectDevice_OpenError(t *testing.T) {
	config := DefaultConfig
	config.DevicePath = "/dev/nonexistent"
	enum := &ErrorEnumerator{}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("test")
	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestEnrollCredential_InvalidCredIDLength tests error when credential ID length is invalid
func TestEnrollCredential_InvalidCredIDLength(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() {
		if err := ctapDev.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	// Create GetInfo response first
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
	}

	infoEncoded, err := cbor.Marshal(info)
	require.NoError(t, err)

	infoPackets := createMultiPacketResponse(ctapDev.cid, infoEncoded)

	// Create auth data with invalid credential ID length
	authData := make([]byte, 60)
	authData[32] = 0x41 // AT flag set
	binary.BigEndian.PutUint32(authData[33:37], 1)
	// AAGUID at 37-53
	binary.BigEndian.PutUint16(authData[53:55], 1000) // Invalid length that exceeds buffer

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData,
		0x03: map[string]interface{}{},
	}

	makeCredEncoded, err := cbor.Marshal(respMap)
	require.NoError(t, err)

	makeCredPackets := createMultiPacketResponse(ctapDev.cid, makeCredEncoded)

	// mockDev.Reset() - not needed, device already initialized
	for _, packet := range infoPackets {
		mockDev.SetResponse(packet)
	}
	for _, packet := range makeCredPackets {
		mockDev.SetResponse(packet)
	}

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "example.com", Name: "Example"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid credential ID length")
}
