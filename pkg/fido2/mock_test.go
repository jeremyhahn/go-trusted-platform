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
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// MockHIDDevice implements HIDDevice for testing
type MockHIDDevice struct {
	path         string
	vendorID     uint16
	productID    uint16
	manufacturer string
	product      string
	serialNumber string
	readBuf      *bytes.Buffer
	writeBuf     *bytes.Buffer
	closed       bool
	mu           sync.Mutex
	responses    [][]byte // Pre-configured responses
	writeCount   int
}

// NewMockHIDDevice creates a mock HID device
func NewMockHIDDevice(path string) *MockHIDDevice {
	return &MockHIDDevice{
		path:         path,
		vendorID:     0x1234,
		productID:    0x5678,
		manufacturer: "Mock Manufacturer",
		product:      "Mock FIDO2 Key",
		serialNumber: "123456",
		readBuf:      new(bytes.Buffer),
		writeBuf:     new(bytes.Buffer),
		responses:    make([][]byte, 0),
	}
}

func (m *MockHIDDevice) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, fmt.Errorf("device closed")
	}

	n, err := m.writeBuf.Write(data)
	m.writeCount++

	// Auto-generate response based on written command
	m.generateResponse(data)

	return n, err
}

func (m *MockHIDDevice) Read(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return 0, fmt.Errorf("device closed")
	}

	return m.readBuf.Read(data)
}

func (m *MockHIDDevice) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// Reset resets the mock device state so it can be reused.
// This is useful for testing multiple operations with the same device.
func (m *MockHIDDevice) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = false
	m.readBuf.Reset()
	m.writeBuf.Reset()
	m.writeCount = 0
	m.responses = make([][]byte, 0)
}

func (m *MockHIDDevice) Path() string         { return m.path }
func (m *MockHIDDevice) VendorID() uint16     { return m.vendorID }
func (m *MockHIDDevice) ProductID() uint16    { return m.productID }
func (m *MockHIDDevice) Manufacturer() string { return m.manufacturer }
func (m *MockHIDDevice) Product() string      { return m.product }
func (m *MockHIDDevice) SerialNumber() string { return m.serialNumber }

// SetResponse adds a pre-configured response
func (m *MockHIDDevice) SetResponse(response []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, response)
}

// SetMultiPacketResponse sets all packets for a multi-packet response
func (m *MockHIDDevice) SetMultiPacketResponse(packets [][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses = append(m.responses, packets...)
}

// generateResponse generates mock responses based on CTAPHID commands
func (m *MockHIDDevice) generateResponse(packet []byte) {
	if len(packet) < HIDPacketSize {
		return
	}

	// Check if we have pre-configured responses
	// Write ALL of them to readBuf at once for multi-packet responses
	if len(m.responses) > 0 {
		for len(m.responses) > 0 {
			resp := m.responses[0]
			m.responses = m.responses[1:]
			m.readBuf.Write(resp)
		}
		return
	}

	// Parse CTAPHID packet
	cid := binary.BigEndian.Uint32(packet[0:4])
	cmd := packet[4]

	switch cmd {
	case CTAPHID_INIT:
		m.generateInitResponse(cid, packet[7:])
	case CTAPHID_CBOR:
		m.generateCBORResponse(cid, packet[7:])
	case CTAPHID_PING:
		// Read payload length from bytes 5-7
		payloadLen := int(binary.BigEndian.Uint16(packet[5:7]))
		m.generatePingResponse(cid, packet[7:7+payloadLen])
	}
}

// generateInitResponse generates CTAPHID_INIT response
func (m *MockHIDDevice) generateInitResponse(reqCID uint32, nonce []byte) {
	response := make([]byte, HIDPacketSize)

	// Use broadcast CID for response
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17) // Response length

	// Echo nonce
	copy(response[7:15], nonce[:8])

	// New CID
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)

	// Protocol version
	response[19] = 2 // CTAP 2.0

	// Device version
	response[20] = 1 // Major
	response[21] = 0 // Minor
	response[22] = 0 // Build

	// Capabilities
	response[23] = 0x01 // CBOR capability

	m.readBuf.Write(response)
}

// generateCBORResponse generates CTAPHID_CBOR response
func (m *MockHIDDevice) generateCBORResponse(cid uint32, payload []byte) {
	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		m.generateGetInfoResponse(cid)
	case CmdMakeCredential:
		m.generateMakeCredentialResponse(cid, payload[1:])
	case CmdGetAssertion:
		m.generateGetAssertionResponse(cid, payload[1:])
	}
}

// writeHIDPackets writes CBOR payload as HID packets
func (m *MockHIDDevice) writeHIDPackets(cid uint32, payload []byte) {
	// Add status byte to payload
	fullPayload := append([]byte{StatusOK}, payload...)
	payloadLen := len(fullPayload)

	// First packet
	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7
	if payloadLen <= firstPayloadSize {
		// Single packet response
		copy(firstPacket[7:], fullPayload)
		m.readBuf.Write(firstPacket)
		return
	}

	// Multi-packet response
	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	m.readBuf.Write(firstPacket)

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
		m.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

// generateGetInfoResponse generates GetInfo response
func (m *MockHIDDevice) generateGetInfoResponse(cid uint32) {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0", "U2F_V2"}, // versions
		0x02: []string{"hmac-secret"},        // extensions
		0x03: make([]byte, 16),               // aaguid
		0x04: map[string]bool{ // options
			"rk":   true,
			"up":   true,
			"plat": false,
		},
		0x05: uint64(1200), // maxMsgSize
		0x06: []uint64{1},  // pinProtocols
	}

	encoded, _ := cbor.Marshal(info)
	m.writeHIDPackets(cid, encoded)
}

// generateMakeCredentialResponse generates MakeCredential response
func (m *MockHIDDevice) generateMakeCredentialResponse(cid uint32, reqData []byte) {
	// Generate mock authenticator data
	authData := make([]byte, 37+16+2+32) // Base + AAGUID + credIDLen + credID

	// RP ID hash (32 bytes)
	copy(authData[0:32], make([]byte, 32))

	// Flags: UP + AT
	authData[32] = 0x41

	// Sign counter
	binary.BigEndian.PutUint32(authData[33:37], 1)

	// AAGUID
	copy(authData[37:53], make([]byte, 16))

	// Credential ID length
	binary.BigEndian.PutUint16(authData[53:55], 32)

	// Credential ID
	credID := make([]byte, 32)
	for i := range credID {
		credID[i] = byte(i)
	}
	copy(authData[55:87], credID)

	// Build response
	respMap := map[int]interface{}{
		0x01: "none",                   // fmt
		0x02: authData,                 // authData
		0x03: map[string]interface{}{}, // attStmt
	}

	encoded, _ := cbor.Marshal(respMap)
	m.writeHIDPackets(cid, encoded)
}

// generateGetAssertionResponse generates GetAssertion response
func (m *MockHIDDevice) generateGetAssertionResponse(cid uint32, reqData []byte) {
	// Generate mock authenticator data with HMAC-secret extension
	authData := make([]byte, 37+32) // Base + HMAC output

	// RP ID hash
	copy(authData[0:32], make([]byte, 32))

	// Flags: UP + ED (extension data)
	authData[32] = 0x81

	// Sign counter
	binary.BigEndian.PutUint32(authData[33:37], 2)

	// HMAC-secret output (32 bytes)
	hmacOutput := make([]byte, 32)
	for i := range hmacOutput {
		hmacOutput[i] = byte(i + 100)
	}
	copy(authData[37:], hmacOutput)

	// Build response
	respMap := map[int]interface{}{
		0x01: map[string]interface{}{ // credential
			"type": "public-key",
			"id":   make([]byte, 32),
		},
		0x02: authData,         // authData
		0x03: make([]byte, 64), // signature
	}

	encoded, _ := cbor.Marshal(respMap)
	m.writeHIDPackets(cid, encoded)
}

// generatePingResponse generates CTAPHID_PING response
func (m *MockHIDDevice) generatePingResponse(cid uint32, data []byte) {
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], cid)
	response[4] = CTAPHID_PING
	binary.BigEndian.PutUint16(response[5:7], uint16(len(data)))
	copy(response[7:], data)
	m.readBuf.Write(response)
}

// MockHIDDeviceEnumerator implements HIDDeviceEnumerator for testing
type MockHIDDeviceEnumerator struct {
	devices map[string]*MockHIDDevice
	mu      sync.Mutex
}

// NewMockHIDDeviceEnumerator creates a mock device enumerator
func NewMockHIDDeviceEnumerator() *MockHIDDeviceEnumerator {
	return &MockHIDDeviceEnumerator{
		devices: make(map[string]*MockHIDDevice),
	}
}

func (e *MockHIDDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var devices []HIDDevice
	for _, dev := range e.devices {
		// Filter by vendor/product ID if specified
		if vendorID != 0 && dev.VendorID() != vendorID {
			continue
		}
		if productID != 0 && dev.ProductID() != productID {
			continue
		}
		// Reset the device so it can be reused
		dev.Reset()
		devices = append(devices, dev)
	}
	return devices, nil
}

func (e *MockHIDDeviceEnumerator) Open(path string) (HIDDevice, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	dev, ok := e.devices[path]
	if !ok {
		return nil, fmt.Errorf("device not found: %s", path)
	}
	return dev, nil
}

// AddDevice adds a mock device to the enumerator
func (e *MockHIDDeviceEnumerator) AddDevice(device *MockHIDDevice) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.devices[device.Path()] = device
}

// RemoveDevice removes a device from the enumerator
func (e *MockHIDDeviceEnumerator) RemoveDevice(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.devices, path)
}
