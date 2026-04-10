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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// HIDDevice interface for USB HID communication
// This allows for easy mocking in tests
type HIDDevice interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
	Path() string
	ProductID() uint16
	VendorID() uint16
	Product() string
	Manufacturer() string
	SerialNumber() string
}

// HIDDeviceEnumerator interface for device enumeration
type HIDDeviceEnumerator interface {
	Enumerate(vendorID, productID uint16) ([]HIDDevice, error)
	Open(path string) (HIDDevice, error)
}

// CTAPHID protocol constants
const (
	// FIDO Alliance Vendor ID
	FIDOAllianceVID = 0xF1D0

	// HID Report descriptor usage page
	HIDUsagePage = 0xF1D0
	HIDUsage     = 0x01

	// CTAPHID Command codes
	CTAPHID_PING      = 0x81
	CTAPHID_MSG       = 0x83
	CTAPHID_LOCK      = 0x84
	CTAPHID_INIT      = 0x86
	CTAPHID_WINK      = 0x88
	CTAPHID_CBOR      = 0x90
	CTAPHID_CANCEL    = 0x91
	CTAPHID_KEEPALIVE = 0xBB
	CTAPHID_ERROR     = 0xBF

	// CTAPHID constants
	HIDPacketSize = 64
	InitNonceSize = 8
	CIDSize       = 4
	CIDBroadcast  = 0xFFFFFFFF
)

// CTAPHIDDevice wraps a HID device with CTAP protocol handling
type CTAPHIDDevice struct {
	device HIDDevice
	cid    uint32
	config *Config
}

// NewCTAPHIDDevice creates a new CTAP HID device
func NewCTAPHIDDevice(device HIDDevice, config *Config) (*CTAPHIDDevice, error) {
	ctapDev := &CTAPHIDDevice{
		device: device,
		config: config,
	}

	// Initialize the channel
	if err := ctapDev.init(); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("failed to initialize CTAP channel: %w", err)
	}

	return ctapDev, nil
}

// init performs CTAPHID_INIT to get a channel ID
func (d *CTAPHIDDevice) init() error {
	nonce := make([]byte, InitNonceSize)
	// Use a simple timestamp-based nonce for initialization
	binary.BigEndian.PutUint64(nonce, uint64(time.Now().UnixNano()))

	resp, err := d.sendCommand(CIDBroadcast, CTAPHID_INIT, nonce, d.config.Timeout)
	if err != nil {
		return fmt.Errorf("CTAPHID_INIT failed: %w", err)
	}

	if len(resp) < 17 {
		return fmt.Errorf("invalid CTAPHID_INIT response length: %d", len(resp))
	}

	// Verify nonce echo
	if !bytes.Equal(resp[:8], nonce) {
		return fmt.Errorf("nonce mismatch in CTAPHID_INIT response")
	}

	// Extract channel ID
	d.cid = binary.BigEndian.Uint32(resp[8:12])

	return nil
}

// sendCommand sends a CTAPHID command and waits for response
func (d *CTAPHIDDevice) sendCommand(cid uint32, cmd byte, data []byte, timeout time.Duration) ([]byte, error) {
	// Create HID packets
	packets := d.createPackets(cid, cmd, data)

	// Send all packets
	for _, packet := range packets {
		if _, err := d.device.Write(packet); err != nil {
			return nil, fmt.Errorf("failed to write HID packet: %w", err)
		}
	}

	// Read response with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return d.readResponse(ctx, cid)
}

// createPackets creates CTAPHID packets from payload
func (d *CTAPHIDDevice) createPackets(cid uint32, cmd byte, data []byte) [][]byte {
	var packets [][]byte
	dataLen := len(data)

	// First packet (initialization packet)
	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = cmd
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(dataLen))

	// First packet payload size: 64 - 7 = 57 bytes
	firstPayloadSize := HIDPacketSize - 7
	if dataLen <= firstPayloadSize {
		copy(firstPacket[7:], data)
		return [][]byte{firstPacket}
	}

	copy(firstPacket[7:], data[:firstPayloadSize])
	packets = append(packets, firstPacket)
	data = data[firstPayloadSize:]

	// Continuation packets
	seq := byte(0)
	for len(data) > 0 {
		packet := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(packet[0:4], cid)
		packet[4] = seq

		// Continuation packet payload size: 64 - 5 = 59 bytes
		contPayloadSize := HIDPacketSize - 5
		n := contPayloadSize
		if len(data) < n {
			n = len(data)
		}
		copy(packet[5:], data[:n])

		packets = append(packets, packet)
		data = data[n:]
		seq++
	}

	return packets
}

// readResponse reads CTAPHID response packets
func (d *CTAPHIDDevice) readResponse(ctx context.Context, expectedCID uint32) ([]byte, error) {
	done := make(chan struct {
		data []byte
		err  error
	}, 1)

	go func() {
		data, err := d.readResponseSync(expectedCID)
		done <- struct {
			data []byte
			err  error
		}{data, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ErrOperationTimeout
	case result := <-done:
		return result.data, result.err
	}
}

// readResponseSync synchronously reads response packets
func (d *CTAPHIDDevice) readResponseSync(expectedCID uint32) ([]byte, error) {
	// Read first packet
	packet := make([]byte, HIDPacketSize)
	n, err := d.device.Read(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to read first packet: %w", err)
	}
	if n != HIDPacketSize {
		return nil, fmt.Errorf("incomplete first packet: got %d bytes", n)
	}

	// Parse first packet
	cid := binary.BigEndian.Uint32(packet[0:4])
	if cid != expectedCID {
		return nil, fmt.Errorf("channel ID mismatch: expected 0x%08X, got 0x%08X", expectedCID, cid)
	}

	cmd := packet[4]

	// Handle keepalive messages
	if cmd == CTAPHID_KEEPALIVE {
		// Status byte in packet[7]
		// Continue waiting for actual response
		return d.readResponseSync(expectedCID)
	}

	// Handle error responses
	if cmd == CTAPHID_ERROR {
		if n >= 8 {
			errCode := packet[7]
			return nil, fmt.Errorf("CTAPHID error: 0x%02X", errCode)
		}
		return nil, ErrDeviceError
	}

	// Get payload length
	payloadLen := int(binary.BigEndian.Uint16(packet[5:7]))
	if payloadLen == 0 {
		return []byte{}, nil
	}

	// Read first packet payload
	firstPayloadSize := HIDPacketSize - 7
	var response []byte
	if payloadLen <= firstPayloadSize {
		response = make([]byte, payloadLen)
		copy(response, packet[7:7+payloadLen])
		return response, nil
	}

	response = make([]byte, payloadLen)
	copy(response, packet[7:])
	bytesRead := firstPayloadSize

	// Read continuation packets
	seq := byte(0)
	for bytesRead < payloadLen {
		packet := make([]byte, HIDPacketSize)
		n, err := d.device.Read(packet)
		if err != nil {
			return nil, fmt.Errorf("failed to read continuation packet: %w", err)
		}
		if n != HIDPacketSize {
			return nil, fmt.Errorf("incomplete continuation packet: got %d bytes", n)
		}

		// Verify CID and sequence
		packetCID := binary.BigEndian.Uint32(packet[0:4])
		if packetCID != expectedCID {
			return nil, fmt.Errorf("channel ID mismatch in continuation")
		}

		packetSeq := packet[4]
		if packetSeq != seq {
			return nil, fmt.Errorf("sequence mismatch: expected %d, got %d", seq, packetSeq)
		}

		// Copy payload
		contPayloadSize := HIDPacketSize - 5
		remaining := payloadLen - bytesRead
		n = contPayloadSize
		if remaining < n {
			n = remaining
		}
		copy(response[bytesRead:], packet[5:5+n])
		bytesRead += n
		seq++
	}

	return response, nil
}

// SendCBOR sends a CTAP2 CBOR command
func (d *CTAPHIDDevice) SendCBOR(cmd byte, request interface{}) ([]byte, error) {
	var payload []byte

	// First byte is the CTAP command
	payload = append(payload, cmd)

	// Encode request as CBOR if provided
	if request != nil {
		enc, err := cbor.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("failed to encode CBOR request: %w", err)
		}
		payload = append(payload, enc...)
	}

	// Send CTAPHID_CBOR command
	resp, err := d.sendCommand(d.cid, CTAPHID_CBOR, payload, d.config.Timeout)
	if err != nil {
		return nil, err
	}

	if len(resp) == 0 {
		return nil, fmt.Errorf("empty CBOR response")
	}

	// First byte is status code
	status := resp[0]
	if status != StatusOK {
		return nil, d.handleCTAPError(status)
	}

	// Return CBOR payload (everything after status byte)
	if len(resp) == 1 {
		return []byte{}, nil
	}

	return resp[1:], nil
}

// handleCTAPError converts CTAP status codes to errors
func (d *CTAPHIDDevice) handleCTAPError(status byte) error {
	switch status {
	case StatusInvalidCommand:
		return fmt.Errorf("invalid CTAP command")
	case StatusInvalidParameter:
		return fmt.Errorf("invalid parameter")
	case StatusInvalidLength:
		return fmt.Errorf("invalid length")
	case StatusInvalidSeq:
		return fmt.Errorf("invalid sequence")
	case StatusTimeout:
		return ErrOperationTimeout
	case StatusChannelBusy:
		return fmt.Errorf("channel busy")
	case StatusInvalidCBOR:
		return ErrInvalidCBOR
	case StatusUnsupportedExtension:
		return ErrUnsupportedExtension
	case StatusCredentialExcluded:
		return fmt.Errorf("credential excluded")
	case StatusUserActionPending:
		return ErrUserPresenceRequired
	case StatusOperationDenied:
		return fmt.Errorf("operation denied")
	case StatusNoCredentials:
		return ErrCredentialNotFound
	case StatusUserActionTimeout:
		return ErrOperationTimeout
	case StatusNotAllowed:
		return fmt.Errorf("operation not allowed")
	case StatusPINInvalid:
		return ErrInvalidPIN
	case StatusPINBlocked:
		return ErrPINBlocked
	case StatusPINRequired:
		return ErrPINRequired
	case StatusUPRequired:
		return ErrUserPresenceRequired
	case StatusUVBlocked:
		return fmt.Errorf("user verification blocked")
	default:
		return fmt.Errorf("CTAP error: 0x%02X", status)
	}
}

// Ping sends a CTAPHID_PING command
func (d *CTAPHIDDevice) Ping(data []byte) ([]byte, error) {
	return d.sendCommand(d.cid, CTAPHID_PING, data, d.config.Timeout)
}

// Close closes the device
func (d *CTAPHIDDevice) Close() error {
	return d.device.Close()
}

// Info returns device information
func (d *CTAPHIDDevice) Info() Device {
	return Device{
		Path:         d.device.Path(),
		VendorID:     d.device.VendorID(),
		ProductID:    d.device.ProductID(),
		Manufacturer: d.device.Manufacturer(),
		Product:      d.device.Product(),
		SerialNumber: d.device.SerialNumber(),
		Transport:    "usb",
	}
}
