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

//go:build linux

package ipxe

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCalculateUDPChecksum_OddPayload tests checksum calculation with odd
// length payload to ensure the padding logic is covered.
func TestCalculateUDPChecksum_OddPayload(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	udpHeader := []byte{
		0x00, 0x43, // Source port: 67
		0x00, 0x44, // Dest port: 68
		0x00, 0x0D, // Length: 13 (8 header + 5 payload)
		0x00, 0x00, // Checksum: 0
	}

	// Odd length payload - should trigger the padding branch
	payload := []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F} // "Hello" - 5 bytes

	result := calculateUDPChecksum(srcIP, dstIP, udpHeader, payload)

	// Result should be non-zero
	if result == 0 {
		t.Error("checksum should not be zero")
	}
}

// TestCalculateUDPChecksum_EvenPayload tests checksum calculation with even
// length payload to ensure no padding is applied.
func TestCalculateUDPChecksum_EvenPayload(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	udpHeader := []byte{
		0x00, 0x43, // Source port: 67
		0x00, 0x44, // Dest port: 68
		0x00, 0x0C, // Length: 12 (8 header + 4 payload)
		0x00, 0x00, // Checksum: 0
	}

	// Even length payload
	payload := []byte{0x74, 0x65, 0x73, 0x74} // "test" - 4 bytes

	result := calculateUDPChecksum(srcIP, dstIP, udpHeader, payload)

	// Result should be non-zero
	if result == 0 {
		t.Error("checksum should not be zero")
	}
}

// TestCalculateUDPChecksum_CarryBits tests that carry bit folding is correct.
func TestCalculateUDPChecksum_CarryBits(t *testing.T) {
	// Use values that will cause carry bits
	srcIP := net.ParseIP("255.255.255.255")
	dstIP := net.ParseIP("255.255.255.255")
	udpHeader := []byte{
		0xFF, 0xFF, // Source port: 65535
		0xFF, 0xFF, // Dest port: 65535
		0xFF, 0xFF, // Length: 65535 (invalid but tests carry)
		0x00, 0x00, // Checksum: 0
	}
	payload := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	result := calculateUDPChecksum(srcIP, dstIP, udpHeader, payload)

	// Result should handle overflow correctly
	if result == 0 {
		t.Error("checksum should not be zero even with max values")
	}
}

// TestBuildUDP4Packet_VerifyChecksums verifies that both IP and UDP checksums
// are correctly calculated in the built packet.
func TestBuildUDP4Packet_VerifyChecksums(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	payload := []byte("test payload data for checksum verification")

	packet := buildUDP4Packet(srcIP, dstIP, 67, 68, payload)

	// Verify IP checksum
	t.Run("IP checksum verification", func(t *testing.T) {
		// Sum entire IP header including checksum should be 0xFFFF
		var sum uint32
		ipHeader := packet[:ipHeaderLen]
		for i := 0; i < ipHeaderLen; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ipHeader[i : i+2]))
		}
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}

		if sum != 0xFFFF {
			t.Errorf("IP checksum verification failed: sum = 0x%04X, want 0xFFFF", sum)
		}
	})

	// Verify UDP checksum
	t.Run("UDP checksum verification", func(t *testing.T) {
		udpHeader := packet[ipHeaderLen : ipHeaderLen+udpHeaderLen]
		actualPayload := packet[ipHeaderLen+udpHeaderLen:]

		// Calculate pseudo-header + UDP checksum
		var sum uint32

		// Pseudo-header
		srcIP4 := srcIP.To4()
		dstIP4 := dstIP.To4()
		sum += uint32(binary.BigEndian.Uint16(srcIP4[0:2]))
		sum += uint32(binary.BigEndian.Uint16(srcIP4[2:4]))
		sum += uint32(binary.BigEndian.Uint16(dstIP4[0:2]))
		sum += uint32(binary.BigEndian.Uint16(dstIP4[2:4]))
		sum += uint32(unix.IPPROTO_UDP)
		sum += uint32(len(udpHeader) + len(actualPayload))

		// UDP header (including checksum)
		for i := 0; i < udpHeaderLen; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(udpHeader[i : i+2]))
		}

		// Payload
		for i := 0; i < len(actualPayload); i += 2 {
			if i+1 < len(actualPayload) {
				sum += uint32(binary.BigEndian.Uint16(actualPayload[i : i+2]))
			} else {
				sum += uint32(actualPayload[i]) << 8
			}
		}

		// Fold carry
		for sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}

		if sum != 0xFFFF {
			t.Errorf("UDP checksum verification failed: sum = 0x%04X, want 0xFFFF", sum)
		}
	})
}

// TestBuildUDP4Packet_OddPayload tests packet building with odd length payload.
func TestBuildUDP4Packet_OddPayload(t *testing.T) {
	srcIP := net.ParseIP("10.0.0.1")
	dstIP := net.ParseIP("10.0.0.2")
	// Odd length payload to test the padding branch in checksum
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05} // 5 bytes

	packet := buildUDP4Packet(srcIP, dstIP, 67, 68, payload)

	// Verify length
	expectedLen := ipHeaderLen + udpHeaderLen + len(payload)
	if len(packet) != expectedLen {
		t.Errorf("packet length = %d, want %d", len(packet), expectedLen)
	}

	// Verify payload was copied correctly
	for i, b := range payload {
		if packet[ipHeaderLen+udpHeaderLen+i] != b {
			t.Errorf("payload[%d] = 0x%02X, want 0x%02X", i, packet[ipHeaderLen+udpHeaderLen+i], b)
		}
	}
}

// TestIp4ToUint32_IPv4Mapped tests conversion of IPv4-mapped IPv6 addresses.
func TestIp4ToUint32_IPv4Mapped(t *testing.T) {
	// IPv4-mapped IPv6 addresses should convert correctly
	ip := net.ParseIP("::ffff:192.168.1.1")
	result := ip4ToUint32(ip)

	expected := uint32(0xC0A80101) // 192.168.1.1
	if result != expected {
		t.Errorf("ip4ToUint32(::ffff:192.168.1.1) = 0x%08X, want 0x%08X", result, expected)
	}
}

// TestCalculateIPChecksum_SingleWord tests checksum with minimal header.
func TestCalculateIPChecksum_SingleWord(t *testing.T) {
	// Test with a simple case
	header := []byte{0x45, 0x00}
	result := calculateIPChecksum(header)

	// Single word: 0x4500, complement: ~0x4500 = 0xBAFF
	expected := uint16(0xBAFF)
	if result != expected {
		t.Errorf("calculateIPChecksum(%v) = 0x%04X, want 0x%04X", header, result, expected)
	}
}

// TestNewServerRawConn_ValidPort tests port boundary validation.
func TestNewServerRawConn_ValidPort(t *testing.T) {
	// Test valid port at boundary (65535)
	_, err := NewServerRawConn("lo", net.ParseIP("127.0.0.1"), 65535)
	// Will fail due to permissions but should pass validation
	if err != nil && err == ErrInvalidPort {
		t.Errorf("port 65535 should be valid, got ErrInvalidPort")
	}

	// Test valid port at boundary (1)
	_, err = NewServerRawConn("lo", net.ParseIP("127.0.0.1"), 1)
	// Will fail due to permissions but should pass validation
	if err != nil && err == ErrInvalidPort {
		t.Errorf("port 1 should be valid, got ErrInvalidPort")
	}
}

// TestCalculateUDPChecksum_EmptyPayload tests checksum with empty payload.
func TestCalculateUDPChecksum_EmptyPayload(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("192.168.1.2")
	udpHeader := []byte{
		0x00, 0x43, // Source port: 67
		0x00, 0x44, // Dest port: 68
		0x00, 0x08, // Length: 8 (header only)
		0x00, 0x00, // Checksum: 0
	}

	// Empty payload
	payload := []byte{}

	result := calculateUDPChecksum(srcIP, dstIP, udpHeader, payload)

	// Result should be non-zero
	if result == 0 {
		t.Error("checksum should not be zero even with empty payload")
	}

	// Verify by recalculating
	udpWithChecksum := make([]byte, len(udpHeader))
	copy(udpWithChecksum, udpHeader)
	binary.BigEndian.PutUint16(udpWithChecksum[6:8], result)

	// Recalculate sum
	var sum uint32
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()
	sum += uint32(binary.BigEndian.Uint16(srcIP4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP4[2:4]))
	sum += uint32(unix.IPPROTO_UDP)
	sum += uint32(len(udpHeader))

	for i := 0; i < len(udpWithChecksum); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpWithChecksum[i : i+2]))
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	if sum != 0xFFFF {
		t.Errorf("checksum verification failed: sum = 0x%04X, want 0xFFFF", sum)
	}
}

// TestBuildUDP4Packet_EmptyPayload tests packet building with empty payload.
func TestBuildUDP4Packet_EmptyPayload(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1")
	dstIP := net.ParseIP("255.255.255.255")

	packet := buildUDP4Packet(srcIP, dstIP, 67, 68, []byte{})

	// Verify length
	expectedLen := ipHeaderLen + udpHeaderLen
	if len(packet) != expectedLen {
		t.Errorf("packet length = %d, want %d", len(packet), expectedLen)
	}

	// Verify UDP length in header
	udpLen := binary.BigEndian.Uint16(packet[ipHeaderLen+4 : ipHeaderLen+6])
	if udpLen != udpHeaderLen {
		t.Errorf("UDP length = %d, want %d", udpLen, udpHeaderLen)
	}
}

// TestCalculateIPChecksum_CarryFolding tests that carry bits are properly folded.
func TestCalculateIPChecksum_CarryFolding(t *testing.T) {
	// Create a header that will generate carries
	header := []byte{
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0x00, 0x00, // Checksum field zeroed
		0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF,
	}

	result := calculateIPChecksum(header)

	// Verify by adding result back
	header[10] = byte(result >> 8)
	header[11] = byte(result)

	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	if sum != 0xFFFF {
		t.Errorf("checksum verification failed: sum = 0x%04X, want 0xFFFF", sum)
	}
}
