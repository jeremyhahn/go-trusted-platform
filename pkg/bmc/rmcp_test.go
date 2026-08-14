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

package bmc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"log/slog"
	"testing"
)

// --- IPMI Checksum Tests ---

func TestIPMIChecksum(t *testing.T) {
	t.Run("zero data", func(t *testing.T) {
		result := ipmiChecksum([]byte{0x00, 0x00})
		if result != 0x00 {
			t.Errorf("checksum = 0x%02x, want 0x00", result)
		}
	})

	t.Run("BMC address and netfn", func(t *testing.T) {
		// rsAddr=0x20, netFn/LUN=0x18 (App, LUN=0)
		// Sum = 0x20 + 0x18 = 0x38, checksum = -0x38 = 0xC8
		data := []byte{0x20, 0x18}
		result := ipmiChecksum(data)
		expected := byte(0xC8)
		if result != expected {
			t.Errorf("checksum = 0x%02x, want 0x%02x", result, expected)
		}
	})

	t.Run("known IPMI sequence", func(t *testing.T) {
		// Test with a known sequence: 0x81 + 0x00 + 0x38 = 0xB9
		// checksum = -0xB9 = 0x47
		data := []byte{0x81, 0x00, 0x38}
		result := ipmiChecksum(data)
		expected := byte(0x47)
		if result != expected {
			t.Errorf("checksum = 0x%02x, want 0x%02x", result, expected)
		}
	})
}

func TestIPMIChecksum_SingleByte(t *testing.T) {
	// Single byte checksum: -byte value
	result := ipmiChecksum([]byte{0x01})
	if result != 0xFF {
		t.Errorf("checksum = 0x%02x, want 0xFF", result)
	}
}

// --- Build IPMI Message Tests ---

func TestBuildIPMIMessage(t *testing.T) {
	t.Run("chassis status no data", func(t *testing.T) {
		msg := buildIPMIMessage(netFnChassis, cmdChassisStatus, nil)

		// Expected: rsAddr(0x20) + netFn/LUN(0x00) + headerCksum +
		//           rqAddr(0x81) + rqSeq/rqLUN(0x00) + cmd(0x01) + dataCksum
		if len(msg) != 7 {
			t.Fatalf("len = %d, want 7", len(msg))
		}
		if msg[0] != 0x20 {
			t.Errorf("rsAddr = 0x%02x, want 0x20", msg[0])
		}
		// netFnChassis shifted left two bits is 0x00.
		if msg[1] != 0x00 {
			t.Errorf("netFn/LUN = 0x%02x, want 0x00", msg[1])
		}
		// Header checksum: -(0x20 + 0x00) = 0xE0
		if msg[2] != 0xE0 {
			t.Errorf("header checksum = 0x%02x, want 0xE0", msg[2])
		}
		if msg[3] != 0x81 {
			t.Errorf("rqAddr = 0x%02x, want 0x81", msg[3])
		}
		if msg[5] != cmdChassisStatus {
			t.Errorf("cmd = 0x%02x, want 0x%02x", msg[5], cmdChassisStatus)
		}
		// Data checksum over rqAddr+rqSeq+cmd = -(0x81 + 0x00 + 0x01) = 0x7E
		if msg[6] != 0x7E {
			t.Errorf("data checksum = 0x%02x, want 0x7E", msg[6])
		}
	})

	t.Run("chassis control with data", func(t *testing.T) {
		msg := buildIPMIMessage(netFnChassis, cmdChassisControl, []byte{chassisControlPowerUp})

		if len(msg) != 8 { // 7 + 1 data byte
			t.Fatalf("len = %d, want 8", len(msg))
		}
		if msg[5] != cmdChassisControl {
			t.Errorf("cmd = 0x%02x, want 0x%02x", msg[5], cmdChassisControl)
		}
		if msg[6] != chassisControlPowerUp {
			t.Errorf("data = 0x%02x, want 0x%02x", msg[6], chassisControlPowerUp)
		}
	})

	t.Run("app netfn", func(t *testing.T) {
		msg := buildIPMIMessage(netFnApp, cmdGetDeviceID, nil)
		// netFnApp is 0x06, which becomes 0x18 once shifted left two bits.
		if msg[1] != 0x18 {
			t.Errorf("netFn/LUN = 0x%02x, want 0x18", msg[1])
		}
	})
}

func TestBuildIPMIMessage_StorageNetFn(t *testing.T) {
	msg := buildIPMIMessage(netFnStorage, cmdGetSDRRepositoryInfo, nil)
	// netFnStorage is 0x0A, which becomes 0x28 once shifted left two bits.
	if msg[1] != 0x28 {
		t.Errorf("netFn/LUN = 0x%02x, want 0x28", msg[1])
	}
}

// --- RMCP Packet Building Tests ---

func TestBuildRMCPPlusUnauthPacket(t *testing.T) {
	t.Run("open session request", func(t *testing.T) {
		payload := []byte{0x01, 0x02, 0x03, 0x04}
		packet := buildRMCPPlusUnauthPacket(payloadTypeOpenSessionReq, 0, 0, payload)

		// RMCP header
		if packet[0] != rmcpVersion {
			t.Errorf("RMCP version = 0x%02x, want 0x%02x", packet[0], rmcpVersion)
		}
		if packet[1] != rmcpReserved {
			t.Errorf("reserved = 0x%02x, want 0x%02x", packet[1], rmcpReserved)
		}
		if packet[2] != rmcpSeqNum {
			t.Errorf("seq = 0x%02x, want 0x%02x", packet[2], rmcpSeqNum)
		}
		if packet[3] != rmcpClassIPMI {
			t.Errorf("class = 0x%02x, want 0x%02x", packet[3], rmcpClassIPMI)
		}

		// Auth type and payload type
		if packet[4] != authTypeRMCPPlus {
			t.Errorf("auth type = 0x%02x, want 0x%02x", packet[4], authTypeRMCPPlus)
		}
		if packet[5] != payloadTypeOpenSessionReq {
			t.Errorf("payload type = 0x%02x, want 0x%02x", packet[5], payloadTypeOpenSessionReq)
		}

		// Session ID = 0
		sid := binary.LittleEndian.Uint32(packet[6:10])
		if sid != 0 {
			t.Errorf("session ID = %d, want 0", sid)
		}

		// Sequence = 0
		seq := binary.LittleEndian.Uint32(packet[10:14])
		if seq != 0 {
			t.Errorf("sequence = %d, want 0", seq)
		}

		// Payload length
		plen := binary.LittleEndian.Uint16(packet[14:16])
		if plen != 4 {
			t.Errorf("payload length = %d, want 4", plen)
		}

		// Payload data
		if !bytes.Equal(packet[16:20], payload) {
			t.Errorf("payload = %v, want %v", packet[16:20], payload)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		packet := buildRMCPPlusUnauthPacket(payloadTypeRAKP1, 0x12345678, 1, nil)
		if len(packet) != 16 {
			t.Fatalf("len = %d, want 16", len(packet))
		}
		sid := binary.LittleEndian.Uint32(packet[6:10])
		if sid != 0x12345678 {
			t.Errorf("session ID = 0x%08x, want 0x12345678", sid)
		}
		plen := binary.LittleEndian.Uint16(packet[14:16])
		if plen != 0 {
			t.Errorf("payload length = %d, want 0", plen)
		}
	})
}

func TestBuildRMCPPlusUnauthPacket_RAKP3(t *testing.T) {
	payload := make([]byte, 28)
	payload[0] = 0x00 // tag
	packet := buildRMCPPlusUnauthPacket(payloadTypeRAKP3, 0, 0, payload)
	if packet[5] != payloadTypeRAKP3 {
		t.Errorf("payload type = 0x%02x, want 0x%02x", packet[5], payloadTypeRAKP3)
	}
}

// --- Extract Unauth Payload Tests ---

func TestExtractUnauthPayload(t *testing.T) {
	t.Run("valid response", func(t *testing.T) {
		payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
		packet := buildRMCPPlusUnauthPacket(payloadTypeOpenSessionResp, 0, 0, payload)

		extracted, err := extractUnauthPayload(packet, payloadTypeOpenSessionResp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(extracted, payload) {
			t.Errorf("extracted = %v, want %v", extracted, payload)
		}
	})

	t.Run("wrong payload type", func(t *testing.T) {
		packet := buildRMCPPlusUnauthPacket(payloadTypeOpenSessionResp, 0, 0, []byte{0x01})
		_, err := extractUnauthPayload(packet, payloadTypeRAKP2)
		if err == nil {
			t.Fatal("expected error for wrong payload type")
		}
	})

	t.Run("packet too short", func(t *testing.T) {
		_, err := extractUnauthPayload([]byte{0x06, 0x00}, payloadTypeOpenSessionResp)
		if err == nil {
			t.Fatal("expected error for short packet")
		}
		var target ErrPacketTooShort
		if _, ok := err.(ErrPacketTooShort); !ok {
			t.Errorf("expected ErrPacketTooShort, got %T", target)
		}
	})

	t.Run("invalid RMCP version", func(t *testing.T) {
		packet := make([]byte, 20)
		packet[0] = 0x05 // Wrong version
		packet[3] = rmcpClassIPMI
		_, err := extractUnauthPayload(packet, payloadTypeOpenSessionResp)
		if err == nil {
			t.Fatal("expected error for invalid RMCP version")
		}
	})

	t.Run("payload length exceeds packet", func(t *testing.T) {
		packet := buildRMCPPlusUnauthPacket(payloadTypeOpenSessionResp, 0, 0, []byte{0x01, 0x02})
		// Corrupt payload length to be too large.
		binary.LittleEndian.PutUint16(packet[14:16], 100)
		_, err := extractUnauthPayload(packet, payloadTypeOpenSessionResp)
		if err == nil {
			t.Fatal("expected error for payload length exceeding packet")
		}
	})
}

// --- Key Derivation Tests ---

func TestDeriveKeys_HMACSHA1(t *testing.T) {
	s := &rmcpSession{
		authAlgo:      authAlgoHMACSHA1,
		integrityAlgo: integrityAlgoHMACSHA1_96,
		cryptoAlgo:    cryptoAlgoAESCBC128,
		password:      "test_password",
		username:      "admin",
		privilege:     privilegeAdministrator,
	}

	// Set deterministic values for testing.
	for i := range s.clientRand {
		s.clientRand[i] = byte(i)
	}
	for i := range s.bmcRand {
		s.bmcRand[i] = byte(i + 0x10)
	}

	if err := s.deriveKeys(); err != nil {
		t.Fatalf("deriveKeys() error: %v", err)
	}

	// Verify SIK is computed correctly.
	// SIK = HMAC-SHA1(password, clientRand || bmcRand || privilege || userLen || username)
	sikData := make([]byte, 0, 34+len("admin"))
	sikData = append(sikData, s.clientRand[:]...)
	sikData = append(sikData, s.bmcRand[:]...)
	sikData = append(sikData, s.privilege)
	sikData = append(sikData, byte(len("admin")))
	sikData = append(sikData, []byte("admin")...)

	mac := hmac.New(sha1.New, []byte("test_password"))
	mac.Write(sikData)
	expectedSIK := mac.Sum(nil)

	if !bytes.Equal(s.sik, expectedSIK) {
		t.Errorf("SIK mismatch:\n  got:  %x\n  want: %x", s.sik, expectedSIK)
	}

	// Verify K1 = HMAC-SHA1(SIK, 0x01 * 20)
	k1Input := bytes.Repeat([]byte{0x01}, 20)
	mac = hmac.New(sha1.New, expectedSIK)
	mac.Write(k1Input)
	expectedK1 := mac.Sum(nil)

	if !bytes.Equal(s.k1, expectedK1) {
		t.Errorf("K1 mismatch:\n  got:  %x\n  want: %x", s.k1, expectedK1)
	}

	// Verify K2 = HMAC-SHA1(SIK, 0x02 * 20)
	k2Input := bytes.Repeat([]byte{0x02}, 20)
	mac = hmac.New(sha1.New, expectedSIK)
	mac.Write(k2Input)
	expectedK2 := mac.Sum(nil)

	if !bytes.Equal(s.k2, expectedK2) {
		t.Errorf("K2 mismatch:\n  got:  %x\n  want: %x", s.k2, expectedK2)
	}

	// Verify keys are non-nil and non-empty.
	if len(s.sik) != sha1.Size {
		t.Errorf("SIK length = %d, want %d", len(s.sik), sha1.Size)
	}
	if len(s.k1) != sha1.Size {
		t.Errorf("K1 length = %d, want %d", len(s.k1), sha1.Size)
	}
	if len(s.k2) != sha1.Size {
		t.Errorf("K2 length = %d, want %d", len(s.k2), sha1.Size)
	}
}

func TestDeriveKeys_HMACSHA256(t *testing.T) {
	s := &rmcpSession{
		authAlgo:      authAlgoHMACSHA256,
		integrityAlgo: integrityAlgoHMACSHA256_128,
		cryptoAlgo:    cryptoAlgoAESCBC128,
		password:      "admin_pass",
		username:      "root",
		privilege:     privilegeAdministrator,
	}

	for i := range s.clientRand {
		s.clientRand[i] = byte(i + 0x20)
	}
	for i := range s.bmcRand {
		s.bmcRand[i] = byte(i + 0x30)
	}

	if err := s.deriveKeys(); err != nil {
		t.Fatalf("deriveKeys() error: %v", err)
	}

	if len(s.sik) != sha256.Size {
		t.Errorf("SIK length = %d, want %d", len(s.sik), sha256.Size)
	}
	if len(s.k1) != sha256.Size {
		t.Errorf("K1 length = %d, want %d", len(s.k1), sha256.Size)
	}
	if len(s.k2) != sha256.Size {
		t.Errorf("K2 length = %d, want %d", len(s.k2), sha256.Size)
	}

	// Verify all keys are different from each other.
	if bytes.Equal(s.sik, s.k1) {
		t.Error("SIK and K1 should be different")
	}
	if bytes.Equal(s.sik, s.k2) {
		t.Error("SIK and K2 should be different")
	}
	if bytes.Equal(s.k1, s.k2) {
		t.Error("K1 and K2 should be different")
	}
}

// --- Auth HMAC Tests ---

func TestComputeAuthHMAC_SHA1(t *testing.T) {
	s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
	key := []byte("test_key")
	data := []byte("test_data")

	result := s.computeAuthHMAC(key, data)

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA1 mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestComputeAuthHMAC_SHA256(t *testing.T) {
	s := &rmcpSession{authAlgo: authAlgoHMACSHA256}
	key := []byte("test_key")
	data := []byte("test_data")

	result := s.computeAuthHMAC(key, data)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA256 mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestAuthHMACLen(t *testing.T) {
	tests := []struct {
		name     string
		algo     uint8
		expected int
	}{
		{"SHA1", authAlgoHMACSHA1, sha1.Size},
		{"SHA256", authAlgoHMACSHA256, sha256.Size},
		{"None defaults to SHA1", authAlgoNone, sha1.Size},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &rmcpSession{authAlgo: tt.algo}
			if got := s.authHMACLen(); got != tt.expected {
				t.Errorf("authHMACLen() = %d, want %d", got, tt.expected)
			}
		})
	}
}

// --- Integrity HMAC Tests ---

func TestComputeIntegrity_SHA1_96(t *testing.T) {
	s := &rmcpSession{
		integrityAlgo: integrityAlgoHMACSHA1_96,
		k1:            bytes.Repeat([]byte{0xAA}, 20),
	}
	data := []byte("integrity test data")

	result := s.computeIntegrity(data)

	// Should be truncated to 12 bytes.
	if len(result) != 12 {
		t.Fatalf("integrity HMAC length = %d, want 12", len(result))
	}

	// Verify against manual computation.
	mac := hmac.New(sha1.New, s.k1)
	mac.Write(data)
	full := mac.Sum(nil)
	expected := full[:12]

	if !bytes.Equal(result, expected) {
		t.Errorf("integrity HMAC mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestComputeIntegrity_SHA256_128(t *testing.T) {
	s := &rmcpSession{
		integrityAlgo: integrityAlgoHMACSHA256_128,
		k1:            bytes.Repeat([]byte{0xBB}, 32),
	}
	data := []byte("integrity test data sha256")

	result := s.computeIntegrity(data)

	// Should be truncated to 16 bytes.
	if len(result) != 16 {
		t.Fatalf("integrity HMAC length = %d, want 16", len(result))
	}

	mac := hmac.New(sha256.New, s.k1)
	mac.Write(data)
	full := mac.Sum(nil)
	expected := full[:16]

	if !bytes.Equal(result, expected) {
		t.Errorf("integrity HMAC mismatch:\n  got:  %x\n  want: %x", result, expected)
	}
}

func TestIntegrityHMACTruncLen(t *testing.T) {
	tests := []struct {
		name     string
		algo     uint8
		expected int
	}{
		{"SHA1-96", integrityAlgoHMACSHA1_96, 12},
		{"SHA256-128", integrityAlgoHMACSHA256_128, 16},
		{"None defaults to 12", integrityAlgoNone, 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &rmcpSession{integrityAlgo: tt.algo}
			if got := s.integrityHMACTruncLen(); got != tt.expected {
				t.Errorf("integrityHMACTruncLen() = %d, want %d", got, tt.expected)
			}
		})
	}
}

// --- AES-CBC-128 Encryption/Decryption Tests ---

func TestEncryptDecryptPayload(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo: cryptoAlgoAESCBC128,
		k2:         bytes.Repeat([]byte{0x42}, 20), // 20 bytes, AES uses first 16
	}

	t.Run("round trip single block", func(t *testing.T) {
		original := []byte("hello IPMI 2.0!") // 15 bytes
		encrypted, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt error: %v", err)
		}

		// Encrypted payload should be IV (16) + at least one block (16).
		if len(encrypted) < 32 {
			t.Fatalf("encrypted length = %d, want >= 32", len(encrypted))
		}
		if len(encrypted)%aes.BlockSize != 0 {
			t.Fatalf("encrypted length %d not a multiple of block size", len(encrypted))
		}

		decrypted, err := s.decryptPayload(encrypted)
		if err != nil {
			t.Fatalf("decrypt error: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("round trip failed:\n  got:  %q\n  want: %q", decrypted, original)
		}
	})

	t.Run("round trip multi block", func(t *testing.T) {
		original := bytes.Repeat([]byte{0xAB}, 47) // 47 bytes, spans multiple blocks
		encrypted, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt error: %v", err)
		}

		decrypted, err := s.decryptPayload(encrypted)
		if err != nil {
			t.Fatalf("decrypt error: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("round trip failed for %d-byte payload", len(original))
		}
	})

	t.Run("round trip exact block size", func(t *testing.T) {
		// 15 bytes data + 1 byte pad length = 16 bytes, exact block.
		// Actually with IPMI padding: data + pad bytes + padLen byte
		original := bytes.Repeat([]byte{0xCD}, 31)
		encrypted, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt error: %v", err)
		}

		decrypted, err := s.decryptPayload(encrypted)
		if err != nil {
			t.Fatalf("decrypt error: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("round trip failed for exact-block-sized payload")
		}
	})

	t.Run("round trip empty data", func(t *testing.T) {
		original := []byte{}
		encrypted, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt error: %v", err)
		}

		decrypted, err := s.decryptPayload(encrypted)
		if err != nil {
			t.Fatalf("decrypt error: %v", err)
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("round trip failed for empty payload")
		}
	})

	t.Run("different encryptions produce different ciphertext", func(t *testing.T) {
		original := []byte("determinism check")
		enc1, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt 1 error: %v", err)
		}
		enc2, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt 2 error: %v", err)
		}
		// Due to random IV, ciphertexts should differ.
		if bytes.Equal(enc1, enc2) {
			t.Error("two encryptions of same data produced identical ciphertext")
		}
	})
}

func TestDecryptPayload_Errors(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo: cryptoAlgoAESCBC128,
		k2:         bytes.Repeat([]byte{0x42}, 20),
	}

	t.Run("too short", func(t *testing.T) {
		_, err := s.decryptPayload([]byte{0x01, 0x02, 0x03})
		if err == nil {
			t.Fatal("expected error for short payload")
		}
		if _, ok := err.(ErrDecryptFailed); !ok {
			t.Errorf("expected ErrDecryptFailed, got %T", err)
		}
	})

	t.Run("not block aligned", func(t *testing.T) {
		data := make([]byte, aes.BlockSize+5) // IV + non-aligned
		_, err := s.decryptPayload(data)
		if err == nil {
			t.Fatal("expected error for non-aligned ciphertext")
		}
	})

	t.Run("invalid padding", func(t *testing.T) {
		// Create a valid-looking encrypted block but with bad padding.
		key := s.k2[:16]
		block, _ := aes.NewCipher(key)
		iv := make([]byte, aes.BlockSize)
		// Plaintext where last byte (pad length) claims huge pad.
		plaintext := make([]byte, aes.BlockSize)
		plaintext[aes.BlockSize-1] = 0xFF // Invalid: pad length > block

		ciphertext := make([]byte, aes.BlockSize)
		mode := newCBCEncrypterForTest(block, iv)
		mode.CryptBlocks(ciphertext, plaintext)

		encrypted := append(iv, ciphertext...)
		_, err := s.decryptPayload(encrypted)
		if err == nil {
			t.Fatal("expected error for invalid padding")
		}
	})
}

func TestEncryptPayload_PaddingCorrectness(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo: cryptoAlgoAESCBC128,
		k2:         bytes.Repeat([]byte{0x42}, 20),
	}

	// Test various data sizes to ensure padding is always correct.
	for dataLen := 0; dataLen < 50; dataLen++ {
		original := bytes.Repeat([]byte{0xAA}, dataLen)
		encrypted, err := s.encryptPayload(original)
		if err != nil {
			t.Fatalf("encrypt error for len %d: %v", dataLen, err)
		}

		// Ciphertext (excluding IV) must be block-aligned.
		ciphertextLen := len(encrypted) - aes.BlockSize
		if ciphertextLen%aes.BlockSize != 0 {
			t.Errorf("data len %d: ciphertext len %d not block-aligned", dataLen, ciphertextLen)
		}

		decrypted, err := s.decryptPayload(encrypted)
		if err != nil {
			t.Fatalf("decrypt error for len %d: %v", dataLen, err)
		}
		if !bytes.Equal(decrypted, original) {
			t.Errorf("data len %d: round trip failed", dataLen)
		}
	}
}

// --- Session State Tests ---

func TestRMCPSession_ClosedState(t *testing.T) {
	s := &rmcpSession{
		logger: slog.Default(),
	}
	s.closed.Store(true)

	t.Run("Send returns error when closed", func(t *testing.T) {
		_, err := s.Send(netFnApp, cmdGetDeviceID, nil)
		if err == nil {
			t.Fatal("expected error for closed session")
		}
		if _, ok := err.(ErrSessionClosed); !ok {
			t.Errorf("expected ErrSessionClosed, got %T: %v", err, err)
		}
	})

	t.Run("Open returns error when closed", func(t *testing.T) {
		err := s.Open(context.Background())
		if err == nil {
			t.Fatal("expected error for closed session")
		}
		if _, ok := err.(ErrSessionClosed); !ok {
			t.Errorf("expected ErrSessionClosed, got %T: %v", err, err)
		}
	})

	t.Run("double close is idempotent", func(t *testing.T) {
		err := s.Close()
		if err != nil {
			t.Errorf("double Close() should not error, got: %v", err)
		}
	})
}

func TestNewRMCPSession_Defaults(t *testing.T) {
	config := &Config{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "password",
		Protocol: ProtocolIPMI,
	}
	s := newRMCPSession(config, slog.Default())

	if s.addr != "192.168.1.100:623" {
		t.Errorf("addr = %q, want %q", s.addr, "192.168.1.100:623")
	}
	if s.username != "admin" {
		t.Errorf("username = %q, want %q", s.username, "admin")
	}
	if s.password != "password" {
		t.Errorf("password = %q, want %q", s.password, "password")
	}
	if s.authAlgo != authAlgoHMACSHA256 {
		t.Errorf("authAlgo = %d, want %d", s.authAlgo, authAlgoHMACSHA256)
	}
	if s.integrityAlgo != integrityAlgoHMACSHA256_128 {
		t.Errorf("integrityAlgo = %d, want %d", s.integrityAlgo, integrityAlgoHMACSHA256_128)
	}
	if s.cryptoAlgo != cryptoAlgoAESCBC128 {
		t.Errorf("cryptoAlgo = %d, want %d", s.cryptoAlgo, cryptoAlgoAESCBC128)
	}
	if s.privilege != privilegeAdministrator {
		t.Errorf("privilege = %d, want %d", s.privilege, privilegeAdministrator)
	}
	if s.timeout != defaultIPMITimeout {
		t.Errorf("timeout = %v, want %v", s.timeout, defaultIPMITimeout)
	}
}

func TestNewRMCPSession_EmptyPassword(t *testing.T) {
	config := &Config{
		Address:  "10.0.0.1",
		Port:     623,
		Username: "",
		Password: "",
		Protocol: ProtocolIPMI,
	}
	s := newRMCPSession(config, slog.Default())
	if s.username != "" {
		t.Errorf("expected empty username")
	}
	if s.password != "" {
		t.Errorf("expected empty password")
	}
}

// --- Wrap/Unwrap Tests ---

func TestWrapPayload_NoEncryptionNoIntegrity(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoNone,
		integrityAlgo: integrityAlgoNone,
		bmcSessionID:  0x12345678,
		logger:        slog.Default(),
	}

	ipmiMsg := buildIPMIMessage(netFnChassis, cmdChassisStatus, nil)
	packet, err := s.wrapPayload(ipmiMsg)
	if err != nil {
		t.Fatalf("wrapPayload error: %v", err)
	}

	// RMCP header
	if packet[0] != rmcpVersion {
		t.Errorf("RMCP version = 0x%02x, want 0x%02x", packet[0], rmcpVersion)
	}
	if packet[4] != authTypeRMCPPlus {
		t.Errorf("auth type = 0x%02x, want 0x%02x", packet[4], authTypeRMCPPlus)
	}
	// Payload type should be IPMI with no encrypt/auth bits.
	if packet[5] != payloadTypeIPMI {
		t.Errorf("payload type = 0x%02x, want 0x%02x", packet[5], payloadTypeIPMI)
	}

	// Session ID.
	sid := binary.LittleEndian.Uint32(packet[6:10])
	if sid != 0x12345678 {
		t.Errorf("session ID = 0x%08x, want 0x12345678", sid)
	}

	// Payload length.
	plen := binary.LittleEndian.Uint16(packet[14:16])
	if int(plen) != len(ipmiMsg) {
		t.Errorf("payload length = %d, want %d", plen, len(ipmiMsg))
	}
}

func TestWrapPayload_WithEncryptionAndIntegrity(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoAESCBC128,
		integrityAlgo: integrityAlgoHMACSHA1_96,
		bmcSessionID:  0xAABBCCDD,
		k1:            bytes.Repeat([]byte{0x11}, 20),
		k2:            bytes.Repeat([]byte{0x22}, 20),
		logger:        slog.Default(),
	}

	ipmiMsg := buildIPMIMessage(netFnApp, cmdGetDeviceID, nil)
	packet, err := s.wrapPayload(ipmiMsg)
	if err != nil {
		t.Fatalf("wrapPayload error: %v", err)
	}

	// Payload type should have encrypted and authenticated bits set.
	payloadType := packet[5]
	if payloadType&0x80 == 0 {
		t.Error("encrypted bit not set")
	}
	if payloadType&0x40 == 0 {
		t.Error("authenticated bit not set")
	}

	// Packet should end with 12-byte integrity HMAC.
	if len(packet) < 12 {
		t.Fatalf("packet too short: %d bytes", len(packet))
	}

	// The last 12 bytes are the HMAC.
	// Verify it's not all zeros (would indicate a bug).
	authCode := packet[len(packet)-12:]
	allZero := true
	for _, b := range authCode {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("auth code is all zeros")
	}
}

// --- RAKP Status Code Tests ---

func TestRAKPStatusString(t *testing.T) {
	tests := []struct {
		code     uint8
		contains string
	}{
		{0x00, "no errors"},
		{0x01, "insufficient resources"},
		{0x02, "invalid session ID"},
		{0x04, "invalid authentication algorithm"},
		{0x13, "invalid integrity check value"},
		{0x15, "no cipher suite match"},
		{0xFF, "unknown status code"},
	}
	for _, tt := range tests {
		t.Run(tt.contains, func(t *testing.T) {
			result := rakpStatusString(tt.code)
			if result == "" {
				t.Error("empty result")
			}
		})
	}
}

func TestRAKPStatusString_UnknownCode(t *testing.T) {
	result := rakpStatusString(0xFE)
	if result == "" {
		t.Error("expected non-empty string for unknown code")
	}
}

// --- Error Type Tests ---

func TestRMCPErrors(t *testing.T) {
	t.Run("ErrRAKPAuthFailed", func(t *testing.T) {
		err := ErrRAKPAuthFailed{Stage: "RAKP2", Code: 0x13, Reason: "bad HMAC"}
		msg := err.Error()
		if msg == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrRAKPAuthFailed minimal", func(t *testing.T) {
		err := ErrRAKPAuthFailed{}
		msg := err.Error()
		if msg == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrSessionClosed", func(t *testing.T) {
		err := ErrSessionClosed{}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrPacketTooShort", func(t *testing.T) {
		err := ErrPacketTooShort{Expected: 16, Actual: 4}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrIntegrityCheckFailed", func(t *testing.T) {
		err := ErrIntegrityCheckFailed{}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrCompletionCode", func(t *testing.T) {
		err := ErrCompletionCode{Code: 0xC1, Command: 0x01, NetFn: 0x00}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrUDPSend", func(t *testing.T) {
		err := ErrUDPSend{Cause: ErrSessionClosed{}}
		if err.Error() == "" {
			t.Error("empty error message")
		}
		if err.Unwrap() == nil {
			t.Error("expected non-nil unwrap")
		}
	})

	t.Run("ErrUDPRecv", func(t *testing.T) {
		err := ErrUDPRecv{Cause: ErrSessionClosed{}}
		if err.Error() == "" {
			t.Error("empty error message")
		}
		if err.Unwrap() == nil {
			t.Error("expected non-nil unwrap")
		}
	})

	t.Run("ErrDecryptFailed", func(t *testing.T) {
		err := ErrDecryptFailed{Reason: "bad block"}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})

	t.Run("ErrEncryptFailed", func(t *testing.T) {
		err := ErrEncryptFailed{Reason: "key too short"}
		if err.Error() == "" {
			t.Error("empty error message")
		}
	})
}

// --- HMAC Cross-validation ---

func TestHMACCrossValidation(t *testing.T) {
	// Verify our HMAC computations match Go stdlib directly.
	key := []byte("cross_validation_key")
	data := []byte("cross_validation_data")

	t.Run("SHA1 matches stdlib", func(t *testing.T) {
		s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
		got := s.computeAuthHMAC(key, data)

		h := hmac.New(sha1.New, key)
		h.Write(data)
		want := h.Sum(nil)

		if !hmac.Equal(got, want) {
			t.Errorf("HMAC mismatch:\n  got:  %x\n  want: %x", got, want)
		}
	})

	t.Run("SHA256 matches stdlib", func(t *testing.T) {
		s := &rmcpSession{authAlgo: authAlgoHMACSHA256}
		got := s.computeAuthHMAC(key, data)

		h := hmac.New(sha256.New, key)
		h.Write(data)
		want := h.Sum(nil)

		if !hmac.Equal(got, want) {
			t.Errorf("HMAC mismatch:\n  got:  %x\n  want: %x", got, want)
		}
	})
}

// --- Integrity Verification Consistency ---

func TestIntegrityConsistency(t *testing.T) {
	// Compute integrity, then verify the same data produces the same result.
	s := &rmcpSession{
		integrityAlgo: integrityAlgoHMACSHA1_96,
		k1:            bytes.Repeat([]byte{0xCC}, 20),
	}

	data := []byte("consistency check data for integrity HMAC")
	mac1 := s.computeIntegrity(data)
	mac2 := s.computeIntegrity(data)

	if !bytes.Equal(mac1, mac2) {
		t.Error("integrity HMAC is not deterministic")
	}

	// Different data should produce different HMAC.
	otherData := []byte("different data for integrity check")
	mac3 := s.computeIntegrity(otherData)
	if bytes.Equal(mac1, mac3) {
		t.Error("different data produced same integrity HMAC")
	}
}

// --- Sequence Number Tests ---

func TestSequenceNumberIncrement(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoNone,
		integrityAlgo: integrityAlgoNone,
		bmcSessionID:  1,
		logger:        slog.Default(),
	}

	// Wrap two payloads and verify sequence numbers increment.
	msg1 := buildIPMIMessage(netFnChassis, cmdChassisStatus, nil)
	pkt1, err := s.wrapPayload(msg1)
	if err != nil {
		t.Fatalf("wrapPayload 1 error: %v", err)
	}
	seq1 := binary.LittleEndian.Uint32(pkt1[10:14])

	msg2 := buildIPMIMessage(netFnChassis, cmdChassisStatus, nil)
	pkt2, err := s.wrapPayload(msg2)
	if err != nil {
		t.Fatalf("wrapPayload 2 error: %v", err)
	}
	seq2 := binary.LittleEndian.Uint32(pkt2[10:14])

	if seq2 != seq1+1 {
		t.Errorf("sequence numbers: first=%d, second=%d, want consecutive", seq1, seq2)
	}
}

// --- Algorithm Constants Tests ---

func TestAlgorithmConstants(t *testing.T) {
	// Verify algorithm constants match IPMI 2.0 spec values.
	if authAlgoNone != 0x00 {
		t.Error("authAlgoNone should be 0x00")
	}
	if authAlgoHMACSHA1 != 0x01 {
		t.Error("authAlgoHMACSHA1 should be 0x01")
	}
	if authAlgoHMACMD5 != 0x02 {
		t.Error("authAlgoHMACMD5 should be 0x02")
	}
	if authAlgoHMACSHA256 != 0x03 {
		t.Error("authAlgoHMACSHA256 should be 0x03")
	}
	if integrityAlgoNone != 0x00 {
		t.Error("integrityAlgoNone should be 0x00")
	}
	if integrityAlgoHMACSHA1_96 != 0x01 {
		t.Error("integrityAlgoHMACSHA1_96 should be 0x01")
	}
	if integrityAlgoHMACSHA256_128 != 0x04 {
		t.Error("integrityAlgoHMACSHA256_128 should be 0x04")
	}
	if cryptoAlgoNone != 0x00 {
		t.Error("cryptoAlgoNone should be 0x00")
	}
	if cryptoAlgoAESCBC128 != 0x01 {
		t.Error("cryptoAlgoAESCBC128 should be 0x01")
	}
}

// --- Payload Type Constants Tests ---

func TestPayloadTypeConstants(t *testing.T) {
	if payloadTypeIPMI != 0x00 {
		t.Error("payloadTypeIPMI should be 0x00")
	}
	if payloadTypeOpenSessionReq != 0x10 {
		t.Error("payloadTypeOpenSessionReq should be 0x10")
	}
	if payloadTypeOpenSessionResp != 0x11 {
		t.Error("payloadTypeOpenSessionResp should be 0x11")
	}
	if payloadTypeRAKP1 != 0x12 {
		t.Error("payloadTypeRAKP1 should be 0x12")
	}
	if payloadTypeRAKP2 != 0x13 {
		t.Error("payloadTypeRAKP2 should be 0x13")
	}
	if payloadTypeRAKP3 != 0x14 {
		t.Error("payloadTypeRAKP3 should be 0x14")
	}
	if payloadTypeRAKP4 != 0x15 {
		t.Error("payloadTypeRAKP4 should be 0x15")
	}
}

// --- Chassis Control Constants Tests ---

func TestChassisControlConstants(t *testing.T) {
	if chassisControlPowerDown != 0x00 {
		t.Error("chassisControlPowerDown should be 0x00")
	}
	if chassisControlPowerUp != 0x01 {
		t.Error("chassisControlPowerUp should be 0x01")
	}
	if chassisControlPowerCycle != 0x02 {
		t.Error("chassisControlPowerCycle should be 0x02")
	}
	if chassisControlHardReset != 0x03 {
		t.Error("chassisControlHardReset should be 0x03")
	}
}

// --- helper for test: create CBC encrypter without importing cipher ---

func newCBCEncrypterForTest(block interface {
	BlockSize() int
	Encrypt(dst, src []byte)
}, iv []byte) cbcEncrypter {
	return cbcEncrypter{block: block, iv: iv}
}

type cbcEncrypter struct {
	block interface {
		BlockSize() int
		Encrypt(dst, src []byte)
	}
	iv []byte
}

func (c cbcEncrypter) CryptBlocks(dst, src []byte) {
	bs := c.block.BlockSize()
	xorBytes(dst[:bs], src[:bs], c.iv)
	c.block.Encrypt(dst[:bs], dst[:bs])
}

func xorBytes(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}

// --- UnwrapResponse Tests ---

func TestUnwrapResponse_CompletionCodeError(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoNone,
		integrityAlgo: integrityAlgoNone,
		logger:        slog.Default(),
	}

	// Build a fake response with non-zero completion code.
	ipmiResp := make([]byte, 8)
	ipmiResp[0] = 0x81 // rqAddr
	ipmiResp[1] = 0x04 // netFn/rqLUN (response)
	ipmiResp[2] = ipmiChecksum(ipmiResp[0:2])
	ipmiResp[3] = 0x20             // rsAddr
	ipmiResp[4] = 0x00             // rsSeq
	ipmiResp[5] = cmdChassisStatus // cmd
	ipmiResp[6] = 0xC1             // completion code: command not supported
	ipmiResp[7] = ipmiChecksum(ipmiResp[3:7])

	packet := buildRMCPPlusUnauthPacket(payloadTypeIPMI, 0x12345678, 1, ipmiResp)
	// Override auth type byte.
	packet[4] = authTypeRMCPPlus

	_, err := s.unwrapResponse(packet, cmdChassisStatus, netFnChassis)
	if err == nil {
		t.Fatal("expected error for non-zero completion code")
	}
	if cc, ok := err.(ErrCompletionCode); !ok {
		t.Errorf("expected ErrCompletionCode, got %T: %v", err, err)
	} else if cc.Code != 0xC1 {
		t.Errorf("completion code = 0x%02x, want 0xC1", cc.Code)
	}
}

func TestUnwrapResponse_Success(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoNone,
		integrityAlgo: integrityAlgoNone,
		logger:        slog.Default(),
	}

	// Build a response with completion code 0x00 and some data.
	ipmiResp := make([]byte, 10)
	ipmiResp[0] = 0x81
	ipmiResp[1] = 0x04
	ipmiResp[2] = ipmiChecksum(ipmiResp[0:2])
	ipmiResp[3] = 0x20
	ipmiResp[4] = 0x00
	ipmiResp[5] = cmdChassisStatus
	ipmiResp[6] = 0x00 // Success
	ipmiResp[7] = 0x61 // Power state byte: system power on
	ipmiResp[8] = 0x00 // Last power event
	ipmiResp[9] = ipmiChecksum(ipmiResp[3:9])

	packet := buildRMCPPlusUnauthPacket(payloadTypeIPMI, 0x12345678, 1, ipmiResp)
	packet[4] = authTypeRMCPPlus

	data, err := s.unwrapResponse(packet, cmdChassisStatus, netFnChassis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Data should contain bytes between completion code and trailing checksum.
	if len(data) != 2 { // 0x61 and 0x00
		t.Fatalf("data length = %d, want 2", len(data))
	}
	if data[0] != 0x61 {
		t.Errorf("power state byte = 0x%02x, want 0x61", data[0])
	}
}

func TestUnwrapResponse_TooShort(t *testing.T) {
	s := &rmcpSession{logger: slog.Default()}
	_, err := s.unwrapResponse([]byte{0x06, 0x00, 0xFF, 0x07}, cmdChassisStatus, netFnChassis)
	if err == nil {
		t.Fatal("expected error for short response")
	}
}

func TestUnwrapResponse_NoData(t *testing.T) {
	s := &rmcpSession{
		cryptoAlgo:    cryptoAlgoNone,
		integrityAlgo: integrityAlgoNone,
		logger:        slog.Default(),
	}

	// Minimal IPMI response: no data bytes.
	ipmiResp := make([]byte, 8)
	ipmiResp[0] = 0x81
	ipmiResp[1] = 0x04
	ipmiResp[2] = ipmiChecksum(ipmiResp[0:2])
	ipmiResp[3] = 0x20
	ipmiResp[4] = 0x00
	ipmiResp[5] = cmdChassisControl
	ipmiResp[6] = 0x00
	ipmiResp[7] = ipmiChecksum(ipmiResp[3:7])

	packet := buildRMCPPlusUnauthPacket(payloadTypeIPMI, 1, 1, ipmiResp)
	packet[4] = authTypeRMCPPlus

	data, err := s.unwrapResponse(packet, cmdChassisControl, netFnChassis)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Errorf("expected nil data, got %v", data)
	}
}

// --- Known Test Vector: HMAC-SHA1 ---

func TestHMACSHA1_KnownVector(t *testing.T) {
	// RFC 2202 Test Case 1
	key := bytes.Repeat([]byte{0x0B}, 20)
	data := []byte("Hi There")

	h := hmac.New(sha1.New, key)
	h.Write(data)
	result := h.Sum(nil)

	// Expected: b617318655057264e28bc0b6fb378c8ef146be00
	expected := []byte{
		0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64,
		0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e,
		0xf1, 0x46, 0xbe, 0x00,
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA1 known vector mismatch:\n  got:  %x\n  want: %x", result, expected)
	}

	// Verify our wrapper produces the same.
	s := &rmcpSession{authAlgo: authAlgoHMACSHA1}
	wrapper := s.computeAuthHMAC(key, data)
	if !bytes.Equal(wrapper, expected) {
		t.Errorf("computeAuthHMAC wrapper mismatch:\n  got:  %x\n  want: %x", wrapper, expected)
	}
}

// --- Known Test Vector: HMAC-SHA256 ---

func TestHMACSHA256_KnownVector(t *testing.T) {
	// RFC 4231 Test Case 2
	key := []byte("Jefe")
	data := []byte("what do ya want for nothing?")

	h := hmac.New(sha256.New, key)
	h.Write(data)
	result := h.Sum(nil)

	// Expected from RFC 4231
	expected := []byte{
		0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
		0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
		0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
		0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
	}
	if !bytes.Equal(result, expected) {
		t.Errorf("HMAC-SHA256 known vector mismatch:\n  got:  %x\n  want: %x", result, expected)
	}

	s := &rmcpSession{authAlgo: authAlgoHMACSHA256}
	wrapper := s.computeAuthHMAC(key, data)
	if !bytes.Equal(wrapper, expected) {
		t.Errorf("computeAuthHMAC wrapper mismatch:\n  got:  %x\n  want: %x", wrapper, expected)
	}
}

// --- AES-CBC-128 Known Test Vector ---

func TestAESCBC128_KnownVector(t *testing.T) {
	// NIST SP 800-38A, F.2.1: AES-128-CBC Encrypt
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	iv := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	plaintext := []byte{
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	}
	expectedCiphertext := []byte{
		0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
		0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher error: %v", err)
	}

	var hFunc func() hash.Hash
	_ = hFunc // just to silence unused

	ciphertext := make([]byte, len(plaintext))
	mode := newCBCEncrypterForTest(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("AES-CBC-128 known vector mismatch:\n  got:  %x\n  want: %x",
			ciphertext, expectedCiphertext)
	}
}

// --- Boot Device Bits Map Tests ---

func TestBootDeviceBitsMap(t *testing.T) {
	tests := []struct {
		device BootDevice
		bits   byte
	}{
		{BootDevicePXE, bootDevicePXEBits},
		{BootDeviceDisk, bootDeviceDiskBits},
		{BootDeviceCDROM, bootDeviceCDROMBits},
		{BootDeviceVirtualMedia, bootDeviceCDROMBits},
		{BootDeviceNone, bootDeviceNoneBits},
	}
	for _, tt := range tests {
		t.Run(string(tt.device), func(t *testing.T) {
			bits, ok := bootDeviceBitsMap[tt.device]
			if !ok {
				t.Fatalf("boot device %q not in map", tt.device)
			}
			if bits != tt.bits {
				t.Errorf("bits = 0x%02x, want 0x%02x", bits, tt.bits)
			}
		})
	}
}

func TestIPMIBootDeviceFromBits(t *testing.T) {
	tests := []struct {
		bits   byte
		device BootDevice
	}{
		{bootDeviceNoneBits, BootDeviceNone},
		{bootDevicePXEBits, BootDevicePXE},
		{bootDeviceDiskBits, BootDeviceDisk},
		{bootDeviceCDROMBits, BootDeviceCDROM},
	}
	for _, tt := range tests {
		t.Run(string(tt.device), func(t *testing.T) {
			device, ok := ipmiBootDeviceFromBits[tt.bits]
			if !ok {
				t.Fatalf("bits 0x%02x not in map", tt.bits)
			}
			if device != tt.device {
				t.Errorf("device = %q, want %q", device, tt.device)
			}
		})
	}
}
