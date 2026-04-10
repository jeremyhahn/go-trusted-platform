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

package uefi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert(t *testing.T) []byte {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return certDER
}

func TestNewSignatureListFromCert(t *testing.T) {
	certDER := generateTestCert(t)
	ownerGUID := NewGUID()

	sl := NewSignatureListFromCert(certDER, ownerGUID)

	assert.Equal(t, EFIX509Cert, sl.SignatureType)
	assert.Equal(t, uint32(0), sl.SignatureHeaderSize)
	assert.Equal(t, uint32(GUIDSize+len(certDER)), sl.SignatureSize)
	assert.Equal(t, uint32(SignatureListHeaderSize+GUIDSize+len(certDER)), sl.SignatureListSize)
	assert.Len(t, sl.Signatures, 1)
	assert.Equal(t, ownerGUID, sl.Signatures[0].Owner)
	assert.Equal(t, certDER, sl.Signatures[0].Data)
}

func TestNewSignatureListFromHash(t *testing.T) {
	hash := make([]byte, 32) // SHA-256
	rand.Read(hash)
	ownerGUID := NewGUID()

	sl := NewSignatureListFromHash(hash, EFISHA256, ownerGUID)

	assert.Equal(t, EFISHA256, sl.SignatureType)
	assert.Equal(t, uint32(0), sl.SignatureHeaderSize)
	assert.Equal(t, uint32(GUIDSize+32), sl.SignatureSize) // GUID + SHA256
	assert.Len(t, sl.Signatures, 1)
	assert.Equal(t, hash, sl.Signatures[0].Data)
}

func TestSignatureList_Bytes(t *testing.T) {
	certDER := generateTestCert(t)
	ownerGUID := NewGUID()

	sl := NewSignatureListFromCert(certDER, ownerGUID)
	b := sl.Bytes()

	// Verify header
	assert.Len(t, b, int(sl.SignatureListSize))

	// First 16 bytes should be signature type GUID
	typeGUID, err := GUIDFromBytes(b[0:16])
	require.NoError(t, err)
	assert.Equal(t, EFIX509Cert, typeGUID)

	// Next 4 bytes should be list size
	// (verified by length check above)

	// SignatureHeaderSize at offset 20 should be 0
	// SignatureSize at offset 24 should match

	// After header (28 bytes), should be owner GUID then cert data
	sigOffset := SignatureListHeaderSize
	parsedOwner, err := GUIDFromBytes(b[sigOffset : sigOffset+GUIDSize])
	require.NoError(t, err)
	assert.Equal(t, ownerGUID, parsedOwner)

	// Certificate data follows
	certData := b[sigOffset+GUIDSize:]
	assert.Equal(t, certDER, certData)
}

func TestSignatureList_Bytes_WithHeader(t *testing.T) {
	sl := &SignatureList{
		SignatureType:       EFIX509Cert,
		SignatureListSize:   100,
		SignatureHeaderSize: 8,
		SignatureSize:       48,
		Header:              []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Signatures: []SignatureData{
			{
				Owner: NewGUID(),
				Data:  make([]byte, 32),
			},
		},
	}

	b := sl.Bytes()
	assert.NotNil(t, b)

	// Verify header is included
	headerOffset := SignatureListHeaderSize
	assert.Equal(t, sl.Header, b[headerOffset:headerOffset+8])
}

func TestSignatureList_Bytes_WithPadding(t *testing.T) {
	// Create a signature list where SignatureSize is larger than actual data
	sl := &SignatureList{
		SignatureType:       EFIX509Cert,
		SignatureListSize:   100,
		SignatureHeaderSize: 0,
		SignatureSize:       64, // Larger than actual data (16 GUID + 32 data = 48)
		Signatures: []SignatureData{
			{
				Owner: NewGUID(),
				Data:  make([]byte, 32),
			},
		},
	}

	b := sl.Bytes()
	assert.NotNil(t, b)

	// Should include padding to reach SignatureSize
	sigOffset := SignatureListHeaderSize
	sigEnd := sigOffset + int(sl.SignatureSize)
	assert.LessOrEqual(t, sigEnd, len(b))
}

func TestSignatureList_AddSignature(t *testing.T) {
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	rand.Read(hash1)
	rand.Read(hash2)

	owner1 := NewGUID()
	owner2 := NewGUID()

	sl := NewSignatureListFromHash(hash1, EFISHA256, owner1)
	originalSize := sl.SignatureListSize

	err := sl.AddSignature(SignatureData{Owner: owner2, Data: hash2})
	require.NoError(t, err)

	assert.Len(t, sl.Signatures, 2)
	assert.Equal(t, originalSize+sl.SignatureSize, sl.SignatureListSize)
}

func TestSignatureList_AddSignature_FirstSignature(t *testing.T) {
	// Test adding to empty list
	sl := &SignatureList{
		SignatureType:       EFISHA256,
		SignatureListSize:   SignatureListHeaderSize,
		SignatureHeaderSize: 0,
		Signatures:          []SignatureData{},
	}

	hash := make([]byte, 32)
	rand.Read(hash)

	err := sl.AddSignature(SignatureData{Owner: NewGUID(), Data: hash})
	require.NoError(t, err)

	assert.Len(t, sl.Signatures, 1)
	assert.Equal(t, uint32(GUIDSize+32), sl.SignatureSize)
}

func TestSignatureList_AddSignature_SizeMismatch(t *testing.T) {
	hash := make([]byte, 32)
	rand.Read(hash)

	sl := NewSignatureListFromHash(hash, EFISHA256, NewGUID())

	// Try to add a different size hash
	differentHash := make([]byte, 48) // SHA-384 size
	rand.Read(differentHash)

	err := sl.AddSignature(SignatureData{Owner: NewGUID(), Data: differentHash})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature size mismatch")
}

func TestParseSignatureList(t *testing.T) {
	certDER := generateTestCert(t)
	ownerGUID := NewGUID()

	original := NewSignatureListFromCert(certDER, ownerGUID)
	data := original.Bytes()

	parsed, consumed, err := ParseSignatureList(data)
	require.NoError(t, err)

	assert.Equal(t, len(data), consumed)
	assert.Equal(t, original.SignatureType, parsed.SignatureType)
	assert.Equal(t, original.SignatureListSize, parsed.SignatureListSize)
	assert.Equal(t, original.SignatureSize, parsed.SignatureSize)
	assert.Len(t, parsed.Signatures, 1)
	assert.Equal(t, ownerGUID, parsed.Signatures[0].Owner)
	assert.Equal(t, certDER, parsed.Signatures[0].Data)
}

func TestParseSignatureList_WithHeader(t *testing.T) {
	// Create signature list with header
	sl := &SignatureList{
		SignatureType:       EFIX509Cert,
		SignatureListSize:   uint32(SignatureListHeaderSize + 8 + GUIDSize + 32),
		SignatureHeaderSize: 8,
		SignatureSize:       uint32(GUIDSize + 32),
		Header:              []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Signatures: []SignatureData{
			{
				Owner: NewGUID(),
				Data:  make([]byte, 32),
			},
		},
	}

	data := sl.Bytes()
	parsed, _, err := ParseSignatureList(data)
	require.NoError(t, err)

	assert.Equal(t, sl.Header, parsed.Header)
}

func TestParseSignatureList_Multiple(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)
	owner1 := NewGUID()
	owner2 := NewGUID()

	sl1 := NewSignatureListFromCert(cert1, owner1)
	sl2 := NewSignatureListFromCert(cert2, owner2)

	combined := ConcatSignatureLists(sl1, sl2)

	lists, err := ParseSignatureLists(combined)
	require.NoError(t, err)

	assert.Len(t, lists, 2)
	assert.Equal(t, cert1, lists[0].Signatures[0].Data)
	assert.Equal(t, cert2, lists[1].Signatures[0].Data)
}

func TestParseSignatureList_TooShort(t *testing.T) {
	data := make([]byte, 10) // Too short for header
	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "data too short for signature list header")
}

func TestParseSignatureList_InvalidGUID(t *testing.T) {
	data := make([]byte, SignatureListHeaderSize)
	// Leave first 16 bytes (GUID) as zeros - invalid
	// Set size fields
	binary.LittleEndian.PutUint32(data[16:20], uint32(SignatureListHeaderSize))
	binary.LittleEndian.PutUint32(data[20:24], 0)
	binary.LittleEndian.PutUint32(data[24:28], uint32(GUIDSize))

	_, _, err := ParseSignatureList(data)
	// Should still work but might have an "invalid" GUID
	require.NoError(t, err)
}

func TestParseSignatureList_SizeTooSmall(t *testing.T) {
	data := make([]byte, SignatureListHeaderSize)
	copy(data[0:16], EFIX509Cert.Bytes())

	// Set size smaller than header
	binary.LittleEndian.PutUint32(data[16:20], 20) // Less than SignatureListHeaderSize
	binary.LittleEndian.PutUint32(data[20:24], 0)
	binary.LittleEndian.PutUint32(data[24:28], uint32(GUIDSize))

	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature list size too small")
}

func TestParseSignatureList_SignatureSizeTooSmall(t *testing.T) {
	data := make([]byte, SignatureListHeaderSize)
	copy(data[0:16], EFIX509Cert.Bytes())
	binary.LittleEndian.PutUint32(data[16:20], uint32(SignatureListHeaderSize))
	binary.LittleEndian.PutUint32(data[20:24], 0)
	binary.LittleEndian.PutUint32(data[24:28], 8) // Less than GUIDSize

	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature size too small")
}

func TestParseSignatureList_InvalidSize(t *testing.T) {
	certDER := generateTestCert(t)
	ownerGUID := NewGUID()

	sl := NewSignatureListFromCert(certDER, ownerGUID)
	data := sl.Bytes()

	// Corrupt the size field to be larger than actual data
	binary.LittleEndian.PutUint32(data[16:20], 0xFFFFFFFF)

	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature list size exceeds data length")
}

func TestParseSignatureList_HeaderExceedsData(t *testing.T) {
	data := make([]byte, SignatureListHeaderSize+2)
	copy(data[0:16], EFIX509Cert.Bytes())
	binary.LittleEndian.PutUint32(data[16:20], uint32(SignatureListHeaderSize+100))
	binary.LittleEndian.PutUint32(data[20:24], 100) // Header size larger than remaining data
	binary.LittleEndian.PutUint32(data[24:28], uint32(GUIDSize+32))

	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature list size exceeds data length")
}

func TestParseSignatureList_MisalignedSignatures(t *testing.T) {
	data := make([]byte, SignatureListHeaderSize+GUIDSize+33) // 33 bytes signature data
	copy(data[0:16], EFISHA256.Bytes())
	binary.LittleEndian.PutUint32(data[16:20], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[20:24], 0)
	binary.LittleEndian.PutUint32(data[24:28], uint32(GUIDSize+32)) // 48 bytes per sig

	// But we only have 49 bytes of signature data (not aligned to 48)
	_, _, err := ParseSignatureList(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature data size not aligned")
}

func TestParseSignatureLists_Empty(t *testing.T) {
	lists, err := ParseSignatureLists([]byte{})
	require.NoError(t, err)
	assert.Len(t, lists, 0)
}

func TestParseSignatureLists_Error(t *testing.T) {
	// Create invalid data that will fail to parse
	data := make([]byte, 10)
	_, err := ParseSignatureLists(data)
	assert.Error(t, err)
}

func TestConcatSignatureLists(t *testing.T) {
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	rand.Read(hash1)
	rand.Read(hash2)

	sl1 := NewSignatureListFromHash(hash1, EFISHA256, NewGUID())
	sl2 := NewSignatureListFromHash(hash2, EFISHA256, NewGUID())

	combined := ConcatSignatureLists(sl1, sl2)

	expectedLen := int(sl1.SignatureListSize + sl2.SignatureListSize)
	assert.Len(t, combined, expectedLen)
}

func TestConcatSignatureLists_Empty(t *testing.T) {
	result := ConcatSignatureLists()
	assert.Len(t, result, 0)
}

func TestSignatureList_IsX509(t *testing.T) {
	certDER := generateTestCert(t)
	sl := NewSignatureListFromCert(certDER, NewGUID())
	assert.True(t, sl.IsX509())

	hash := make([]byte, 32)
	hashSl := NewSignatureListFromHash(hash, EFISHA256, NewGUID())
	assert.False(t, hashSl.IsX509())
}

func TestSignatureList_IsSHA256(t *testing.T) {
	hash := make([]byte, 32)
	sl := NewSignatureListFromHash(hash, EFISHA256, NewGUID())
	assert.True(t, sl.IsSHA256())

	certDER := generateTestCert(t)
	certSl := NewSignatureListFromCert(certDER, NewGUID())
	assert.False(t, certSl.IsSHA256())
}

func TestSignatureList_SignatureCount(t *testing.T) {
	hash := make([]byte, 32)
	sl := NewSignatureListFromHash(hash, EFISHA256, NewGUID())
	assert.Equal(t, 1, sl.SignatureCount())

	hash2 := make([]byte, 32)
	rand.Read(hash2)
	_ = sl.AddSignature(SignatureData{Owner: NewGUID(), Data: hash2})
	assert.Equal(t, 2, sl.SignatureCount())
}

func TestSignatureList_RoundTrip(t *testing.T) {
	// Test that serialization and parsing produces identical results
	tests := []struct {
		name string
		sl   *SignatureList
	}{
		{
			name: "single cert",
			sl:   NewSignatureListFromCert(generateTestCert(t), NewGUID()),
		},
		{
			name: "single hash",
			sl:   NewSignatureListFromHash(make([]byte, 32), EFISHA256, NewGUID()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.sl.Bytes()
			parsed, _, err := ParseSignatureList(data)
			require.NoError(t, err)

			// Re-serialize and compare
			data2 := parsed.Bytes()
			assert.Equal(t, data, data2)
		})
	}
}
