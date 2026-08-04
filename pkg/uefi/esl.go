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
	"bytes"
	"encoding/binary"
	"fmt"
)

// NewSignatureListFromCert creates an EFI_SIGNATURE_LIST containing an X.509 certificate
// The certificate must be DER-encoded (not PEM)
func NewSignatureListFromCert(certDER []byte, ownerGUID GUID) *SignatureList {
	sigData := SignatureData{
		Owner: ownerGUID,
		Data:  certDER,
	}

	// SignatureSize = GUID (16 bytes) + certificate length
	sigSize := uint32(GUIDSize + len(certDER))

	// SignatureListSize = header (28 bytes) + one signature
	listSize := uint32(SignatureListHeaderSize + sigSize)

	return &SignatureList{
		SignatureType:       EFIX509Cert,
		SignatureListSize:   listSize,
		SignatureHeaderSize: 0,
		SignatureSize:       sigSize,
		Signatures:          []SignatureData{sigData},
	}
}

// NewSignatureListFromHash creates an EFI_SIGNATURE_LIST containing a hash
// hashType should be EFISHA256, EFISHA384, or EFISHA512
func NewSignatureListFromHash(hash []byte, hashType GUID, ownerGUID GUID) *SignatureList {
	sigData := SignatureData{
		Owner: ownerGUID,
		Data:  hash,
	}

	// SignatureSize = GUID (16 bytes) + hash length
	sigSize := uint32(GUIDSize + len(hash))

	// SignatureListSize = header (28 bytes) + one signature
	listSize := uint32(SignatureListHeaderSize + sigSize)

	return &SignatureList{
		SignatureType:       hashType,
		SignatureListSize:   listSize,
		SignatureHeaderSize: 0,
		SignatureSize:       sigSize,
		Signatures:          []SignatureData{sigData},
	}
}

// AddSignature adds a signature to the list
// All signatures in a list must have the same type and size
func (sl *SignatureList) AddSignature(data SignatureData) error {
	newSize := uint32(GUIDSize + len(data.Data))

	// Check if this is the first signature
	if len(sl.Signatures) == 0 {
		sl.SignatureSize = newSize
	} else if sl.SignatureSize != newSize {
		return &MessageError{Msg: fmt.Sprintf("signature size mismatch: expected %d, got %d", sl.SignatureSize, newSize)}
	}

	sl.Signatures = append(sl.Signatures, data)

	// Update list size
	sl.SignatureListSize = uint32(SignatureListHeaderSize) +
		sl.SignatureHeaderSize +
		uint32(len(sl.Signatures))*sl.SignatureSize

	return nil
}

// Bytes serializes the SignatureList to binary format
func (sl *SignatureList) Bytes() []byte {
	buf := new(bytes.Buffer)

	// Write header
	buf.Write(sl.SignatureType.Bytes())
	_ = binary.Write(buf, binary.LittleEndian, sl.SignatureListSize)
	_ = binary.Write(buf, binary.LittleEndian, sl.SignatureHeaderSize)
	_ = binary.Write(buf, binary.LittleEndian, sl.SignatureSize)

	// Write optional header
	if len(sl.Header) > 0 {
		buf.Write(sl.Header)
	}

	// Write signatures
	for _, sig := range sl.Signatures {
		buf.Write(sig.Owner.Bytes())
		buf.Write(sig.Data)

		// Pad to SignatureSize if needed
		written := GUIDSize + len(sig.Data)
		if uint32(written) < sl.SignatureSize {
			padding := make([]byte, sl.SignatureSize-uint32(written))
			buf.Write(padding)
		}
	}

	return buf.Bytes()
}

// ParseSignatureList parses an EFI_SIGNATURE_LIST from binary data
func ParseSignatureList(data []byte) (*SignatureList, int, error) {
	if len(data) < SignatureListHeaderSize {
		return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "data too short for signature list header"}}
	}

	sl := &SignatureList{}

	// Parse header
	var err error
	sl.SignatureType, err = GUIDFromBytes(data[0:16])
	if err != nil {
		return nil, 0, &WrappedError{Msg: "failed to parse signature type GUID", Err: err}
	}

	sl.SignatureListSize = binary.LittleEndian.Uint32(data[16:20])
	sl.SignatureHeaderSize = binary.LittleEndian.Uint32(data[20:24])
	sl.SignatureSize = binary.LittleEndian.Uint32(data[24:28])

	// Validate sizes
	if sl.SignatureListSize < SignatureListHeaderSize {
		return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "signature list size too small"}}
	}
	if sl.SignatureSize < GUIDSize {
		return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "signature size too small (must include GUID)"}}
	}
	if int(sl.SignatureListSize) > len(data) {
		return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "signature list size exceeds data length"}}
	}

	// Parse optional header
	offset := SignatureListHeaderSize
	if sl.SignatureHeaderSize > 0 {
		if offset+int(sl.SignatureHeaderSize) > len(data) {
			return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "signature header exceeds data length"}}
		}
		sl.Header = make([]byte, sl.SignatureHeaderSize)
		copy(sl.Header, data[offset:offset+int(sl.SignatureHeaderSize)])
		offset += int(sl.SignatureHeaderSize)
	}

	// Calculate number of signatures
	sigDataSize := sl.SignatureListSize - SignatureListHeaderSize - sl.SignatureHeaderSize
	if sigDataSize%sl.SignatureSize != 0 {
		return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: "signature data size not aligned"}}
	}
	numSigs := sigDataSize / sl.SignatureSize

	// Parse signatures
	sl.Signatures = make([]SignatureData, 0, numSigs)
	for i := uint32(0); i < numSigs; i++ {
		if offset+int(sl.SignatureSize) > len(data) {
			return nil, 0, &SentinelCauseError{Sentinel: ErrInvalidFormat, Cause: &MessageError{Msg: fmt.Sprintf("signature %d exceeds data length", i)}}
		}

		sig := SignatureData{}
		sig.Owner, err = GUIDFromBytes(data[offset : offset+GUIDSize])
		if err != nil {
			return nil, 0, &WrappedError{Msg: fmt.Sprintf("failed to parse signature %d owner GUID", i), Err: err}
		}

		dataLen := sl.SignatureSize - GUIDSize
		sig.Data = make([]byte, dataLen)
		copy(sig.Data, data[offset+GUIDSize:offset+int(sl.SignatureSize)])

		sl.Signatures = append(sl.Signatures, sig)
		offset += int(sl.SignatureSize)
	}

	return sl, int(sl.SignatureListSize), nil
}

// ParseSignatureLists parses multiple concatenated EFI_SIGNATURE_LISTs
func ParseSignatureLists(data []byte) ([]*SignatureList, error) {
	var lists []*SignatureList
	offset := 0

	for offset < len(data) {
		sl, consumed, err := ParseSignatureList(data[offset:])
		if err != nil {
			return lists, &WrappedError{Msg: fmt.Sprintf("failed to parse signature list at offset %d", offset), Err: err}
		}
		lists = append(lists, sl)
		offset += consumed
	}

	return lists, nil
}

// ConcatSignatureLists concatenates multiple signature lists into a single byte slice
func ConcatSignatureLists(lists ...*SignatureList) []byte {
	buf := new(bytes.Buffer)
	for _, sl := range lists {
		buf.Write(sl.Bytes())
	}
	return buf.Bytes()
}

// SignatureCount returns the number of signatures in the list
func (sl *SignatureList) SignatureCount() int {
	return len(sl.Signatures)
}

// IsX509 returns true if the signature list contains X.509 certificates
func (sl *SignatureList) IsX509() bool {
	return sl.SignatureType.Equal(EFIX509Cert)
}

// IsSHA256 returns true if the signature list contains SHA-256 hashes
func (sl *SignatureList) IsSHA256() bool {
	return sl.SignatureType.Equal(EFISHA256)
}
