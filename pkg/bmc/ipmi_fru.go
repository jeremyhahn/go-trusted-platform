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
	"fmt"
	"strings"
)

// fruData holds the parsed fields from a FRU information structure.
// Per IPMI Platform Management FRU Information Storage Definition v1.0.
type fruData struct {
	BoardManufacturer   string
	BoardProduct        string
	BoardSerial         string
	BoardPartNumber     string
	ProductManufacturer string
	ProductName         string
	ProductPartNumber   string
	ProductVersion      string
	ProductSerial       string
	ProductAssetTag     string
}

// parseFRU parses the raw FRU data per IPMI Platform Management FRU spec.
//
// FRU Common Header (8 bytes):
//
//	Byte 0: Format version (0x01)
//	Byte 1: Internal Use Area offset (in multiples of 8 bytes)
//	Byte 2: Chassis Info Area offset
//	Byte 3: Board Info Area offset
//	Byte 4: Product Info Area offset
//	Byte 5: Multi-Record Area offset
//	Byte 6: Padding (0x00)
//	Byte 7: Header checksum
func parseFRU(data []byte) (*fruData, error) {
	if len(data) < 8 {
		return nil, ErrFRURead{Reason: "FRU data too short for common header"}
	}
	if data[0] != 0x01 {
		return nil, ErrFRURead{Reason: fmt.Sprintf("unsupported FRU format version: %d", data[0])}
	}

	fru := &fruData{}

	// Parse Board Info Area
	boardOffset := int(data[3]) * 8
	if boardOffset > 0 && boardOffset < len(data) {
		parseBoardArea(data[boardOffset:], fru)
	}

	// Parse Product Info Area
	productOffset := int(data[4]) * 8
	if productOffset > 0 && productOffset < len(data) {
		parseProductArea(data[productOffset:], fru)
	}

	return fru, nil
}

// parseBoardArea parses the Board Info Area of FRU data.
//
// Board Info Area layout:
//
//	Byte 0: Format version
//	Byte 1: Board area length (in multiples of 8 bytes)
//	Byte 2: Language code
//	Byte 3-5: Manufacturing date/time
//	Byte 6+: TLV fields: Manufacturer, Product Name, Serial Number, Part Number, FRU File ID
func parseBoardArea(data []byte, fru *fruData) {
	if len(data) < 6 {
		return
	}
	// Skip version (1), length (1), language (1), mfg date (3) = 6 bytes
	offset := 6
	fields := []*string{
		&fru.BoardManufacturer,
		&fru.BoardProduct,
		&fru.BoardSerial,
		&fru.BoardPartNumber,
	}
	for i := range fields {
		val, n := readFRUField(data, offset)
		if n == 0 {
			break
		}
		*fields[i] = val
		offset += n
	}
}

// parseProductArea parses the Product Info Area of FRU data.
//
// Product Info Area layout:
//
//	Byte 0: Format version
//	Byte 1: Product area length (in multiples of 8 bytes)
//	Byte 2: Language code
//	Byte 3+: TLV fields: Manufacturer, Product Name, Part/Model Number, Version, Serial Number, Asset Tag, FRU File ID
func parseProductArea(data []byte, fru *fruData) {
	if len(data) < 3 {
		return
	}
	// Skip version (1), length (1), language (1) = 3 bytes
	offset := 3
	fields := []*string{
		&fru.ProductManufacturer,
		&fru.ProductName,
		&fru.ProductPartNumber,
		&fru.ProductVersion,
		&fru.ProductSerial,
		&fru.ProductAssetTag,
	}
	for i := range fields {
		val, n := readFRUField(data, offset)
		if n == 0 {
			break
		}
		*fields[i] = val
		offset += n
	}
}

// readFRUField reads a single TLV-encoded field from FRU data at the given offset.
// Returns the decoded string and the number of bytes consumed (including the type/length byte).
// Returns ("", 0) if the field cannot be read or is an end-of-fields marker.
//
// Type/Length byte encoding:
//
//	Bits 7:6 = type: 00=binary, 01=BCD+, 10=6-bit packed ASCII, 11=8-bit ASCII/Latin1
//	Bits 5:0 = length in bytes (for type 11) or coded length
//	0xC1 = end-of-fields marker
func readFRUField(data []byte, offset int) (string, int) {
	if offset >= len(data) {
		return "", 0
	}
	typeLen := data[offset]
	if typeLen == 0xC1 {
		return "", 0 // End of fields
	}
	fieldLen := int(typeLen & 0x3F)
	fieldType := (typeLen >> 6) & 0x03
	if offset+1+fieldLen > len(data) {
		return "", 0
	}
	raw := data[offset+1 : offset+1+fieldLen]

	var val string
	switch fieldType {
	case 0x03: // 8-bit ASCII / Latin-1
		val = strings.TrimRight(string(raw), "\x00 ")
	case 0x00: // Binary
		val = fmt.Sprintf("%x", raw)
	default:
		// BCD+ and 6-bit packed ASCII: fall back to hex representation.
		val = fmt.Sprintf("%x", raw)
	}
	return val, 1 + fieldLen
}
