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

package uki

import (
	"bytes"
	stdpe "debug/pe"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMinimalPE builds a valid PE32+ binary in memory with the specified
// number of existing sections and extra header padding bytes (space for
// additional section header entries between the section table and the first
// section's raw data).
//
// Layout:
//
//	[0x00]  DOS header          (64 bytes)  - MZ sig, PE offset at 0x3C
//	[0x40]  PE signature        (4 bytes)   - "PE\0\0"
//	[0x44]  COFF header         (20 bytes)  - numSections, sizeOfOptionalHeader=112
//	[0x58]  Optional header     (112 bytes) - Magic=0x20b, SizeOfHeaders, SizeOfImage
//	[0xC8]  Section headers     (40 * numSections bytes)
//	[...]   Header padding      (headerPadding bytes of zeros)
//	[aligned to 512] Section data (512 bytes of 0xCC per section)
func createMinimalPE(t *testing.T, numSections int, headerPadding int) []byte {
	t.Helper()

	const (
		dosHeaderSize      = 64
		peSignatureSize    = 4
		coffHeaderSize     = 20
		optionalHeaderSize = 112 // PE32+ fixed fields, no data directories
		sectionDataSize    = 512 // each section gets 512 bytes of 0xCC
	)

	peOffset := uint32(dosHeaderSize) // PE sig starts right after DOS header
	coffOff := peOffset + peSignatureSize
	optOff := coffOff + coffHeaderSize
	sectionTableOff := optOff + optionalHeaderSize
	sectionTableSize := uint32(numSections) * sectionHeaderSize

	// First section raw data starts at the next 512-byte boundary after
	// the section table + padding.
	rawHeaderEnd := sectionTableOff + sectionTableSize + uint32(headerPadding)
	firstSectionRawData := alignUp(rawHeaderEnd, fileAlignment)

	totalSize := firstSectionRawData + uint32(numSections)*sectionDataSize
	sizeOfImage := alignUp(totalSize, defaultSectionAlignment)

	buf := make([]byte, totalSize)

	// --- DOS header ---
	binary.LittleEndian.PutUint16(buf[0:2], dosSignature)   // "MZ"
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peOffset) // e_lfanew

	// --- PE signature ---
	binary.LittleEndian.PutUint32(buf[peOffset:peOffset+4], peSignature)

	// --- COFF header (20 bytes at coffOff) ---
	// Machine (offset 0): 0x8664 = AMD64
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], 0x8664)
	// NumberOfSections (offset 2)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], uint16(numSections))
	// SizeOfOptionalHeader (offset 16)
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], optionalHeaderSize)

	// --- Optional header (112 bytes at optOff) ---
	// Magic (offset 0): 0x20b = PE32+
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x20b)
	// AddressOfEntryPoint (offset 16)
	binary.LittleEndian.PutUint32(buf[optOff+16:optOff+20], 0x1000)
	// SizeOfCode (offset 4)
	binary.LittleEndian.PutUint32(buf[optOff+4:optOff+8], 0x2000)
	// SizeOfImage (offset 56)
	binary.LittleEndian.PutUint32(buf[optOff+56:optOff+60], sizeOfImage)
	// SizeOfHeaders (offset 60)
	binary.LittleEndian.PutUint32(buf[optOff+60:optOff+64], firstSectionRawData)

	// --- Section headers (40 bytes each at sectionTableOff) ---
	for i := 0; i < numSections; i++ {
		off := sectionTableOff + uint32(i)*sectionHeaderSize
		rawDataPtr := firstSectionRawData + uint32(i)*sectionDataSize

		// Name (8 bytes)
		name := []byte(".sect")
		name = append(name, byte('0'+i))
		copy(buf[off:off+8], name)

		// VirtualSize (offset 8)
		binary.LittleEndian.PutUint32(buf[off+8:off+12], sectionDataSize)
		// VirtualAddress (offset 12)
		binary.LittleEndian.PutUint32(buf[off+12:off+16], 0x1000+uint32(i)*0x1000)
		// SizeOfRawData (offset 16)
		binary.LittleEndian.PutUint32(buf[off+16:off+20], sectionDataSize)
		// PointerToRawData (offset 20)
		binary.LittleEndian.PutUint32(buf[off+20:off+24], rawDataPtr)
		// Characteristics (offset 36): IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
		binary.LittleEndian.PutUint32(buf[off+36:off+40], 0x40000040)
	}

	// --- Section data: fill each section with 0xCC ---
	for i := 0; i < numSections; i++ {
		dataStart := firstSectionRawData + uint32(i)*sectionDataSize
		for j := uint32(0); j < sectionDataSize; j++ {
			buf[dataStart+j] = 0xCC
		}
	}

	return buf
}

func TestNewPEPatcher_ValidPE(t *testing.T) {
	pe := createMinimalPE(t, 1, 200)

	p, err := newPEPatcher(pe)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Verify parsed offsets
	assert.Equal(t, uint32(64), p.peHeaderOffset, "PE header should start at offset 64")
	assert.Equal(t, uint32(68), p.coffOffset, "COFF header should be at PE offset + 4")
	assert.Equal(t, uint32(88), p.optHeaderOffset, "Optional header should be at COFF offset + 20")

	// Verify parsed header values
	assert.Equal(t, uint16(1), p.numberOfSections, "should have 1 section")
	assert.Equal(t, uint16(112), p.sizeOfOptionalHeader, "optional header size should be 112")

	// SizeOfHeaders equals firstSectionRawData
	assert.Equal(t, p.firstSectionRawData, p.sizeOfHeaders, "SizeOfHeaders should match first section raw data offset")

	// SizeOfImage should be aligned to sectionAlignment
	assert.Equal(t, uint32(0), p.sizeOfImage%defaultSectionAlignment,
		"SizeOfImage should be aligned to section alignment")

	// Verify existing section was parsed
	require.Len(t, p.sections, 1)
	assert.Equal(t, uint32(512), p.sections[0].sizeOfRawData, "section raw data size should be 512")
	assert.Equal(t, p.firstSectionRawData, p.sections[0].pointerToRawData,
		"first section pointer should match firstSectionRawData")

	// Verify section table base
	expectedSectionTableBase := p.optHeaderOffset + uint32(p.sizeOfOptionalHeader)
	assert.Equal(t, expectedSectionTableBase, p.sectionTableBase,
		"section table base should be optHeaderOffset + sizeOfOptionalHeader")

	// Verify that the patcher made a copy (original slice is not the same backing array)
	pe[0] = 0xFF
	assert.Equal(t, uint16(dosSignature), binary.LittleEndian.Uint16(p.data[0:2]),
		"patcher should hold an independent copy of the data")
}

func TestNewPEPatcher_InvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "file too small",
			data:    make([]byte, 32),
			wantErr: "file too small for DOS header",
		},
		{
			name: "invalid DOS signature",
			data: func() []byte {
				buf := make([]byte, 512)
				// Write wrong DOS signature
				binary.LittleEndian.PutUint16(buf[0:2], 0xBEEF)
				return buf
			}(),
			wantErr: "invalid DOS signature",
		},
		{
			name: "invalid PE signature",
			data: func() []byte {
				buf := make([]byte, 512)
				// Valid DOS sig
				binary.LittleEndian.PutUint16(buf[0:2], dosSignature)
				// PE offset points to offset 64
				binary.LittleEndian.PutUint32(buf[0x3C:0x40], 64)
				// Wrong PE signature
				binary.LittleEndian.PutUint32(buf[64:68], 0xDEADBEEF)
				return buf
			}(),
			wantErr: "invalid PE signature",
		},
		{
			name: "PE offset beyond file",
			data: func() []byte {
				buf := make([]byte, 64)
				binary.LittleEndian.PutUint16(buf[0:2], dosSignature)
				// PE offset points past end of file
				binary.LittleEndian.PutUint32(buf[0x3C:0x40], 9999)
				return buf
			}(),
			wantErr: "PE header offset beyond file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := newPEPatcher(tt.data)
			require.Error(t, err)
			assert.Nil(t, p)

			var peErr *ErrInvalidPE
			require.ErrorAs(t, err, &peErr, "error should be *ErrInvalidPE")
			assert.Contains(t, peErr.Error(), tt.wantErr)
		})
	}
}

func TestPEPatcher_AddSection(t *testing.T) {
	// Create PE with 1 section and 200 bytes padding (room for ~5 more headers)
	originalPE := createMinimalPE(t, 1, 200)
	originalCopy := make([]byte, len(originalPE))
	copy(originalCopy, originalPE)

	p, err := newPEPatcher(originalPE)
	require.NoError(t, err)

	sectionData := []byte("hello section data for testing")
	err = p.addSection(".test", sectionData, 0x40000040)
	require.NoError(t, err)

	result := p.bytes()

	// Verify NumberOfSections incremented in the byte slice
	coffOff := p.coffOffset
	numSections := binary.LittleEndian.Uint16(result[coffOff+2 : coffOff+4])
	assert.Equal(t, uint16(2), numSections, "NumberOfSections should be 2 after adding a section")

	// Verify the new section header was written at the expected offset
	newHeaderOff := p.sectionTableBase + 1*sectionHeaderSize // after the first section header
	var nameBytes [8]byte
	copy(nameBytes[:], result[newHeaderOff:newHeaderOff+8])
	assert.Equal(t, ".test\x00\x00\x00", string(nameBytes[:]), "section name should be .test zero-padded")

	// Verify SizeOfRawData in the new header is file-aligned
	newSizeOfRawData := binary.LittleEndian.Uint32(result[newHeaderOff+16 : newHeaderOff+20])
	assert.Equal(t, alignUp(uint32(len(sectionData)), fileAlignment), newSizeOfRawData,
		"new section SizeOfRawData should be file-aligned")
	assert.Equal(t, uint32(0), newSizeOfRawData%fileAlignment,
		"new section SizeOfRawData must be a multiple of FileAlignment")

	// Verify PointerToRawData in the new header
	newPointerToRawData := binary.LittleEndian.Uint32(result[newHeaderOff+20 : newHeaderOff+24])
	assert.Equal(t, uint32(0), newPointerToRawData%fileAlignment,
		"new section PointerToRawData should be file-aligned")

	// Verify Characteristics
	newCharacteristics := binary.LittleEndian.Uint32(result[newHeaderOff+36 : newHeaderOff+40])
	assert.Equal(t, uint32(0x40000040), newCharacteristics,
		"new section characteristics should match input")

	// Verify VirtualAddress is non-zero and section-aligned (OVMF requirement)
	newVirtualAddr := binary.LittleEndian.Uint32(result[newHeaderOff+12 : newHeaderOff+16])
	assert.NotEqual(t, uint32(0), newVirtualAddr,
		"new section VirtualAddress must be non-zero for OVMF compatibility")
	assert.Equal(t, uint32(0), newVirtualAddr%defaultSectionAlignment,
		"new section VirtualAddress should be section-aligned")

	// Verify VirtualSize matches the data length
	newVirtualSize := binary.LittleEndian.Uint32(result[newHeaderOff+8 : newHeaderOff+12])
	assert.Equal(t, uint32(len(sectionData)), newVirtualSize,
		"new section VirtualSize should match data length")

	// Verify VirtualAddress doesn't overlap with existing section's virtual range
	origVA := binary.LittleEndian.Uint32(result[p.sectionTableBase+12 : p.sectionTableBase+16])
	origVS := binary.LittleEndian.Uint32(result[p.sectionTableBase+8 : p.sectionTableBase+12])
	assert.GreaterOrEqual(t, newVirtualAddr, alignUp(origVA+origVS, defaultSectionAlignment),
		"new section VirtualAddress must be past existing section's virtual range")

	// Verify SizeOfImage was updated to cover the new section
	updatedSizeOfImage := binary.LittleEndian.Uint32(result[p.optHeaderOffset+56 : p.optHeaderOffset+60])
	assert.GreaterOrEqual(t, updatedSizeOfImage, newVirtualAddr+newVirtualSize,
		"SizeOfImage must cover the new section's virtual range")
	assert.Equal(t, uint32(0), updatedSizeOfImage%defaultSectionAlignment,
		"SizeOfImage must be section-aligned")

	// Verify section data is at the declared offset
	actualData := result[newPointerToRawData : newPointerToRawData+uint32(len(sectionData))]
	assert.Equal(t, sectionData, actualData, "section data should be at PointerToRawData")

	// Verify original kernel bytes before section table are UNTOUCHED.
	// In-place mutations: NumberOfSections (2 bytes at coffOff+2) and
	// SizeOfImage (4 bytes at optHeaderOffset+56). Compare the ranges
	// on either side of these fields up to the original section table end.
	originalTableEnd := p.sectionTableBase + 1*sectionHeaderSize
	numSectionsStart := coffOff + 2
	numSectionsEnd := coffOff + 4
	sizeOfImageStart := p.optHeaderOffset + 56
	sizeOfImageEnd := p.optHeaderOffset + 60

	// Bytes before the NumberOfSections field
	assert.Equal(t, originalCopy[:numSectionsStart], p.data[:numSectionsStart],
		"bytes before NumberOfSections field must be identical to the original")
	// Bytes between NumberOfSections and SizeOfImage
	assert.Equal(t, originalCopy[numSectionsEnd:sizeOfImageStart],
		p.data[numSectionsEnd:sizeOfImageStart],
		"bytes between NumberOfSections and SizeOfImage must be identical to the original")
	// Bytes after SizeOfImage up to original section table end
	assert.Equal(t, originalCopy[sizeOfImageEnd:originalTableEnd],
		p.data[sizeOfImageEnd:originalTableEnd],
		"bytes after SizeOfImage field must be identical to the original")

	// Also verify original section data is untouched
	origFirstSection := p.sections[0]
	origDataStart := origFirstSection.pointerToRawData
	origDataEnd := origDataStart + origFirstSection.sizeOfRawData
	for i := origDataStart; i < origDataEnd; i++ {
		assert.Equal(t, byte(0xCC), result[i],
			"original section data byte at offset %d should be 0xCC", i)
	}
}

func TestPEPatcher_AddSection_NameTooLong(t *testing.T) {
	pe := createMinimalPE(t, 1, 200)
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	err = p.addSection(".toolongname", []byte("data"), 0x40000040)
	require.Error(t, err)

	var nameErr *ErrSectionNameTooLong
	require.ErrorAs(t, err, &nameErr, "error should be *ErrSectionNameTooLong")
	assert.Contains(t, nameErr.Error(), ".toolongname")
}

func TestPEPatcher_AddSection_NoSpace(t *testing.T) {
	// The fixed header layout uses:
	//   DOS=64 + PE sig=4 + COFF=20 + OptHdr=112 = 200 bytes
	// Section table starts at offset 200. With 7 sections and 0 padding:
	//   table end = 200 + 7*40 = 480
	//   firstSectionRawData = alignUp(480, 512) = 512
	//   available = 512 - 480 = 32 bytes (less than 40 needed for a header)
	pe := createMinimalPE(t, 7, 0)
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	// Verify there truly is no space
	currentTableEnd := p.sectionTableBase + uint32(p.numberOfSections)*sectionHeaderSize
	available := int(p.firstSectionRawData) - int(currentTableEnd)
	require.Less(t, available, sectionHeaderSize,
		"test setup: should have less than 40 bytes available (have %d)", available)

	err = p.addSection(".new", []byte("data"), 0x40000040)
	require.Error(t, err)

	var spaceErr *ErrNoHeaderSpace
	require.ErrorAs(t, err, &spaceErr, "error should be *ErrNoHeaderSpace")
	assert.Contains(t, spaceErr.Error(), "no header space")
}

func TestPEPatcher_PreservesOriginalHeaders(t *testing.T) {
	pe := createMinimalPE(t, 2, 200)

	// Record known values from the optional header and section headers
	// before patching.
	peOff := uint32(64)
	coffOff := peOff + 4
	optOff := coffOff + 20
	sectionTableOff := optOff + 112

	// Optional header fields to verify
	originalEntryPoint := binary.LittleEndian.Uint32(pe[optOff+16 : optOff+20])
	originalSizeOfCode := binary.LittleEndian.Uint32(pe[optOff+4 : optOff+8])
	originalMagic := binary.LittleEndian.Uint16(pe[optOff : optOff+2])
	originalSizeOfImage := binary.LittleEndian.Uint32(pe[optOff+56 : optOff+60])
	originalSizeOfHeaders := binary.LittleEndian.Uint32(pe[optOff+60 : optOff+64])

	// Section 0 header fields
	sec0Off := sectionTableOff
	originalSec0VirtualSize := binary.LittleEndian.Uint32(pe[sec0Off+8 : sec0Off+12])
	originalSec0VirtualAddr := binary.LittleEndian.Uint32(pe[sec0Off+12 : sec0Off+16])
	originalSec0SizeOfRaw := binary.LittleEndian.Uint32(pe[sec0Off+16 : sec0Off+20])
	originalSec0PtrToRaw := binary.LittleEndian.Uint32(pe[sec0Off+20 : sec0Off+24])
	originalSec0Chars := binary.LittleEndian.Uint32(pe[sec0Off+36 : sec0Off+40])

	// Section 1 header fields
	sec1Off := sectionTableOff + sectionHeaderSize
	originalSec1VirtualSize := binary.LittleEndian.Uint32(pe[sec1Off+8 : sec1Off+12])
	originalSec1VirtualAddr := binary.LittleEndian.Uint32(pe[sec1Off+12 : sec1Off+16])
	originalSec1SizeOfRaw := binary.LittleEndian.Uint32(pe[sec1Off+16 : sec1Off+20])
	originalSec1PtrToRaw := binary.LittleEndian.Uint32(pe[sec1Off+20 : sec1Off+24])
	originalSec1Chars := binary.LittleEndian.Uint32(pe[sec1Off+36 : sec1Off+40])

	// Now patch
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	err = p.addSection(".added", []byte("new section data"), 0x40000040)
	require.NoError(t, err)

	result := p.bytes()

	// Verify optional header fields are unchanged
	assert.Equal(t, originalMagic,
		binary.LittleEndian.Uint16(result[optOff:optOff+2]),
		"Magic should be preserved")
	assert.Equal(t, originalSizeOfCode,
		binary.LittleEndian.Uint32(result[optOff+4:optOff+8]),
		"SizeOfCode should be preserved")
	assert.Equal(t, originalEntryPoint,
		binary.LittleEndian.Uint32(result[optOff+16:optOff+20]),
		"AddressOfEntryPoint should be preserved")
	// SizeOfImage may be updated by addSection to cover the new section's
	// virtual range. Verify it is >= the original and properly aligned.
	newSizeOfImage := binary.LittleEndian.Uint32(result[optOff+56 : optOff+60])
	assert.GreaterOrEqual(t, newSizeOfImage, originalSizeOfImage,
		"SizeOfImage should be >= original after adding a section")
	assert.Equal(t, uint32(0), newSizeOfImage%defaultSectionAlignment,
		"SizeOfImage should be aligned to section alignment")
	assert.Equal(t, originalSizeOfHeaders,
		binary.LittleEndian.Uint32(result[optOff+60:optOff+64]),
		"SizeOfHeaders should be preserved")

	// Verify section 0 header is unchanged
	assert.Equal(t, originalSec0VirtualSize,
		binary.LittleEndian.Uint32(result[sec0Off+8:sec0Off+12]),
		"Section 0 VirtualSize should be preserved")
	assert.Equal(t, originalSec0VirtualAddr,
		binary.LittleEndian.Uint32(result[sec0Off+12:sec0Off+16]),
		"Section 0 VirtualAddress should be preserved")
	assert.Equal(t, originalSec0SizeOfRaw,
		binary.LittleEndian.Uint32(result[sec0Off+16:sec0Off+20]),
		"Section 0 SizeOfRawData should be preserved")
	assert.Equal(t, originalSec0PtrToRaw,
		binary.LittleEndian.Uint32(result[sec0Off+20:sec0Off+24]),
		"Section 0 PointerToRawData should be preserved")
	assert.Equal(t, originalSec0Chars,
		binary.LittleEndian.Uint32(result[sec0Off+36:sec0Off+40]),
		"Section 0 Characteristics should be preserved")

	// Verify section 1 header is unchanged
	assert.Equal(t, originalSec1VirtualSize,
		binary.LittleEndian.Uint32(result[sec1Off+8:sec1Off+12]),
		"Section 1 VirtualSize should be preserved")
	assert.Equal(t, originalSec1VirtualAddr,
		binary.LittleEndian.Uint32(result[sec1Off+12:sec1Off+16]),
		"Section 1 VirtualAddress should be preserved")
	assert.Equal(t, originalSec1SizeOfRaw,
		binary.LittleEndian.Uint32(result[sec1Off+16:sec1Off+20]),
		"Section 1 SizeOfRawData should be preserved")
	assert.Equal(t, originalSec1PtrToRaw,
		binary.LittleEndian.Uint32(result[sec1Off+20:sec1Off+24]),
		"Section 1 PointerToRawData should be preserved")
	assert.Equal(t, originalSec1Chars,
		binary.LittleEndian.Uint32(result[sec1Off+36:sec1Off+40]),
		"Section 1 Characteristics should be preserved")
}

func TestPEPatcher_MultipleAddSections(t *testing.T) {
	pe := createMinimalPE(t, 1, 400) // 400 bytes padding = room for 10 more headers
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	type sectionInput struct {
		name string
		data []byte
	}

	sections := []sectionInput{
		{name: ".cmd", data: []byte("root=/dev/sda1 ro quiet")},
		{name: ".osrel", data: []byte("NAME=Linux\nVERSION=6.0")},
		{name: ".initrd", data: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}},
	}

	for _, s := range sections {
		err := p.addSection(s.name, s.data, 0x40000040)
		require.NoError(t, err, "adding section %s should succeed", s.name)
	}

	result := p.bytes()

	// Verify total number of sections: 1 original + 3 added = 4
	coffOff := p.coffOffset
	numSections := binary.LittleEndian.Uint16(result[coffOff+2 : coffOff+4])
	assert.Equal(t, uint16(4), numSections, "should have 4 sections total")

	// Verify each added section header and data
	for i, s := range sections {
		hdrOff := p.sectionTableBase + uint32(1+i)*sectionHeaderSize // skip original section

		// Read name from header
		var nameBytes [8]byte
		copy(nameBytes[:], result[hdrOff:hdrOff+8])
		expectedName := make([]byte, 8)
		copy(expectedName, s.name)
		assert.Equal(t, expectedName, nameBytes[:],
			"section %d name should be %s", i, s.name)

		// Read SizeOfRawData (must be file-aligned)
		sizeOfRaw := binary.LittleEndian.Uint32(result[hdrOff+16 : hdrOff+20])
		assert.Equal(t, alignUp(uint32(len(s.data)), fileAlignment), sizeOfRaw,
			"section %d SizeOfRawData should be file-aligned", i)
		assert.Equal(t, uint32(0), sizeOfRaw%fileAlignment,
			"section %d SizeOfRawData must be a multiple of FileAlignment", i)

		// Read PointerToRawData
		ptrToRaw := binary.LittleEndian.Uint32(result[hdrOff+20 : hdrOff+24])
		assert.Equal(t, uint32(0), ptrToRaw%fileAlignment,
			"section %d PointerToRawData should be file-aligned", i)

		// Verify data at the offset
		assert.Equal(t, s.data, result[ptrToRaw:ptrToRaw+uint32(len(s.data))],
			"section %d data should match", i)

		// Read Characteristics
		chars := binary.LittleEndian.Uint32(result[hdrOff+36 : hdrOff+40])
		assert.Equal(t, uint32(0x40000040), chars,
			"section %d characteristics should match", i)

		// Verify VirtualAddress is non-zero and section-aligned
		va := binary.LittleEndian.Uint32(result[hdrOff+12 : hdrOff+16])
		assert.NotEqual(t, uint32(0), va,
			"section %d VirtualAddress must be non-zero", i)
		assert.Equal(t, uint32(0), va%defaultSectionAlignment,
			"section %d VirtualAddress should be section-aligned", i)

		// Verify VirtualSize matches data length
		vs := binary.LittleEndian.Uint32(result[hdrOff+8 : hdrOff+12])
		assert.Equal(t, uint32(len(s.data)), vs,
			"section %d VirtualSize should match data length", i)
	}

	// Verify sections don't overlap: each section's raw data range (using
	// file-aligned SizeOfRawData) must not overlap with any other section.
	type dataRange struct {
		start uint32
		end   uint32
	}
	allSections := make([]dataRange, 0, 4)
	for i := uint16(0); i < numSections; i++ {
		hdrOff := p.sectionTableBase + uint32(i)*sectionHeaderSize
		ptrToRaw := binary.LittleEndian.Uint32(result[hdrOff+20 : hdrOff+24])
		sizeOfRaw := binary.LittleEndian.Uint32(result[hdrOff+16 : hdrOff+20])
		allSections = append(allSections, dataRange{start: ptrToRaw, end: ptrToRaw + sizeOfRaw})
	}
	// Also verify total file size accommodates all section data
	for idx, sec := range allSections {
		assert.LessOrEqual(t, sec.end, uint32(len(result)),
			"section %d raw data end (%d) exceeds file size (%d)", idx, sec.end, len(result))
	}
	for i := 0; i < len(allSections); i++ {
		for j := i + 1; j < len(allSections); j++ {
			a, b := allSections[i], allSections[j]
			overlaps := a.start < b.end && b.start < a.end
			assert.False(t, overlaps,
				"sections %d and %d should not overlap: [%d,%d) vs [%d,%d)",
				i, j, a.start, a.end, b.start, b.end)
		}
	}

	// Verify the original section data (0xCC fill) is intact
	origPtrToRaw := binary.LittleEndian.Uint32(result[p.sectionTableBase+20 : p.sectionTableBase+24])
	origSizeOfRaw := binary.LittleEndian.Uint32(result[p.sectionTableBase+16 : p.sectionTableBase+20])
	for off := origPtrToRaw; off < origPtrToRaw+origSizeOfRaw; off++ {
		assert.Equal(t, byte(0xCC), result[off],
			"original section data at offset %d should be 0xCC", off)
	}
}

func TestNewPEPatcher_MultipleSectionsParseCorrectly(t *testing.T) {
	pe := createMinimalPE(t, 3, 100)

	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	assert.Equal(t, uint16(3), p.numberOfSections)
	require.Len(t, p.sections, 3)

	// All sections should have 512 bytes of raw data
	for i, s := range p.sections {
		assert.Equal(t, uint32(512), s.sizeOfRawData,
			"section %d should have 512 bytes of raw data", i)
	}

	// firstSectionRawData should be the minimum PointerToRawData
	minPtr := p.sections[0].pointerToRawData
	for _, s := range p.sections[1:] {
		if s.pointerToRawData < minPtr {
			minPtr = s.pointerToRawData
		}
	}
	assert.Equal(t, minPtr, p.firstSectionRawData,
		"firstSectionRawData should be the minimum PointerToRawData")
}

func TestNewPEPatcher_ZeroSections(t *testing.T) {
	pe := createMinimalPE(t, 0, 100)

	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	assert.Equal(t, uint16(0), p.numberOfSections)
	assert.Empty(t, p.sections)
	// With zero sections, firstSectionRawData falls back to sizeOfHeaders
	assert.Equal(t, p.sizeOfHeaders, p.firstSectionRawData)
}

func TestAlignUp(t *testing.T) {
	tests := []struct {
		value     uint32
		alignment uint32
		expected  uint32
	}{
		{0, 512, 0},
		{1, 512, 512},
		{511, 512, 512},
		{512, 512, 512},
		{513, 512, 1024},
		{4096, 4096, 4096},
		{4097, 4096, 8192},
	}

	for _, tt := range tests {
		result := alignUp(tt.value, tt.alignment)
		assert.Equal(t, tt.expected, result,
			"alignUp(%d, %d) should be %d", tt.value, tt.alignment, tt.expected)
	}
}

// TestPEPatcher_SizeOfRawDataAlignment verifies that SizeOfRawData is always
// a multiple of FileAlignment (512 bytes) after adding sections of various
// sizes. This is the root cause of OVMF rejecting non-compliant PE images.
func TestPEPatcher_SizeOfRawDataAlignment(t *testing.T) {
	testCases := []struct {
		name     string
		dataSize int
	}{
		{"1_byte", 1},
		{"exactly_512", 512},
		{"513_bytes", 513},
		{"1023_bytes", 1023},
		{"1024_bytes", 1024},
		{"large_unaligned", 65537},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pe := createMinimalPE(t, 1, 200)
			p, err := newPEPatcher(pe)
			require.NoError(t, err)

			data := make([]byte, tc.dataSize)
			for i := range data {
				data[i] = 0xAA
			}

			err = p.addSection(".test", data, 0x40000040)
			require.NoError(t, err)

			result := p.bytes()

			// Read SizeOfRawData from the new section header
			newHeaderOff := p.sectionTableBase + 1*sectionHeaderSize
			sizeOfRawData := binary.LittleEndian.Uint32(result[newHeaderOff+16 : newHeaderOff+20])

			assert.Equal(t, uint32(0), sizeOfRawData%fileAlignment,
				"SizeOfRawData (%d) must be a multiple of FileAlignment (%d) for data size %d",
				sizeOfRawData, fileAlignment, tc.dataSize)
			assert.GreaterOrEqual(t, sizeOfRawData, uint32(tc.dataSize),
				"SizeOfRawData must be >= actual data size")

			// Verify file size accommodates all aligned section data
			ptrToRaw := binary.LittleEndian.Uint32(result[newHeaderOff+20 : newHeaderOff+24])
			assert.LessOrEqual(t, ptrToRaw+sizeOfRawData, uint32(len(result)),
				"file must be large enough to contain all section data including padding")

			// Verify actual data is present at the offset
			assert.Equal(t, data, result[ptrToRaw:ptrToRaw+uint32(tc.dataSize)],
				"original section data should be intact")

			// Verify padding bytes are zero
			for i := ptrToRaw + uint32(tc.dataSize); i < ptrToRaw+sizeOfRawData; i++ {
				assert.Equal(t, byte(0), result[i],
					"padding byte at offset %d should be zero", i)
			}
		})
	}
}

// TestPEPatcher_TotalFileSizeConsistency verifies that the total file size
// equals the sum of headers + all aligned section data, with no gaps or
// truncation that would cause OVMF's PE loader to reject the image.
func TestPEPatcher_TotalFileSizeConsistency(t *testing.T) {
	pe := createMinimalPE(t, 1, 400)
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	// Add sections with various non-aligned sizes
	sections := []struct {
		name string
		size int
	}{
		{".cmd", 37},
		{".osrel", 100},
		{".initrd", 1500},
	}

	for _, s := range sections {
		data := make([]byte, s.size)
		err := p.addSection(s.name, data, 0x40000040)
		require.NoError(t, err)
	}

	result := p.bytes()

	// Find the last section's end (PointerToRawData + SizeOfRawData)
	var maxEnd uint32
	for i := uint16(0); i < p.numberOfSections; i++ {
		hdrOff := p.sectionTableBase + uint32(i)*sectionHeaderSize
		ptrToRaw := binary.LittleEndian.Uint32(result[hdrOff+20 : hdrOff+24])
		sizeOfRaw := binary.LittleEndian.Uint32(result[hdrOff+16 : hdrOff+20])
		end := ptrToRaw + sizeOfRaw
		if end > maxEnd {
			maxEnd = end
		}
	}

	assert.Equal(t, maxEnd, uint32(len(result)),
		"total file size should equal the end of the last section's raw data")
}

// TestPEPatcher_NoObjectFileFlags verifies that section characteristics
// do not include object-file-only alignment flags (0x00100000 through
// 0x00E00000) which cause UEFI PE loaders to reject the image.
func TestPEPatcher_NoObjectFileFlags(t *testing.T) {
	pe := createMinimalPE(t, 1, 200)
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	// Use the correct characteristics (no alignment flags)
	const goodChars uint32 = 0x40000040
	err = p.addSection(".test", []byte("data"), goodChars)
	require.NoError(t, err)

	result := p.bytes()
	newHeaderOff := p.sectionTableBase + 1*sectionHeaderSize
	chars := binary.LittleEndian.Uint32(result[newHeaderOff+36 : newHeaderOff+40])

	// Object-file alignment flags occupy bits 20-23 (mask 0x00F00000)
	const objAlignMask uint32 = 0x00F00000
	assert.Equal(t, uint32(0), chars&objAlignMask,
		"section characteristics (0x%08X) must not contain object-file alignment flags", chars)
}

// TestPEPatcher_StdlibRoundTrip builds a PE with added sections and verifies
// the result can be parsed by Go's debug/pe standard library.
func TestPEPatcher_StdlibRoundTrip(t *testing.T) {
	pe := createMinimalPE(t, 1, 400)
	p, err := newPEPatcher(pe)
	require.NoError(t, err)

	// Add a few sections
	err = p.addSection(".cmdline", []byte("root=/dev/sda1 ro\x00"), 0x40000040)
	require.NoError(t, err)
	err = p.addSection(".initrd", make([]byte, 2048), 0x40000040)
	require.NoError(t, err)

	result := p.bytes()

	// Parse with debug/pe
	peFile, parseErr := stdpe.NewFile(bytes.NewReader(result))
	require.NoError(t, parseErr, "debug/pe should be able to parse the patched PE")
	defer func() { _ = peFile.Close() }()

	// Verify section count
	assert.Equal(t, 3, len(peFile.Sections), "should have 3 sections (1 original + 2 added)")

	// Verify each section is readable
	for _, sec := range peFile.Sections {
		data, readErr := sec.Data()
		require.NoError(t, readErr, "section %s should be readable", sec.Name)
		assert.NotNil(t, data, "section %s data should not be nil", sec.Name)
	}

	// Verify .cmdline content
	for _, sec := range peFile.Sections {
		if sec.Name == ".cmdline" {
			data, _ := sec.Data()
			// data may include padding zeros from file-aligned SizeOfRawData
			assert.True(t, len(data) >= 18, ".cmdline section data should be at least 18 bytes")
			assert.Equal(t, "root=/dev/sda1 ro\x00", string(data[:18]),
				".cmdline section should contain the command line")
		}
	}
}
