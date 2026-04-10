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
	"encoding/binary"
	"fmt"
)

// PE/COFF format constants
const (
	// DOS header signature "MZ"
	dosSignature = 0x5A4D

	// PE signature "PE\0\0"
	peSignature = 0x00004550

	// File alignment (must match OptionalHeader.FileAlignment)
	fileAlignment = 0x200 // 512 bytes

	// Default section alignment if not found in optional header
	defaultSectionAlignment = 0x1000 // 4KB

	// Size of a single section header entry
	sectionHeaderSize = 40
)

// ErrInvalidPE indicates the input is not a valid PE file.
type ErrInvalidPE struct {
	msg string
}

func (e *ErrInvalidPE) Error() string {
	return "invalid PE: " + e.msg
}

// ErrNoHeaderSpace indicates there is not enough room in the PE header
// area to append additional section table entries.
type ErrNoHeaderSpace struct {
	needed    int
	available int
}

func (e *ErrNoHeaderSpace) Error() string {
	return fmt.Sprintf(
		"no header space for new section: need %d bytes, have %d bytes available",
		e.needed, e.available)
}

// ErrSectionNameTooLong indicates the section name exceeds 8 bytes.
type ErrSectionNameTooLong struct {
	name string
}

func (e *ErrSectionNameTooLong) Error() string {
	return fmt.Sprintf("section name too long (max 8 bytes): %s", e.name)
}

// existingSection holds the minimal fields read from an existing section header.
type existingSection struct {
	virtualAddress   uint32
	virtualSize      uint32
	pointerToRawData uint32
	sizeOfRawData    uint32
}

// pePatcher performs byte-level patching of a PE binary. The original kernel
// bytes are preserved verbatim; only the section table entries, the
// NumberOfSections COFF field, and SizeOfImage are modified in-place.
// New section data is appended at the end of the file.
type pePatcher struct {
	data []byte

	// Parsed offsets (all relative to start of file)
	peHeaderOffset   uint32
	coffOffset       uint32 // peHeaderOffset + 4
	optHeaderOffset  uint32 // coffOffset + 20
	sectionTableBase uint32 // optHeaderOffset + sizeOfOptionalHeader

	// Parsed header values
	numberOfSections     uint16
	sizeOfOptionalHeader uint16
	sizeOfImage          uint32
	sizeOfHeaders        uint32
	sectionAlignment     uint32

	// Existing sections (parsed read-only)
	sections []existingSection

	// First section's PointerToRawData defines end of header area
	firstSectionRawData uint32
}

// newPEPatcher creates a patcher from a copy of the provided PE binary data.
// It parses minimal structural information needed for section insertion.
func newPEPatcher(data []byte) (*pePatcher, error) {
	if len(data) < 64 {
		return nil, &ErrInvalidPE{msg: "file too small for DOS header"}
	}

	// Check DOS signature at offset 0
	sig := binary.LittleEndian.Uint16(data[0:2])
	if sig != dosSignature {
		return nil, &ErrInvalidPE{msg: fmt.Sprintf("invalid DOS signature: 0x%04x", sig)}
	}

	// PE header offset at 0x3C
	peOff := binary.LittleEndian.Uint32(data[0x3C:0x40])
	if int(peOff)+4 > len(data) {
		return nil, &ErrInvalidPE{msg: "PE header offset beyond file"}
	}

	// Verify PE signature
	peSig := binary.LittleEndian.Uint32(data[peOff : peOff+4])
	if peSig != peSignature {
		return nil, &ErrInvalidPE{msg: fmt.Sprintf("invalid PE signature: 0x%08x", peSig)}
	}

	coffOff := peOff + 4

	// COFF header: NumberOfSections at offset 2, SizeOfOptionalHeader at offset 16
	if int(coffOff)+20 > len(data) {
		return nil, &ErrInvalidPE{msg: "file too small for COFF header"}
	}
	numSections := binary.LittleEndian.Uint16(data[coffOff+2 : coffOff+4])
	sizeOptHdr := binary.LittleEndian.Uint16(data[coffOff+16 : coffOff+18])

	optOff := coffOff + 20

	// Read SectionAlignment (offset 32), FileAlignment (offset 36),
	// SizeOfImage (offset 56), and SizeOfHeaders (offset 60) in PE32+ optional header
	if int(optOff)+64 > len(data) {
		return nil, &ErrInvalidPE{msg: "file too small for optional header"}
	}
	sectAlign := binary.LittleEndian.Uint32(data[optOff+32 : optOff+36])
	if sectAlign == 0 {
		sectAlign = defaultSectionAlignment
	}
	sizeOfImage := binary.LittleEndian.Uint32(data[optOff+56 : optOff+60])
	sizeOfHeaders := binary.LittleEndian.Uint32(data[optOff+60 : optOff+64])

	// Section table
	sectionTableStart := optOff + uint32(sizeOptHdr)
	sectionTableEnd := sectionTableStart + uint32(numSections)*sectionHeaderSize

	if int(sectionTableEnd) > len(data) {
		return nil, &ErrInvalidPE{msg: "section table extends beyond file"}
	}

	// Parse existing sections
	sections := make([]existingSection, numSections)
	for i := uint16(0); i < numSections; i++ {
		off := sectionTableStart + uint32(i)*sectionHeaderSize
		sections[i] = existingSection{
			// VirtualSize at offset 8, VirtualAddress at offset 12
			virtualSize:      binary.LittleEndian.Uint32(data[off+8 : off+12]),
			virtualAddress:   binary.LittleEndian.Uint32(data[off+12 : off+16]),
			sizeOfRawData:    binary.LittleEndian.Uint32(data[off+16 : off+20]),
			pointerToRawData: binary.LittleEndian.Uint32(data[off+20 : off+24]),
		}
	}

	// Determine first section's PointerToRawData (end of header space)
	var firstRaw uint32
	if numSections > 0 {
		firstRaw = sections[0].pointerToRawData
		for _, s := range sections[1:] {
			if s.pointerToRawData > 0 && s.pointerToRawData < firstRaw {
				firstRaw = s.pointerToRawData
			}
		}
	} else {
		firstRaw = sizeOfHeaders
	}

	// Copy the original data so we don't mutate the caller's slice
	buf := make([]byte, len(data))
	copy(buf, data)

	return &pePatcher{
		data:                 buf,
		peHeaderOffset:       peOff,
		coffOffset:           coffOff,
		optHeaderOffset:      optOff,
		sectionTableBase:     sectionTableStart,
		numberOfSections:     numSections,
		sizeOfOptionalHeader: sizeOptHdr,
		sizeOfImage:          sizeOfImage,
		sizeOfHeaders:        sizeOfHeaders,
		sectionAlignment:     sectAlign,
		sections:             sections,
		firstSectionRawData:  firstRaw,
	}, nil
}

// addSection appends a new PE section with the given name, data, and
// characteristics. The section header is written into available padding
// space between the existing section table and the first section's raw
// data. Section data is appended at the end of the file, aligned to
// fileAlignment (512 bytes). VirtualAddress and VirtualSize are set to
// proper values so UEFI firmware PE loaders (e.g., OVMF) accept the binary.
func (p *pePatcher) addSection(name string, data []byte, characteristics uint32) error {
	if len(name) > 8 {
		return &ErrSectionNameTooLong{name: name}
	}

	// Check available header space
	currentTableEnd := p.sectionTableBase + uint32(p.numberOfSections)*sectionHeaderSize
	available := int(p.firstSectionRawData) - int(currentTableEnd)
	if available < sectionHeaderSize {
		return &ErrNoHeaderSpace{
			needed:    sectionHeaderSize,
			available: available,
		}
	}

	// Calculate file offset for new section data: align past the end of
	// the last section's raw data (or end of file, whichever is greater).
	lastEnd := p.lastRawDataEnd()
	fileEnd := uint32(len(p.data))
	if fileEnd > lastEnd {
		lastEnd = fileEnd
	}
	dataOffset := alignUp(lastEnd, fileAlignment)

	// Calculate VirtualAddress: next section-aligned address after the
	// last section's virtual range. This ensures OVMF's PE loader accepts
	// the binary during removable media boot discovery.
	virtualAddr := p.nextVirtualAddress()
	virtualSize := uint32(len(data))

	// Build the 40-byte section header
	var hdr [sectionHeaderSize]byte
	copy(hdr[0:8], name)                                   // Name, zero-padded
	binary.LittleEndian.PutUint32(hdr[8:12], virtualSize)  // VirtualSize
	binary.LittleEndian.PutUint32(hdr[12:16], virtualAddr) // VirtualAddress
	alignedSize := alignUp(uint32(len(data)), fileAlignment)
	binary.LittleEndian.PutUint32(hdr[16:20], alignedSize) // SizeOfRawData (file-aligned per PE spec)
	binary.LittleEndian.PutUint32(hdr[20:24], dataOffset)  // PointerToRawData
	// PointerToRelocations = 0 (offset 24)
	// PointerToLinenumbers = 0 (offset 28)
	// NumberOfRelocations = 0 (offset 32)
	// NumberOfLinenumbers = 0 (offset 34)
	binary.LittleEndian.PutUint32(hdr[36:40], characteristics) // Characteristics

	// Write the section header into the padding area
	headerPos := currentTableEnd
	copy(p.data[headerPos:headerPos+sectionHeaderSize], hdr[:])

	// Append section data at the calculated offset. If dataOffset is beyond
	// the current slice length, extend with zero padding first.
	if dataOffset > uint32(len(p.data)) {
		padding := make([]byte, dataOffset-uint32(len(p.data)))
		p.data = append(p.data, padding...)
	}
	p.data = append(p.data, data...)
	// Pad section data to file-aligned boundary (PE spec requires
	// SizeOfRawData bytes of data on disk for each section)
	padding := alignedSize - uint32(len(data))
	if padding > 0 {
		p.data = append(p.data, make([]byte, padding)...)
	}

	// Track the new section with aligned size
	p.sections = append(p.sections, existingSection{
		virtualAddress:   virtualAddr,
		virtualSize:      virtualSize,
		pointerToRawData: dataOffset,
		sizeOfRawData:    alignedSize,
	})
	p.numberOfSections++

	// Patch NumberOfSections in COFF header (2 bytes at coffOffset+2)
	binary.LittleEndian.PutUint16(
		p.data[p.coffOffset+2:p.coffOffset+4],
		p.numberOfSections,
	)

	// Update SizeOfImage to include the new section's virtual range.
	// SizeOfImage must be aligned to SectionAlignment and must cover
	// all sections' virtual address ranges.
	newImageEnd := alignUp(virtualAddr+virtualSize, p.sectionAlignment)
	if newImageEnd > p.sizeOfImage {
		p.sizeOfImage = newImageEnd
		binary.LittleEndian.PutUint32(
			p.data[p.optHeaderOffset+56:p.optHeaderOffset+60],
			p.sizeOfImage,
		)
	}

	return nil
}

// bytes returns the modified PE binary.
func (p *pePatcher) bytes() []byte {
	return p.data
}

// nextVirtualAddress returns the next available section-aligned virtual address.
func (p *pePatcher) nextVirtualAddress() uint32 {
	var maxEnd uint32
	for _, s := range p.sections {
		// Use the larger of VirtualSize and SizeOfRawData to determine the
		// section's actual occupied range in virtual memory
		size := s.virtualSize
		if s.sizeOfRawData > size {
			size = s.sizeOfRawData
		}
		end := s.virtualAddress + size
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 {
		return p.sizeOfHeaders
	}
	return alignUp(maxEnd, p.sectionAlignment)
}

// lastRawDataEnd returns the file offset just past the last section's raw data.
func (p *pePatcher) lastRawDataEnd() uint32 {
	var end uint32
	for _, s := range p.sections {
		sEnd := s.pointerToRawData + s.sizeOfRawData
		if sEnd > end {
			end = sEnd
		}
	}
	if end == 0 {
		return p.sizeOfHeaders
	}
	return end
}

// alignUp rounds value up to the nearest multiple of alignment.
func alignUp(value, alignment uint32) uint32 {
	return (value + alignment - 1) &^ (alignment - 1)
}
