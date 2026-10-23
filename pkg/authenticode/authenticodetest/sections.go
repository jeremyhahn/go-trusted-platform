package authenticodetest

import "encoding/binary"

// Layout constants of the images SectionedPE builds.
const (
	dosHeaderSize      = 64
	peSignatureSize    = 4
	coffHeaderSize     = 20
	optionalHeaderSize = 112 // PE32+ fixed fields, no data directories
	sectionHeaderSize  = 40
	sectionDataSize    = 512 // each section gets 512 bytes of 0xCC
	fileAlignment      = 0x200
	sectionAlignment   = 0x1000
)

// SectionedPE returns a PE32+ AMD64 image with numSections sections
// (.sect0, .sect1, ...) of 512 bytes of 0xCC each, and headerPadding spare
// bytes between the section table and the first section's raw data, so a
// test can exercise how much room a tool has to add section headers.
//
// Unlike MinimalPE it carries no data directories: it is the general form
// for tests that parse and rewrite the section table, not tests that sign.
func SectionedPE(numSections, headerPadding int) []byte {
	const peOffset = dosHeaderSize // the PE signature follows the DOS header
	const coffOff = peOffset + peSignatureSize
	const optOff = coffOff + coffHeaderSize
	const sectionTableOff = optOff + optionalHeaderSize

	sectionTableSize := uint32(numSections) * sectionHeaderSize
	firstSectionRawData := alignUp(sectionTableOff+sectionTableSize+uint32(headerPadding), fileAlignment)
	totalSize := firstSectionRawData + uint32(numSections)*sectionDataSize
	sizeOfImage := alignUp(totalSize, sectionAlignment)

	buf := make([]byte, totalSize)

	// DOS header: "MZ" and e_lfanew.
	binary.LittleEndian.PutUint16(buf[0:2], 0x5A4D)
	binary.LittleEndian.PutUint32(buf[0x3C:0x40], peOffset)

	// PE signature.
	binary.LittleEndian.PutUint32(buf[peOffset:peOffset+4], 0x00004550)

	// COFF header: Machine, NumberOfSections, SizeOfOptionalHeader.
	binary.LittleEndian.PutUint16(buf[coffOff:coffOff+2], MachineAMD64)
	binary.LittleEndian.PutUint16(buf[coffOff+2:coffOff+4], uint16(numSections))
	binary.LittleEndian.PutUint16(buf[coffOff+16:coffOff+18], optionalHeaderSize)

	// Optional header: Magic (PE32+), SizeOfCode, AddressOfEntryPoint,
	// SizeOfImage, SizeOfHeaders.
	binary.LittleEndian.PutUint16(buf[optOff:optOff+2], 0x20b)
	binary.LittleEndian.PutUint32(buf[optOff+4:optOff+8], 0x2000)
	binary.LittleEndian.PutUint32(buf[optOff+16:optOff+20], 0x1000)
	binary.LittleEndian.PutUint32(buf[optOff+56:optOff+60], sizeOfImage)
	binary.LittleEndian.PutUint32(buf[optOff+60:optOff+64], firstSectionRawData)

	for i := 0; i < numSections; i++ {
		off := sectionTableOff + uint32(i)*sectionHeaderSize
		rawDataPtr := firstSectionRawData + uint32(i)*sectionDataSize

		copy(buf[off:off+8], append([]byte(".sect"), byte('0'+i)))
		binary.LittleEndian.PutUint32(buf[off+8:off+12], sectionDataSize)          // VirtualSize
		binary.LittleEndian.PutUint32(buf[off+12:off+16], 0x1000+uint32(i)*0x1000) // VirtualAddress
		binary.LittleEndian.PutUint32(buf[off+16:off+20], sectionDataSize)         // SizeOfRawData
		binary.LittleEndian.PutUint32(buf[off+20:off+24], rawDataPtr)              // PointerToRawData
		binary.LittleEndian.PutUint32(buf[off+36:off+40], 0x40000040)              // INITIALIZED_DATA | MEM_READ
		for j := uint32(0); j < sectionDataSize; j++ {
			buf[rawDataPtr+j] = 0xCC
		}
	}

	return buf
}

// alignUp rounds value up to the next multiple of alignment.
func alignUp(value, alignment uint32) uint32 {
	return (value + alignment - 1) &^ (alignment - 1)
}
