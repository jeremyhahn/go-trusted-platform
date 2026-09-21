// Package authenticodetest builds the minimal PE32+ images the
// Authenticode signer's tests and its consumers' tests sign: one .text
// section, an empty certificate table, and the COFF machine of the
// caller's choice. It is test support, kept out of the production package
// the way net/http/httptest is.
package authenticodetest

import "encoding/binary"

// COFF machine values.
const (
	MachineAMD64   uint16 = 0x8664
	MachineARM64   uint16 = 0xaa64
	MachineRISCV64 uint16 = 0x5064
)

// MinimalPE returns a 4 KiB PE32+ EFI application with the given machine:
// a DOS header, the PE signature at 0x80, a COFF header with one section,
// a 240-byte optional header with 16 data directories (the certificate
// table entry zero, so the image is unsigned) and a .text section of
// 0x200 bytes at file offset 0x200.
func MinimalPE(machine uint16) []byte {
	pe := make([]byte, 4096) // 4KB minimal PE

	// DOS Header (64 bytes)
	binary.LittleEndian.PutUint16(pe[0:2], 0x5A4D) // MZ magic
	binary.LittleEndian.PutUint32(pe[60:64], 0x80) // PE header offset

	// PE Signature at offset 0x80
	copy(pe[0x80:0x84], []byte("PE\x00\x00"))

	// COFF File Header (20 bytes) at offset 0x84
	binary.LittleEndian.PutUint16(pe[0x84:0x86], machine) // Machine
	binary.LittleEndian.PutUint16(pe[0x86:0x88], 1)       // NumberOfSections
	binary.LittleEndian.PutUint32(pe[0x88:0x8C], 0)       // TimeDateStamp
	binary.LittleEndian.PutUint32(pe[0x8C:0x90], 0)       // PointerToSymbolTable
	binary.LittleEndian.PutUint32(pe[0x90:0x94], 0)       // NumberOfSymbols
	binary.LittleEndian.PutUint16(pe[0x94:0x96], 240)     // SizeOfOptionalHeader (PE32+)
	binary.LittleEndian.PutUint16(pe[0x96:0x98], 0x22)    // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	// Optional Header (PE32+) at offset 0x98
	binary.LittleEndian.PutUint16(pe[0x98:0x9A], 0x20b)       // Magic: PE32+
	pe[0x9A] = 14                                             // MajorLinkerVersion
	pe[0x9B] = 0                                              // MinorLinkerVersion
	binary.LittleEndian.PutUint32(pe[0x9C:0xA0], 0x200)       // SizeOfCode
	binary.LittleEndian.PutUint32(pe[0xA0:0xA4], 0)           // SizeOfInitializedData
	binary.LittleEndian.PutUint32(pe[0xA4:0xA8], 0)           // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(pe[0xA8:0xAC], 0x1000)      // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(pe[0xAC:0xB0], 0x1000)      // BaseOfCode
	binary.LittleEndian.PutUint64(pe[0xB0:0xB8], 0x140000000) // ImageBase
	binary.LittleEndian.PutUint32(pe[0xB8:0xBC], 0x1000)      // SectionAlignment
	binary.LittleEndian.PutUint32(pe[0xBC:0xC0], 0x200)       // FileAlignment
	binary.LittleEndian.PutUint16(pe[0xC0:0xC2], 6)           // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(pe[0xC2:0xC4], 0)           // MinorOperatingSystemVersion
	binary.LittleEndian.PutUint16(pe[0xC4:0xC6], 0)           // MajorImageVersion
	binary.LittleEndian.PutUint16(pe[0xC6:0xC8], 0)           // MinorImageVersion
	binary.LittleEndian.PutUint16(pe[0xC8:0xCA], 6)           // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(pe[0xCA:0xCC], 0)           // MinorSubsystemVersion
	binary.LittleEndian.PutUint32(pe[0xCC:0xD0], 0)           // Win32VersionValue
	binary.LittleEndian.PutUint32(pe[0xD0:0xD4], 0x3000)      // SizeOfImage
	binary.LittleEndian.PutUint32(pe[0xD4:0xD8], 0x200)       // SizeOfHeaders
	binary.LittleEndian.PutUint32(pe[0xD8:0xDC], 0)           // CheckSum (will be computed)
	binary.LittleEndian.PutUint16(pe[0xDC:0xDE], 10)          // Subsystem: EFI_APPLICATION
	binary.LittleEndian.PutUint16(pe[0xDE:0xE0], 0x160)       // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
	binary.LittleEndian.PutUint64(pe[0xE0:0xE8], 0x100000)    // SizeOfStackReserve
	binary.LittleEndian.PutUint64(pe[0xE8:0xF0], 0x1000)      // SizeOfStackCommit
	binary.LittleEndian.PutUint64(pe[0xF0:0xF8], 0x100000)    // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(pe[0xF8:0x100], 0x1000)     // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(pe[0x100:0x104], 0)         // LoaderFlags
	binary.LittleEndian.PutUint32(pe[0x104:0x108], 16)        // NumberOfRvaAndSizes

	// Data Directories (16 entries * 8 bytes = 128 bytes) starting at 0x108
	// Entry 4 (Security/Certificate Table) at offset 0x108 + 4*8 = 0x128
	// Initially zero (unsigned)
	binary.LittleEndian.PutUint32(pe[0x128:0x12C], 0) // Certificate Table RVA
	binary.LittleEndian.PutUint32(pe[0x12C:0x130], 0) // Certificate Table Size

	// Section Header (.text) at offset 0x188 (0x98 + 240)
	copy(pe[0x188:0x190], []byte(".text\x00\x00\x00"))         // Name
	binary.LittleEndian.PutUint32(pe[0x190:0x194], 0x100)      // VirtualSize
	binary.LittleEndian.PutUint32(pe[0x194:0x198], 0x1000)     // VirtualAddress
	binary.LittleEndian.PutUint32(pe[0x198:0x19C], 0x200)      // SizeOfRawData
	binary.LittleEndian.PutUint32(pe[0x19C:0x1A0], 0x200)      // PointerToRawData
	binary.LittleEndian.PutUint32(pe[0x1A0:0x1A4], 0)          // PointerToRelocations
	binary.LittleEndian.PutUint32(pe[0x1A4:0x1A8], 0)          // PointerToLinenumbers
	binary.LittleEndian.PutUint16(pe[0x1A8:0x1AA], 0)          // NumberOfRelocations
	binary.LittleEndian.PutUint16(pe[0x1AA:0x1AC], 0)          // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(pe[0x1AC:0x1B0], 0x60000020) // Characteristics: CODE | EXECUTE | READ

	// Add some code in .text section at offset 0x200
	copy(pe[0x200:0x208], []byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC})

	return pe
}
