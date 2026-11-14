// Package measuretest builds the image inputs measure.Predict reads, for
// the tests of the packages that predict an image's PCRs.
package measuretest

import (
	"bytes"
	"encoding/binary"
)

// UBootVersion is the version string UBoot carries.
const UBootVersion = "U-Boot 2024.04 (Apr 02 2024 - 10:58:58 +0000)"

// UBoot is a U-Boot binary carrying UBootVersion.
func UBoot() []byte {
	return []byte("\x00" + UBootVersion + "\x00")
}

// Kernel is the arm64 PE32+ kernel UKI carries in its .linux section.
func Kernel() []byte {
	return pe([]section{{".text", bytes.Repeat([]byte{0xcc}, 0x200)}})
}

// UKI is an arm64 PE32+ UKI: a .cmdline holding cmdline, an .initrd and a
// .linux holding Kernel.
func UKI(cmdline string) []byte {
	return pe([]section{
		{".cmdline", []byte(cmdline)},
		{".initrd", bytes.Repeat([]byte{0x11}, 0x300)},
		{".linux", Kernel()},
	})
}

type section struct {
	name string
	data []byte
}

// pe lays the sections out after a PE32+ header, each at a 0x200 file
// alignment and a 0x1000 section alignment.
func pe(sections []section) []byte {
	const coff, opt, table, headers, fileAlign, sectionAlign = 0x84, 0x98, 0x188, 0x400, 0x200, 0x1000
	up := func(n, align int) int { return (n + align - 1) / align * align }
	size, va := headers, sectionAlign
	raw := make([]int, len(sections))
	vas := make([]int, len(sections))
	for i, s := range sections {
		raw[i], vas[i] = size, va
		size += up(len(s.data), fileAlign)
		va += up(len(s.data), sectionAlign)
	}
	out := make([]byte, size)
	le := binary.LittleEndian
	le.PutUint16(out[0:], 0x5a4d) // MZ
	le.PutUint32(out[0x3c:], 0x80)
	copy(out[0x80:], "PE\x00\x00")
	le.PutUint16(out[coff:], 0xaa64)                  // Machine: ARM64
	le.PutUint16(out[coff+2:], uint16(len(sections))) // NumberOfSections
	le.PutUint16(out[coff+16:], table-opt)            // SizeOfOptionalHeader
	le.PutUint16(out[coff+18:], 0x22)                 // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	le.PutUint16(out[opt:], 0x20b)                    // PE32+
	le.PutUint32(out[opt+16:], sectionAlign)          // AddressOfEntryPoint
	le.PutUint32(out[opt+32:], sectionAlign)          // SectionAlignment
	le.PutUint32(out[opt+36:], fileAlign)             // FileAlignment
	le.PutUint32(out[opt+56:], uint32(va))            // SizeOfImage
	le.PutUint32(out[opt+60:], headers)               // SizeOfHeaders
	le.PutUint16(out[opt+68:], 10)                    // Subsystem: EFI application
	le.PutUint32(out[opt+108:], 16)                   // NumberOfRvaAndSizes
	for i, s := range sections {
		e := out[table+40*i:]
		copy(e[0:8], s.name)
		le.PutUint32(e[8:], uint32(len(s.data)))                 // VirtualSize
		le.PutUint32(e[12:], uint32(vas[i]))                     // VirtualAddress
		le.PutUint32(e[16:], uint32(up(len(s.data), fileAlign))) // SizeOfRawData
		le.PutUint32(e[20:], uint32(raw[i]))                     // PointerToRawData
		le.PutUint32(e[36:], 0x40000040)                         // INITIALIZED_DATA | MEM_READ
		copy(out[raw[i]:], s.data)
	}
	return out
}
