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

//go:build integration

package secureboot

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

// buildMarkerEFIApp assembles a minimal, self-contained PE32+ UEFI
// application whose entry point prints marker (plus CRLF) to the firmware
// console via EFI_SYSTEM_TABLE->ConOut->OutputString and returns EFI_SUCCESS.
// OVMF routes ConOut to the serial console under -display none, so the marker
// is observable on the VM's serial transcript.
//
// The image is position independent (RIP-relative addressing only) and
// carries an empty relocation directory, so the firmware's PE loader accepts
// it at any load address. Layout: 0x400 bytes of headers, one .text section
// at RVA 0x1000 containing the code followed by the UTF-16 marker string.
func buildMarkerEFIApp(marker string) []byte {
	const (
		fileAlign    = 0x200
		sectAlign    = 0x1000
		headersSize  = 0x400
		textRVA      = 0x1000
		subsystemEFI = 10 // IMAGE_SUBSYSTEM_EFI_APPLICATION
	)

	// Machine code (Microsoft x64 calling convention):
	//   entry(ImageHandle RCX, SystemTable RDX)
	//     sub  rsp, 0x28              ; shadow space + 16-byte alignment
	//     mov  rax, [rdx+0x40]        ; SystemTable->ConOut
	//     mov  rcx, rax               ; arg0 = ConOut
	//     lea  rdx, [rip+disp32]      ; arg1 = UTF-16 marker string
	//     call qword [rax+8]          ; ConOut->OutputString
	//     add  rsp, 0x28
	//     xor  eax, eax               ; EFI_SUCCESS
	//     ret
	code := []byte{
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
		0x48, 0x8B, 0x42, 0x40, // mov rax, [rdx+0x40]
		0x48, 0x89, 0xC1, // mov rcx, rax
		0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, // lea rdx, [rip+disp32] (patched below)
		0xFF, 0x50, 0x08, // call [rax+8]
		0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
		0x31, 0xC0, // xor eax, eax
		0xC3, // ret
	}
	leaDispOffset := 14 // offset of the disp32 within code
	leaEndOffset := 18  // RIP value during the lea = start of next instruction

	// UTF-16LE marker + CRLF + NUL terminator, appended right after the code.
	utf16Str := utf16.Encode([]rune(marker + "\r\n"))
	strBytes := make([]byte, 0, (len(utf16Str)+1)*2)
	for _, u := range utf16Str {
		strBytes = append(strBytes, byte(u), byte(u>>8))
	}
	strBytes = append(strBytes, 0x00, 0x00)

	binary.LittleEndian.PutUint32(code[leaDispOffset:], uint32(len(code)-leaEndOffset))

	text := append(append([]byte{}, code...), strBytes...)
	textVirtualSize := len(text)
	textRawSize := align(len(text), fileAlign)
	imageSize := align(textRVA+textVirtualSize, sectAlign)

	var buf bytes.Buffer

	// DOS header (64 bytes): "MZ" + e_lfanew at 0x3C pointing to 0x40.
	dos := make([]byte, 0x40)
	dos[0], dos[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(dos[0x3C:], 0x40)
	buf.Write(dos)

	// PE signature.
	buf.WriteString("PE\x00\x00")

	// COFF file header (20 bytes).
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x8664) // Machine: x86-64
	binary.LittleEndian.PutUint16(coff[2:], 1)      // NumberOfSections
	binary.LittleEndian.PutUint16(coff[16:], 240)   // SizeOfOptionalHeader (PE32+)
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE. RELOCS_STRIPPED
	// is deliberately NOT set so the loader accepts any load address (the
	// relocation directory is present but empty; the code is fully PIC).
	binary.LittleEndian.PutUint16(coff[18:], 0x0022)
	buf.Write(coff)

	// Optional header PE32+ (112 bytes + 16 data directories * 8 = 240).
	opt := make([]byte, 240)
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)               // Magic: PE32+
	binary.LittleEndian.PutUint32(opt[4:], uint32(textRawSize)) // SizeOfCode
	binary.LittleEndian.PutUint32(opt[16:], textRVA)            // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(opt[20:], textRVA)            // BaseOfCode
	binary.LittleEndian.PutUint64(opt[24:], 0x180000000)        // ImageBase
	binary.LittleEndian.PutUint32(opt[32:], sectAlign)          // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], fileAlign)          // FileAlignment
	binary.LittleEndian.PutUint16(opt[48:], 0)                  // MajorSubsystemVersion
	binary.LittleEndian.PutUint32(opt[56:], uint32(imageSize))  // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:], headersSize)        // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:], subsystemEFI)       // Subsystem
	binary.LittleEndian.PutUint64(opt[72:], 0x10000)            // SizeOfStackReserve
	binary.LittleEndian.PutUint64(opt[80:], 0x1000)             // SizeOfStackCommit
	binary.LittleEndian.PutUint64(opt[88:], 0x10000)            // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(opt[96:], 0x1000)             // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(opt[108:], 16)                // NumberOfRvaAndSizes
	// Data directories all zero: empty relocation directory (index 5) means
	// "no fixups required"; the certificate table (index 4) is populated later
	// by the Authenticode signer.
	buf.Write(opt)

	// Section table: one .text section (40 bytes).
	sect := make([]byte, 40)
	copy(sect[0:8], ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sect[8:], uint32(textVirtualSize)) // VirtualSize
	binary.LittleEndian.PutUint32(sect[12:], textRVA)                // VirtualAddress
	binary.LittleEndian.PutUint32(sect[16:], uint32(textRawSize))    // SizeOfRawData
	binary.LittleEndian.PutUint32(sect[20:], headersSize)            // PointerToRawData
	binary.LittleEndian.PutUint32(sect[36:], 0x60000020)             // CODE | EXECUTE | READ
	buf.Write(sect)

	// Pad headers to SizeOfHeaders, then emit the section data padded to
	// its raw size.
	buf.Write(make([]byte, headersSize-buf.Len()))
	buf.Write(text)
	buf.Write(make([]byte, textRawSize-len(text)))

	return buf.Bytes()
}

// align rounds n up to the next multiple of a.
func align(n, a int) int {
	return (n + a - 1) / a * a
}
