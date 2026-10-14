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

package quicwire

// TPM2 sub-opcodes for the category opcode OpTPM2Category.
// The first byte of the payload selects the TPM2 operation.
const (
	SubOpTPM2Info          byte = 0x01
	SubOpTPM2Provision     byte = 0x02
	SubOpTPM2Clear         byte = 0x03
	SubOpTPM2GetEK         byte = 0x04
	SubOpTPM2CreateEK      byte = 0x05
	SubOpTPM2DeleteEK      byte = 0x06
	SubOpTPM2GetEKCert     byte = 0x07
	SubOpTPM2ImportEKCert  byte = 0x08
	SubOpTPM2GetSRK        byte = 0x09
	SubOpTPM2CreateSRK     byte = 0x0A
	SubOpTPM2DeleteSRK     byte = 0x0B
	SubOpTPM2GetIAK        byte = 0x0C
	SubOpTPM2CreateIAK     byte = 0x0D
	SubOpTPM2DeleteIAK     byte = 0x0E
	SubOpTPM2Quote         byte = 0x0F
	SubOpTPM2VerifyQuote   byte = 0x10
	SubOpTPM2ReadPCRs      byte = 0x11
	SubOpTPM2ExtendPCR     byte = 0x12
	SubOpTPM2EventLog      byte = 0x13
	SubOpTPM2Random        byte = 0x14
	SubOpTPM2Seal          byte = 0x15
	SubOpTPM2Unseal        byte = 0x16
	SubOpTPM2Capabilities  byte = 0x17
	SubOpTPM2NVRead        byte = 0x18
	SubOpTPM2NVWrite       byte = 0x19
	SubOpTPM2NVDelete      byte = 0x1A
	SubOpTPM2NVList        byte = 0x1B
	SubOpTPM2IDevIDCSR     byte = 0x1C
	SubOpTPM2LDevIDCSR     byte = 0x1D
	SubOpTPM2PlatformAttrs byte = 0x1E
	SubOpTPM2GetIDevID     byte = 0x1F
	SubOpTPM2MakeCred      byte = 0x20
	SubOpTPM2ActivateCred  byte = 0x21
	SubOpTPM2Certify       byte = 0x22
)
