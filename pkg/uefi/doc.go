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

// Package uefi provides native Go support for UEFI data structures and operations.
//
// This package implements parsing and manipulation of UEFI firmware volumes,
// variable stores, and Secure Boot signature lists. It enables native enrollment
// of Secure Boot keys into OVMF NVRAM files without external dependencies like
// virt-fw-vars or efitools.
//
// # Supported Features
//
//   - UEFI GUID handling and well-known GUIDs
//   - EFI Signature List (ESL) encoding/decoding
//   - Firmware Volume parsing (OVMF_VARS.fd)
//   - Variable Store manipulation
//   - Secure Boot key enrollment (PK, KEK, db, dbx)
//
// # Example Usage
//
//	import (
//	    "github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
//	)
//
//	// Create ESL from X.509 certificate
//	certDER, _ := os.ReadFile("cert.der")
//	esl := uefi.NewSignatureListFromCert(certDER, uefi.NewGUID())
//
//	// Enroll keys into NVRAM
//	nvram, _ := uefi.OpenNVRAM("/path/to/OVMF_VARS.fd")
//	nvram.SetVariable("PK", uefi.EFIGlobalVariable, esl.Bytes())
//	nvram.Save()
//
// # References
//
//   - UEFI Specification 2.10: https://uefi.org/specs/UEFI/2.10/
//   - UEFI Platform Initialization Specification: https://uefi.org/specs/PI/1.8/
//   - EDK2 MdeModulePkg: https://github.com/tianocore/edk2/tree/master/MdeModulePkg
package uefi
