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

// PXE sub-opcodes, multiplexed under OpProvisioningCategory (0xCF).
//
// Eight PXEService methods have their own single-byte opcodes (OpPXEListDevices
// 0xEC through OpPXEUpdateState 0xEF, OpPXEAuthorize 0xFC through
// OpPXERemoveDevice 0xFF). The single-byte opcode space is fully allocated,
// so the other eight take the provisioning category, as the EAB (0x10-0x1A)
// and device profile (0x20-0x2F) sub-ranges do. Sub-range 0x30-0x3F is
// reserved for PXE operations.
//
// The first payload byte is the sub-opcode; the rest is the encoded
// platform.v1 request. Server dispatcher: pkg/api/daemon/quic_pxe.go
// (handlePXECategorySub). SDK routing: sdk/go/transport/quic/aab_pxe.go.
const (
	// PXESubGetDeviceByMAC is PXEService.GetDeviceByMAC.
	PXESubGetDeviceByMAC byte = 0x30

	// PXESubSetDeviceEnrolled is PXEService.SetDeviceEnrolled.
	PXESubSetDeviceEnrolled byte = 0x31

	// PXESubGetEvents is PXEService.GetEvents.
	PXESubGetEvents byte = 0x32

	// PXESubGetStatus is PXEService.GetStatus.
	PXESubGetStatus byte = 0x33

	// PXESubStartService is PXEService.StartService.
	PXESubStartService byte = 0x34

	// PXESubStopService is PXEService.StopService.
	PXESubStopService byte = 0x35

	// PXESubWebhookComplete is PXEService.WebhookComplete.
	PXESubWebhookComplete byte = 0x36

	// PXESubBindDeviceCertificate is PXEService.BindDeviceCertificate.
	PXESubBindDeviceCertificate byte = 0x37
)
