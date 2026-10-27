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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// PXE QUIC wire mapping.
//
// Eight PXEService methods have their own opcodes and carry the generated
// platform.v1 request as the whole payload. The other seven multiplex under
// OpProvisioningCategory (0xCF) with the PXESub* sub-opcode in payload[0] and
// the request in payload[1:]. The daemon dispatcher is
// pkg/api/daemon/quic_pxe.go, which calls the same PXEService servicer gRPC
// uses.
//
// Responses are the generated platform.v1 messages encoded verbatim, so the
// MessagePack keys — which are Go FIELD NAMES, not proto JSON names — match
// on both sides by construction.

// pxeDirectOpcodes routes each PXEService method that owns an opcode byte.
var pxeDirectOpcodes = map[string]byte{
	platformv1.PXEService_ListDevices_FullMethodName:    quicwire.OpPXEListDevices,
	platformv1.PXEService_GetDevice_FullMethodName:      quicwire.OpPXEGetDevice,
	platformv1.PXEService_RegisterDevice_FullMethodName: quicwire.OpPXERegisterDevice,
	platformv1.PXEService_UpdateState_FullMethodName:    quicwire.OpPXEUpdateState,
	platformv1.PXEService_Authorize_FullMethodName:      quicwire.OpPXEAuthorize,
	platformv1.PXEService_Quarantine_FullMethodName:     quicwire.OpPXEQuarantine,
	platformv1.PXEService_Retry_FullMethodName:          quicwire.OpPXERetry,
	platformv1.PXEService_RemoveDevice_FullMethodName:   quicwire.OpPXERemoveDevice,
}

// pxeSubOpcodes routes each remaining PXEService method to its sub-opcode
// under OpProvisioningCategory.
var pxeSubOpcodes = map[string]byte{
	platformv1.PXEService_GetDeviceByMAC_FullMethodName:        quicwire.PXESubGetDeviceByMAC,
	platformv1.PXEService_SetDeviceEnrolled_FullMethodName:     quicwire.PXESubSetDeviceEnrolled,
	platformv1.PXEService_BindDeviceCertificate_FullMethodName: quicwire.PXESubBindDeviceCertificate,
	platformv1.PXEService_GetEvents_FullMethodName:             quicwire.PXESubGetEvents,
	platformv1.PXEService_GetStatus_FullMethodName:             quicwire.PXESubGetStatus,
	platformv1.PXEService_StartService_FullMethodName:          quicwire.PXESubStartService,
	platformv1.PXEService_StopService_FullMethodName:           quicwire.PXESubStopService,
	platformv1.PXEService_WebhookComplete_FullMethodName:       quicwire.PXESubWebhookComplete,
}

// init merges the PXE wire mapping into the shared adapter tables. The file
// name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion, which then validates that every
// category-routed PXE method has its required sub-opcode mapping.
// OpProvisioningCategory is already a category opcode.
func init() {
	for method, opcode := range pxeDirectOpcodes {
		grpcMethodToOpcodeMap[method] = opcode
	}
	for method, sub := range pxeSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpProvisioningCategory
		categorySubOpcodeMap[method] = sub
	}
}
