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

// BMC QUIC wire mapping.
//
// Every BMCService method multiplexes under OpBMCCategory (0x9F) with the
// sub-opcode in payload[0] and the generated platform.v1 request in
// payload[1:]. The daemon dispatcher is
// pkg/api/daemon/quic_bmc.go::handleBMCCategory, which calls the same
// BMCService servicer gRPC uses.
//
// Responses are the generated platform.v1 messages encoded verbatim, so the
// MessagePack keys — which are Go FIELD NAMES, not proto JSON names — match
// on both sides by construction.

// bmcSubOpcodes routes each BMCService method to its sub-opcode byte.
var bmcSubOpcodes = map[string]byte{
	platformv1.BMCService_PowerOn_FullMethodName:               quicwire.BMCSubPowerOn,
	platformv1.BMCService_PowerOff_FullMethodName:              quicwire.BMCSubPowerOff,
	platformv1.BMCService_PowerReset_FullMethodName:            quicwire.BMCSubPowerReset,
	platformv1.BMCService_PowerCycle_FullMethodName:            quicwire.BMCSubPowerCycle,
	platformv1.BMCService_PowerStatus_FullMethodName:           quicwire.BMCSubPowerStatus,
	platformv1.BMCService_SetBootDevice_FullMethodName:         quicwire.BMCSubSetBootDevice,
	platformv1.BMCService_GetBootDevice_FullMethodName:         quicwire.BMCSubGetBootDevice,
	platformv1.BMCService_MountISO_FullMethodName:              quicwire.BMCSubMountISO,
	platformv1.BMCService_UnmountISO_FullMethodName:            quicwire.BMCSubUnmountISO,
	platformv1.BMCService_VirtualMediaStatus_FullMethodName:    quicwire.BMCSubVirtualMediaStatus,
	platformv1.BMCService_GetSensors_FullMethodName:            quicwire.BMCSubGetSensors,
	platformv1.BMCService_GetSystemInfo_FullMethodName:         quicwire.BMCSubGetSystemInfo,
	platformv1.BMCService_Provision_FullMethodName:             quicwire.BMCSubProvision,
	platformv1.BMCService_ProvisionStatus_FullMethodName:       quicwire.BMCSubProvisionStatus,
	platformv1.BMCService_GetWebCertificate_FullMethodName:     quicwire.BMCSubGetWebCertificate,
	platformv1.BMCService_ReplaceWebCertificate_FullMethodName: quicwire.BMCSubReplaceWebCertificate,
	platformv1.BMCService_EnrollBMC_FullMethodName:             quicwire.BMCSubEnroll,
	platformv1.BMCService_RestoreFactoryCert_FullMethodName:    quicwire.BMCSubRestore,
	platformv1.BMCService_ListUsers_FullMethodName:             quicwire.BMCSubListUsers,
	platformv1.BMCService_CreateUser_FullMethodName:            quicwire.BMCSubCreateUser,
	platformv1.BMCService_DeleteUser_FullMethodName:            quicwire.BMCSubDeleteUser,
	platformv1.BMCService_SetUserPassword_FullMethodName:       quicwire.BMCSubSetUserPassword,
	platformv1.BMCService_SetUserPrivilege_FullMethodName:      quicwire.BMCSubSetUserPrivilege,
}

// init merges the BMC wire mapping into the shared adapter tables. The file
// name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion, which then validates that every
// category-routed BMC method has its required sub-opcode mapping.
func init() {
	categoryOpcodes[quicwire.OpBMCCategory] = struct{}{}
	for method, sub := range bmcSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpBMCCategory
		categorySubOpcodeMap[method] = sub
	}
}
