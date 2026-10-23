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
	kmspb "github.com/jeremyhahn/go-quicbaas/api/proto"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// DEK QUIC wire mapping.
//
// The quicbaas.kms.v1 DEKManagement create, list, get, status, rotate and
// delete methods multiplex under OpKMSExtendedCategory (0xCD), subs
// 0x08-0x0D, with the sub-opcode in payload[0]. The daemon dispatcher
// (pkg/api/daemon/quic_dek.go) decodes the quicbaas.kms.v1 request message
// itself and answers the response message, so a pb.NewDEKManagementClient
// over this adapter's connection sends and receives the generated types
// unchanged.

// dekMethodSubOpcodes routes DEKManagement methods to their sub-opcode byte
// under OpKMSExtendedCategory.
var dekMethodSubOpcodes = map[string]byte{
	kmspb.DEKManagement_CreateDEK_FullMethodName:      quicwire.KMSSubCreateDEK,
	kmspb.DEKManagement_ListDEKs_FullMethodName:       quicwire.KMSSubListDEKs,
	kmspb.DEKManagement_GetDEK_FullMethodName:         quicwire.KMSSubGetDEK,
	kmspb.DEKManagement_GetDEKStatus_FullMethodName:   quicwire.KMSSubGetDEKStatus,
	kmspb.DEKManagement_RotateDEK_FullMethodName:      quicwire.KMSSubRotateDEK,
	kmspb.DEKManagement_DeleteDEK_FullMethodName:      quicwire.KMSSubDeleteDEK,
	kmspb.DEKManagement_SetDefaultDEK_FullMethodName:  quicwire.KMSSubSetDefaultDEK,
	kmspb.DEKManagement_SetDEKSafety_FullMethodName:   quicwire.KMSSubSetDEKSafety,
	kmspb.DEKManagement_ClearDEKSafety_FullMethodName: quicwire.KMSSubClearDEKSafety,
}

// init merges the DEK mapping into the shared adapter tables before the
// adapter's category-invariant assertion runs.
func init() {
	for method, sub := range dekMethodSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpKMSExtendedCategory
		categorySubOpcodeMap[method] = sub
	}
}
