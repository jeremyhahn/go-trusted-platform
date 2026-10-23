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

// IAM tenant-record QUIC wire mapping.
//
// PlatformIAMService's tenant methods multiplex under OpIAMCategory (0x51)
// with the sub-opcode in payload[0] and the generated platform.v1 request in
// payload[1:]. They used to alias the OpTenant* bytes, which dispatch to the
// platform TenantService (quotas, DEKs, sync), so an IAM tenant call reached
// the wrong service under the wrong scope (#767). The daemon dispatcher is
// pkg/api/daemon/quic_iam_category.go::handleIAMCategory.

// iamTenantMethodOpcodes routes the IAM tenant methods to the category opcode.
var iamTenantMethodOpcodes = map[string]byte{
	platformv1.PlatformIAMService_CreateTenant_FullMethodName: quicwire.OpIAMCategory,
	platformv1.PlatformIAMService_GetTenant_FullMethodName:    quicwire.OpIAMCategory,
	platformv1.PlatformIAMService_ListTenants_FullMethodName:  quicwire.OpIAMCategory,
	platformv1.PlatformIAMService_UpdateTenant_FullMethodName: quicwire.OpIAMCategory,
	platformv1.PlatformIAMService_DeleteTenant_FullMethodName: quicwire.OpIAMCategory,
}

// iamTenantSubOpcodes routes the IAM tenant methods to their sub-opcode byte.
var iamTenantSubOpcodes = map[string]byte{
	platformv1.PlatformIAMService_CreateTenant_FullMethodName: quicwire.IAMSubTenantCreate,
	platformv1.PlatformIAMService_GetTenant_FullMethodName:    quicwire.IAMSubTenantGet,
	platformv1.PlatformIAMService_ListTenants_FullMethodName:  quicwire.IAMSubTenantList,
	platformv1.PlatformIAMService_UpdateTenant_FullMethodName: quicwire.IAMSubTenantUpdate,
	platformv1.PlatformIAMService_DeleteTenant_FullMethodName: quicwire.IAMSubTenantDelete,
}

// init merges the IAM tenant wire mapping into the shared adapter tables. The
// file name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion, which then validates that every
// category-routed IAM tenant method has its required sub-opcode mapping.
func init() {
	categoryOpcodes[quicwire.OpIAMCategory] = struct{}{}
	for method, opcode := range iamTenantMethodOpcodes {
		grpcMethodToOpcodeMap[method] = opcode
	}
	for method, sub := range iamTenantSubOpcodes {
		categorySubOpcodeMap[method] = sub
	}
}
