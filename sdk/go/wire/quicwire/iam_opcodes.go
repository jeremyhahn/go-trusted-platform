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

// IAM category opcode.
//
// PlatformIAMService's tenant methods manage IAM tenant records, a different
// surface from the platform tenancy (quotas, DEKs, barriers) that the
// OpTenant* opcodes dispatch to. They used to share those bytes, so an IAM
// call reached the platform TenantService and one scope had to cover both
// (#767). They now multiplex under their own category: payload[0] selects the
// sub-operation and payload[1:] carries the MessagePack-encoded platform.v1
// request. The server-side dispatcher lives at
// pkg/api/daemon/quic_iam_category.go::handleIAMCategory.
//
// The opcode space is otherwise fully allocated, so this reclaims 0x51 from
// the block reserved after OpNTPCategory.
const (
	// OpIAMCategory multiplexes the IAM tenant-record sub-operations and
	// group update.
	OpIAMCategory byte = 0x51
)

// IAM sub-opcodes for the OpIAMCategory (0x51) category opcode. These
// constants are the canonical wire-format definition and are consumed by the
// SDK QUIC adapter (sdk/go/transport/quic/aab_iam_tenant.go).
const (
	// IAMSubTenantCreate creates an IAM tenant record.
	IAMSubTenantCreate byte = 0x01

	// IAMSubTenantGet returns one IAM tenant record.
	IAMSubTenantGet byte = 0x02

	// IAMSubTenantList lists IAM tenant records.
	IAMSubTenantList byte = 0x03

	// IAMSubTenantUpdate updates an IAM tenant record.
	IAMSubTenantUpdate byte = 0x04

	// IAMSubTenantDelete deletes an IAM tenant record.
	IAMSubTenantDelete byte = 0x05

	// IAMSubGroupUpdate updates an IAM group. The group bytes 0xBB-0xBF hold
	// create, delete, get, list and add-member, and no byte was left for
	// update, so it travels in this category.
	IAMSubGroupUpdate byte = 0x06
)
