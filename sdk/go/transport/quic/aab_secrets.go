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

// Secrets version QUIC wire mapping.
//
// The quicbaas.kms.v1 SecretsManagement version, rotate, rollback and status
// methods multiplex under OpSecretsCategory (0xCE) with the sub-opcode in
// payload[0]. The daemon dispatcher
// (pkg/api/daemon/quic_secrets.go::handleSecretsCategory) decodes the
// quicbaas.kms.v1 request message itself and answers the response message,
// so a pb.NewSecretsManagementClient over this adapter's connection sends
// and receives the generated types unchanged.
//
// Store, get, list, delete and the rotation-policy calls (subs 0x01-0x06)
// carry platform wire structs, not the quicbaas.kms.v1 messages, so they are
// not routed by gRPC method name.

// secretsMethodSubOpcodes routes SecretsManagement methods to their
// sub-opcode byte under OpSecretsCategory.
var secretsMethodSubOpcodes = map[string]byte{
	kmspb.SecretsManagement_GetSecretVersion_FullMethodName:   quicwire.SecretsSubGetVersion,
	kmspb.SecretsManagement_ListSecretVersions_FullMethodName: quicwire.SecretsSubListVersions,
	kmspb.SecretsManagement_RotateSecret_FullMethodName:       quicwire.SecretsSubRotate,
	kmspb.SecretsManagement_RollbackSecret_FullMethodName:     quicwire.SecretsSubRollback,
	kmspb.SecretsManagement_UpdateSecretStatus_FullMethodName: quicwire.SecretsSubUpdateStatus,
}

// init merges the secrets mapping into the shared adapter tables before the
// adapter's category-invariant assertion runs.
func init() {
	categoryOpcodes[quicwire.OpSecretsCategory] = struct{}{}
	for method, sub := range secretsMethodSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpSecretsCategory
		categorySubOpcodeMap[method] = sub
	}
}
