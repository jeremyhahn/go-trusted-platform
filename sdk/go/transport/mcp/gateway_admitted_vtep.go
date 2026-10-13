// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The gateway_admitted_vteps tool answers {"vteps": [...], "count": n}, which
// the generic round-trip decodes straight into the list reply. The
// gateway_admitted_vtep tool answers the bare VTEP record, which must be
// placed under the reply's vtep field.
func init() {
	mcpReplyDecoders[platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName] = decodeGatewayAdmittedVTEPResult
}

// decodeGatewayAdmittedVTEPResult wraps the bare VTEP record the
// gateway_admitted_vtep tool returns into the gRPC reply.
func decodeGatewayAdmittedVTEPResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetGatewayAdmittedVTEPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName}
	}
	vtep := &platformv1.GatewayAdmittedVTEP{}
	if err := mapToStruct(result, vtep); err != nil {
		return err
	}
	out.Vtep = vtep
	return nil
}
