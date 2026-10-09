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

package quic

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The admitted-VTEP reads multiplex under OpGatewayCategory (sub-opcodes
// 0x17 and 0x18). The daemon dispatcher (pkg/api/quic/gateway_handlers.go)
// decodes quicapi.Gateway*AdmittedVTEP*Request structs and answers with
// their Response structs, whose field names differ from the pb messages and
// whose verdict time travels as Unix seconds rather than a Timestamp.

func init() {
	categoryRequestEncoders[platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName] = requestEncoder(
		platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName,
		func(r *platformv1.GetGatewayAdmittedVTEPRequest) interface{} {
			return &quicapi.GatewayAdmittedVTEPRequest{GatewayID: r.GetGatewayId(), VTEP: r.GetVtep()}
		})
	categoryRequestEncoders[platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName] = requestEncoder(
		platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName,
		func(r *platformv1.ListGatewayAdmittedVTEPsRequest) interface{} {
			return &quicapi.GatewayListAdmittedVTEPsRequest{GatewayID: r.GetGatewayId()}
		})

	categoryResponseDecoders[platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName] = responseDecoder(
		platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName,
		func(w *quicapi.GatewayAdmittedVTEPResponse, out *platformv1.GetGatewayAdmittedVTEPResponse) error {
			out.Vtep = admittedVTEPFromWire(w.VTEP)
			return nil
		})
	categoryResponseDecoders[platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName] = responseDecoder(
		platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName,
		func(w *quicapi.GatewayListAdmittedVTEPsResponse, out *platformv1.ListGatewayAdmittedVTEPsResponse) error {
			out.Vteps = make([]*platformv1.GatewayAdmittedVTEP, 0, len(w.VTEPs))
			for _, vtep := range w.VTEPs {
				if vtep != nil {
					out.Vteps = append(out.Vteps, admittedVTEPFromWire(vtep))
				}
			}
			return nil
		})
}

// admittedVTEPFromWire maps one daemon admitted-VTEP record onto the pb type.
// A zero verdict time is absent on the wire and stays absent in the reply.
func admittedVTEPFromWire(w *quicapi.GatewayAdmittedVTEPInfo) *platformv1.GatewayAdmittedVTEP {
	if w == nil {
		return nil
	}
	out := &platformv1.GatewayAdmittedVTEP{
		Vtep:           w.VTEP,
		DeviceId:       w.DeviceID,
		HostId:         w.HostID,
		Serial:         w.Serial,
		Hostname:       w.Hostname,
		AllocationId:   w.AllocationID,
		BaselineSource: w.BaselineSource,
		ProfileId:      w.ProfileID,
	}
	if w.VerdictAt != 0 {
		out.VerdictAt = timestamppb.New(time.Unix(w.VerdictAt, 0))
	}
	return out
}
