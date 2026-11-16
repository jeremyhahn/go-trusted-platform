// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"net/http"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// lbBasePath is the daemon's gateway load-balancer surface
// (pkg/api/rest/gateway_lb_handlers.go registerLBRoutes). Only the daemon
// serves it; the webservice gateway router has no lb route.
const lbBasePath = "/api/v1/sdn/gateway/lb"

// lbVIPItemPath names one VIP by protocol, address and port.
const lbVIPItemPath = lbBasePath + "/vips/{protocol}/{address}/{port}"

func init() {
	templatedRouteTable[platformv1.GatewayService_GetVIP_FullMethodName] = lbVIPItemRoute(lbVIPItemPath, http.MethodGet)
	templatedRouteTable[platformv1.GatewayService_RemoveVIP_FullMethodName] = lbVIPItemRoute(lbVIPItemPath, http.MethodDelete)
	templatedRouteTable[platformv1.GatewayService_SetVIPBackends_FullMethodName] = lbVIPItemRoute(lbVIPItemPath+"/backends", http.MethodPut)

	grpcMethodToRESTMap[platformv1.GatewayService_AddVIP_FullMethodName] = struct {
		path   string
		method string
	}{lbBasePath + "/vips", http.MethodPost}
	grpcMethodToRESTMap[platformv1.GatewayService_ListVIPs_FullMethodName] = struct {
		path   string
		method string
	}{lbBasePath + "/vips", http.MethodGet}
	grpcMethodToRESTMap[platformv1.GatewayService_GetLBStatus_FullMethodName] = struct {
		path   string
		method string
	}{lbBasePath + "/status", http.MethodGet}

	restRequestEncoders[platformv1.GatewayService_AddVIP_FullMethodName] = encodeAddVIP
	restRequestEncoders[platformv1.GatewayService_SetVIPBackends_FullMethodName] = encodeSetVIPBackends

	restResponseDecoders[platformv1.GatewayService_AddVIP_FullMethodName] = decodeAddVIP
	restResponseDecoders[platformv1.GatewayService_GetVIP_FullMethodName] = decodeGetVIP
	restResponseDecoders[platformv1.GatewayService_SetVIPBackends_FullMethodName] = decodeSetVIPBackends
	restResponseDecoders[platformv1.GatewayService_ListVIPs_FullMethodName] = decodeListVIPs
	restResponseDecoders[platformv1.GatewayService_RemoveVIP_FullMethodName] = decodeRemoveVIP
	restResponseDecoders[platformv1.GatewayService_GetLBStatus_FullMethodName] = decodeGetLBStatus
}

// lbVIPItemRoute fills {protocol}, {address} and {port} from the request;
// none of the three may be empty.
func lbVIPItemRoute(path, method string) templatedRoute {
	return templatedRoute{
		path:   path,
		method: method,
		pathParams: []pathParam{
			{placeholder: "{protocol}", field: "protocol"},
			{placeholder: "{address}", field: "address"},
			{placeholder: "{port}", field: "port"},
		},
	}
}

// lbBackendBody is one backend as the daemon's LBBackend reads it.
type lbBackendBody struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Weight  uint32 `json:"weight,omitempty"`
}

// lbVIPBody is the flat VIP document the daemon's LBVIPRequest reads.
type lbVIPBody struct {
	Address   string          `json:"address"`
	Port      uint32          `json:"port"`
	Protocol  string          `json:"protocol"`
	Algorithm string          `json:"algorithm,omitempty"`
	Backends  []lbBackendBody `json:"backends"`
}

// lbBackendsBody is the daemon's LBSetBackendsRequest.
type lbBackendsBody struct {
	Backends []lbBackendBody `json:"backends"`
}

func lbBackends(in []*platformv1.VIPBackend) []lbBackendBody {
	out := make([]lbBackendBody, 0, len(in))
	for _, b := range in {
		out = append(out, lbBackendBody{Address: b.GetAddress(), Port: b.GetPort(), Weight: b.GetWeight()})
	}
	return out
}

// encodeAddVIP flattens AddVIPRequest.vip into the daemon's VIP document.
func encodeAddVIP(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.AddVIPRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.GatewayService_AddVIP_FullMethodName}
	}
	v := in.GetVip()
	return lbVIPBody{
		Address:   v.GetAddress(),
		Port:      v.GetPort(),
		Protocol:  v.GetProtocol(),
		Algorithm: v.GetAlgorithm(),
		Backends:  lbBackends(v.GetBackends()),
	}, nil
}

// encodeSetVIPBackends sends {backends}; the VIP is named in the path.
func encodeSetVIPBackends(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.SetVIPBackendsRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.GatewayService_SetVIPBackends_FullMethodName}
	}
	return lbBackendsBody{Backends: lbBackends(in.GetBackends())}, nil
}

func decodeAddVIP(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.AddVIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_AddVIP_FullMethodName}
	}
	vip, err := gateway.DecodeVIPStatusJSON(raw)
	if err != nil {
		return err
	}
	out.Vip = vip
	out.Status = &platformv1.Status{Success: true}
	return nil
}

func decodeGetVIP(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetVIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetVIP_FullMethodName}
	}
	vip, err := gateway.DecodeVIPStatusJSON(raw)
	if err != nil {
		return err
	}
	out.Vip = vip
	return nil
}

func decodeSetVIPBackends(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.SetVIPBackendsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_SetVIPBackends_FullMethodName}
	}
	vip, err := gateway.DecodeVIPStatusJSON(raw)
	if err != nil {
		return err
	}
	out.Vip = vip
	out.Status = &platformv1.Status{Success: true}
	return nil
}

func decodeListVIPs(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.ListVIPsResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_ListVIPs_FullMethodName}
	}
	decoded, err := gateway.DecodeListVIPsJSON(raw)
	if err != nil {
		return err
	}
	out.Vips = decoded.GetVips()
	return nil
}

func decodeRemoveVIP(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.RemoveVIPResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_RemoveVIP_FullMethodName}
	}
	st, err := unmarshalIPAMStatus(raw)
	if err != nil {
		return err
	}
	out.Status = st
	return nil
}

func decodeGetLBStatus(raw []byte, reply interface{}) error {
	out, ok := reply.(*platformv1.GetLBStatusResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.GatewayService_GetLBStatus_FullMethodName}
	}
	decoded, err := gateway.DecodeLBStatusJSON(raw)
	if err != nil {
		return err
	}
	out.Status = decoded.GetStatus()
	return nil
}
