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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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
	vip, err := decodeVIPStatusJSON(raw)
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
	vip, err := decodeVIPStatusJSON(raw)
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
	vip, err := decodeVIPStatusJSON(raw)
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
	decoded, err := decodeListVIPsJSON(raw)
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
	decoded, err := decodeLBStatusJSON(raw)
	if err != nil {
		return err
	}
	out.Status = decoded.GetStatus()
	return nil
}

// lbBackendJSON is one load-balanced endpoint as the daemon lb routes carry
// it.
type lbBackendJSON struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	Weight  uint32 `json:"weight"`
}

// lbBackendStatusJSON is an endpoint with its health.
type lbBackendStatusJSON struct {
	Backend lbBackendJSON `json:"backend"`
	Healthy bool          `json:"healthy"`
}

// lbVIPJSON is the flat VIP document the daemon lb routes answer with: the
// VIP config fields sit at the top level beside ct_zone and group_id,
// where the gRPC VIPStatus nests the config under vip.
type lbVIPJSON struct {
	Address   string                `json:"address"`
	Port      uint32                `json:"port"`
	Protocol  string                `json:"protocol"`
	Algorithm string                `json:"algorithm"`
	CTZone    uint32                `json:"ct_zone"`
	GroupID   uint32                `json:"group_id"`
	Backends  []lbBackendStatusJSON `json:"backends"`
}

// lbVIPListJSON is the VIP list reply: {vips, count, timestamp}.
type lbVIPListJSON struct {
	VIPs []lbVIPJSON `json:"vips"`
}

// lbStatusJSON is the bare load-balancer status object.
type lbStatusJSON struct {
	Active          bool      `json:"active"`
	VIPCount        uint32    `json:"vip_count"`
	HealthyBackends uint32    `json:"healthy_backends"`
	TotalBackends   uint32    `json:"total_backends"`
	LastReconcile   time.Time `json:"last_reconcile"`
}

func (w lbVIPJSON) status() *platformv1.VIPStatus {
	cfg := &platformv1.VIPConfig{
		Address:   w.Address,
		Port:      w.Port,
		Protocol:  w.Protocol,
		Algorithm: w.Algorithm,
	}
	out := &platformv1.VIPStatus{Vip: cfg, CtZone: w.CTZone, GroupId: w.GroupID}
	for _, b := range w.Backends {
		be := &platformv1.VIPBackend{Address: b.Backend.Address, Port: b.Backend.Port, Weight: b.Backend.Weight}
		cfg.Backends = append(cfg.Backends, be)
		out.Backends = append(out.Backends, &platformv1.VIPBackendStatus{
			Backend: &platformv1.VIPBackend{Address: be.Address, Port: be.Port, Weight: be.Weight},
			Healthy: b.Healthy,
		})
	}
	return out
}

// decodeVIPStatusJSON decodes the flat VIP document a daemon lb route
// returns (add, get, set backends) into the gRPC VIPStatus.
func decodeVIPStatusJSON(data []byte) (*platformv1.VIPStatus, error) {
	var wire lbVIPJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &lbDecodeError{what: "VIP", cause: err}
	}
	return wire.status(), nil
}

// decodeListVIPsJSON decodes the daemon VIP list into the gRPC reply; the
// count and timestamp have no proto field and are dropped.
func decodeListVIPsJSON(data []byte) (*platformv1.ListVIPsResponse, error) {
	var wire lbVIPListJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &lbDecodeError{what: "VIP list", cause: err}
	}
	out := &platformv1.ListVIPsResponse{}
	for _, v := range wire.VIPs {
		out.Vips = append(out.Vips, v.status())
	}
	return out, nil
}

// decodeLBStatusJSON decodes the bare load-balancer status object into the
// gRPC reply that wraps it under status. A zero last_reconcile means the
// service never converged, so it is left unset rather than encoded as
// year 1.
func decodeLBStatusJSON(data []byte) (*platformv1.GetLBStatusResponse, error) {
	var wire lbStatusJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &lbDecodeError{what: "LB status", cause: err}
	}
	status := &platformv1.LBStatus{
		Active:          wire.Active,
		VipCount:        wire.VIPCount,
		HealthyBackends: wire.HealthyBackends,
		TotalBackends:   wire.TotalBackends,
	}
	if !wire.LastReconcile.IsZero() {
		status.LastReconcile = timestamppb.New(wire.LastReconcile)
	}
	return &platformv1.GetLBStatusResponse{Status: status}, nil
}

// lbDecodeError is returned when a load-balancer reply is not the document
// the daemon lb routes serve.
type lbDecodeError struct {
	what  string
	cause error
}

func (e *lbDecodeError) Error() string {
	return fmt.Sprintf("rest: decode gateway %s: %v", e.what, e.cause)
}

func (e *lbDecodeError) Unwrap() error { return e.cause }
