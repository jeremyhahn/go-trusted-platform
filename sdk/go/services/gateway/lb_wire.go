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

package gateway

import (
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

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

// DecodeVIPStatusJSON decodes the flat VIP document a daemon lb route
// returns (add, get, set backends) into the gRPC VIPStatus.
func DecodeVIPStatusJSON(data []byte) (*platformv1.VIPStatus, error) {
	var wire lbVIPJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrLBDecodeFailed{What: "VIP", Cause: err}
	}
	return wire.status(), nil
}

// DecodeListVIPsJSON decodes the daemon VIP list into the gRPC reply; the
// count and timestamp have no proto field and are dropped.
func DecodeListVIPsJSON(data []byte) (*platformv1.ListVIPsResponse, error) {
	var wire lbVIPListJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrLBDecodeFailed{What: "VIP list", Cause: err}
	}
	out := &platformv1.ListVIPsResponse{}
	for _, v := range wire.VIPs {
		out.Vips = append(out.Vips, v.status())
	}
	return out, nil
}

// DecodeLBStatusJSON decodes the bare load-balancer status object into the
// gRPC reply that wraps it under status. A zero last_reconcile means the
// service never converged, so it is left unset rather than encoded as
// year 1.
func DecodeLBStatusJSON(data []byte) (*platformv1.GetLBStatusResponse, error) {
	var wire lbStatusJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, &ErrLBDecodeFailed{What: "LB status", Cause: err}
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

// ErrLBDecodeFailed is returned when a transport's load-balancer payload is
// not the document the daemon lb routes serve.
type ErrLBDecodeFailed struct {
	What  string
	Cause error
}

// Error implements the error interface.
func (e *ErrLBDecodeFailed) Error() string {
	return fmt.Sprintf("gateway: decode %s: %v", e.What, e.Cause)
}

// Unwrap implements errors.Unwrap.
func (e *ErrLBDecodeFailed) Unwrap() error { return e.Cause }
