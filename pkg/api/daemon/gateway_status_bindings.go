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

package daemon

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	gatewaysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// GatewayStatusController is the status and mode half of the gateway gRPC
// service. The QUIC, MCP and REST surfaces bind to it so every transport
// answers from the one implementation (#65): on a node with no in-process
// gateway they all report it as not configured.
type GatewayStatusController interface {
	GetGatewayStatus(ctx context.Context, req *platformv1.GetGatewayStatusRequest) (*platformv1.GetGatewayStatusResponse, error)
	SetGatewayMode(ctx context.Context, req *platformv1.SetGatewayModeRequest) (*platformv1.SetGatewayModeResponse, error)
}

// Compile-time check: the gateway gRPC service is a status controller.
var _ GatewayStatusController = (*GatewayService)(nil)

// gatewayStatusQUICAdapter serves the QUIC status and mode sub-opcodes
// from the gateway gRPC service. gRPC status errors pass through; the QUIC
// handler maps their codes.
type gatewayStatusQUICAdapter struct {
	controller GatewayStatusController
}

// Status returns the gateway status.
func (a gatewayStatusQUICAdapter) Status(ctx context.Context) (*quic.GatewayStatusInfo, error) {
	if a.controller == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.controller.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, err
	}
	return protoGatewayStatusToQUIC(resp.GetStatus()), nil
}

// SetModes sets the gateway's mode bitmask and returns its status after
// the change.
func (a gatewayStatusQUICAdapter) SetModes(ctx context.Context, modes uint32) (*quic.GatewayStatusInfo, error) {
	if a.controller == nil {
		return nil, errGatewayFeatureNotConfigured
	}
	resp, err := a.controller.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: modes})
	if err != nil {
		return nil, err
	}
	return protoGatewayStatusToQUIC(resp.GetGatewayStatus()), nil
}

// protoGatewayStatusToQUIC converts the gRPC gateway status to its QUIC
// wire shape; nil stays nil.
func protoGatewayStatusToQUIC(s *platformv1.GatewayStatus) *quic.GatewayStatusInfo {
	if s == nil {
		return nil
	}
	info := &quic.GatewayStatusInfo{
		ID:            s.GetId(),
		NodeID:        s.GetNodeId(),
		Modes:         s.GetModes(),
		Tier:          s.GetTier(),
		Reputation:    s.GetReputation(),
		UptimeSeconds: s.GetUptimeSeconds(),
		Healthy:       s.GetHealthy(),
	}
	if s.GetStartedAt() != nil {
		info.StartedAt = s.GetStartedAt().AsTime().Unix()
	}
	return info
}

// gatewayStatusView is the MCP result of gateway_status and
// gateway_mode_set: the gRPC status with its modes spelled out.
type gatewayStatusView struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`
	// Modes names the active modes (overlay, edge, transit); ModeBitmask
	// is the same set as the GatewayModeEnum bitmask.
	Modes         []string   `json:"modes"`
	ModeBitmask   uint32     `json:"mode_bitmask"`
	Tier          string     `json:"tier,omitempty"`
	Reputation    float64    `json:"reputation"`
	UptimeSeconds uint64     `json:"uptime_seconds"`
	Healthy       bool       `json:"healthy"`
	StartedAt     *time.Time `json:"started_at,omitempty"`
}

// newGatewayStatusView converts the gRPC gateway status to its MCP view;
// nil stays nil.
func newGatewayStatusView(s *platformv1.GatewayStatus) *gatewayStatusView {
	if s == nil {
		return nil
	}
	view := &gatewayStatusView{
		ID:            s.GetId(),
		NodeID:        s.GetNodeId(),
		Modes:         gatewaysvc.ModeNames(s.GetModes()),
		ModeBitmask:   s.GetModes(),
		Tier:          s.GetTier(),
		Reputation:    s.GetReputation(),
		UptimeSeconds: s.GetUptimeSeconds(),
		Healthy:       s.GetHealthy(),
	}
	if s.GetStartedAt() != nil {
		started := s.GetStartedAt().AsTime()
		view.StartedAt = &started
	}
	return view
}

// gatewayStatusTools serves the MCP gateway_status and gateway_mode_set
// tools from the gateway gRPC service. It is embedded by both MCP service
// providers.
type gatewayStatusTools struct {
	controller GatewayStatusController
}

// SetGatewayStatusController wires the gateway gRPC service the status
// tools answer from.
func (t *gatewayStatusTools) SetGatewayStatusController(controller GatewayStatusController) {
	t.controller = controller
}

// GatewayStatus returns the gateway status.
func (t gatewayStatusTools) GatewayStatus(ctx context.Context) (interface{}, error) {
	if t.controller == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	resp, err := t.controller.GetGatewayStatus(ctx, &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		return nil, err
	}
	return newGatewayStatusView(resp.GetStatus()), nil
}

// GatewayModeSet sets the gateway's modes by name and returns its status
// after the change. An unknown name is refused before the service is
// called; an empty list reaches the service, which refuses it.
func (t gatewayStatusTools) GatewayModeSet(ctx context.Context, modes []string) (interface{}, error) {
	if t.controller == nil {
		return nil, ErrServiceNotAvailable{Service: "gateway"}
	}
	bitmask, err := gatewaysvc.ModesFromNames(modes)
	if err != nil {
		return nil, err
	}
	resp, err := t.controller.SetGatewayMode(ctx, &platformv1.SetGatewayModeRequest{Modes: bitmask})
	if err != nil {
		return nil, err
	}
	return newGatewayStatusView(resp.GetGatewayStatus()), nil
}
