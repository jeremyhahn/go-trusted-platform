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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/configdelivery"
)

// =============================================================================
// MCP config delivery (provisioning) bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.ProvisionProvider by delegating to the
// same *configdelivery.Service that powers the REST handler and the platform.v1
// ConfigDeliveryService gRPC surface. This keeps the MCP and gRPC surfaces in
// lockstep: AI/LLM clients calling provision_fetch_config hit the exact same
// code path as a gRPC FetchConfig RPC.
//
// Authentication (single-use nonce + EAB HMAC and EK-certificate binding) is
// enforced inside the backing service; this bridge only maps arguments and
// wraps the service's typed errors in ErrConfigDeliveryClassified, carrying
// the code the gRPC matcher tables give the same error. MCP therefore answers
// the error class gRPC does (invalid-argument, unauthenticated /
// permission-denied, not-found, failed-precondition, unavailable), and the
// typed cause stays reachable through errors.As.

// requireConfigDeliveryService returns a typed unavailable error when the
// config delivery service is not wired into the provider.
func (p *MCPServiceProvider) requireConfigDeliveryService() error {
	if p.configDeliveryService == nil {
		return ErrConfigDeliveryServiceNotAvailable{}
	}
	return nil
}

// ProvisionGetNonce issues a new single-use nonce for replay prevention.
func (p *MCPServiceProvider) ProvisionGetNonce(ctx context.Context) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}

	nonce, err := p.configDeliveryService.IssueNonce()
	if err != nil {
		p.logger.Error("mcp provision: failed to issue nonce", "error", err)
		// gRPC GetNonce answers every nonce failure as Internal.
		return nil, classifyConfigDeliveryError(err, nil)
	}
	return &configdelivery.NonceResponse{Nonce: nonce}, nil
}

// ProvisionFetchConfig authenticates a device and resolves its platform
// configuration. The tri-state service result maps onto two response shapes:
// a delivered config (config, status) XOR a pending session (session_id,
// provision_url, poll_interval_seconds).
func (p *MCPServiceProvider) ProvisionFetchConfig(ctx context.Context, req *mcp.ProvisionFetchConfigRequest) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}
	if req == nil {
		req = &mcp.ProvisionFetchConfigRequest{}
	}

	configResp, pendingResp, err := p.configDeliveryService.ResolveConfig(ctx, &configdelivery.ConfigRequest{
		EKSerial:   req.EKSerial,
		MACAddress: req.MACAddress,
		EKCert:     req.EKCert,
		EABKeyID:   req.EABKeyID,
		EABHMAC:    req.EABHMAC,
		Nonce:      req.Nonce,
	})
	if err != nil {
		return nil, classifyConfigDeliveryError(err, fetchConfigErrorMatchers)
	}
	if pendingResp != nil {
		return pendingResp, nil
	}
	return configResp, nil
}

// ProvisionSignDigest authenticates a remote resign request and signs the
// supplied UKI (or kernel-module) digest with the control-plane Secure Boot
// DB key.
func (p *MCPServiceProvider) ProvisionSignDigest(ctx context.Context, req *mcp.ProvisionSignDigestRequest) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}
	if req == nil {
		req = &mcp.ProvisionSignDigestRequest{}
	}

	resp, err := p.configDeliveryService.SignDigest(ctx, &configdelivery.SignRequest{
		EKSerial:   req.EKSerial,
		MACAddress: req.MACAddress,
		EKCert:     req.EKCert,
		EABKeyID:   req.EABKeyID,
		EABHMAC:    req.EABHMAC,
		Nonce:      req.Nonce,
		Digest:     req.Digest,
		KeyRef:     req.KeyRef,
	})
	if err != nil {
		return nil, classifyConfigDeliveryError(err, signDigestErrorMatchers)
	}
	return resp, nil
}

// ProvisionPollSession checks whether a pending provisioning session has been
// fulfilled, returning either the delivered config (config, status) or the
// pending marker (status: "pending").
func (p *MCPServiceProvider) ProvisionPollSession(ctx context.Context, sessionID string) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}

	configResp, err := p.configDeliveryService.PollSession(ctx, sessionID)
	if err != nil {
		return nil, classifyConfigDeliveryError(err, sessionErrorMatchers)
	}
	if configResp == nil {
		return &configdelivery.PollPendingResponse{Status: pollSessionPendingStatus}, nil
	}
	return configResp, nil
}

// ProvisionFulfillSession links a device profile to a pending provisioning
// session, acknowledging with status "fulfilled".
func (p *MCPServiceProvider) ProvisionFulfillSession(ctx context.Context, sessionID string, profileID uint64) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}

	if err := p.configDeliveryService.FulfillSession(ctx, sessionID, profileID); err != nil {
		return nil, classifyConfigDeliveryError(err, sessionErrorMatchers)
	}

	p.logger.Info("mcp provision: session fulfilled",
		"session_id", sessionID, "profile_id", profileID)
	return map[string]string{"status": fulfillSessionStatus}, nil
}

// ProvisionListSessions returns all active (non-expired) provisioning
// sessions.
func (p *MCPServiceProvider) ProvisionListSessions(ctx context.Context) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}

	sessions := p.configDeliveryService.ListSessions()
	return map[string]interface{}{"sessions": sessions}, nil
}

// ProvisionGetSession returns a provisioning session by ID.
func (p *MCPServiceProvider) ProvisionGetSession(ctx context.Context, sessionID string) (interface{}, error) {
	if err := p.requireConfigDeliveryService(); err != nil {
		return nil, err
	}

	session, err := p.configDeliveryService.GetSession(sessionID)
	if err != nil {
		return nil, classifyConfigDeliveryError(err, sessionErrorMatchers)
	}
	return map[string]interface{}{"session": session}, nil
}

// Compile-time interface compliance check.
var _ mcp.ProvisionProvider = (*MCPServiceProvider)(nil)
