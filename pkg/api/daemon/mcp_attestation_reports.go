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
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

var _ mcp.AttestationReportProvider = (*MCPServiceProvider)(nil)

// AttestationDeviceReport implements mcp.AttestationReportProvider.
func (p *MCPServiceProvider) AttestationDeviceReport(_ context.Context, deviceID string) (any, bool, error) {
	h := p.attestationReporting
	if h == nil || h.Reports == nil {
		return nil, false, mcp.ErrAttestationReportingNotConfigured
	}
	view, ok := h.Reports.View(deviceID)
	if !ok {
		return nil, false, nil
	}
	return view, true, nil
}

// AttestationDeviceReports implements mcp.AttestationReportProvider.
func (p *MCPServiceProvider) AttestationDeviceReports(_ context.Context) ([]any, error) {
	h := p.attestationReporting
	if h == nil || h.Reports == nil {
		return nil, mcp.ErrAttestationReportingNotConfigured
	}
	views := h.Reports.Views()
	out := make([]any, 0, len(views))
	for _, v := range views {
		out = append(out, v)
	}
	return out, nil
}

// AttestationRefreshDevice implements mcp.AttestationReportProvider.
func (p *MCPServiceProvider) AttestationRefreshDevice(_ context.Context, deviceID string) error {
	h := p.attestationReporting
	if h == nil || h.Refresher == nil {
		return mcp.ErrAttestationReportingNotConfigured
	}
	return h.Refresher.Refresh(deviceID)
}

// AttestationCallerPolicy implements mcp.AttestationReportProvider.
func (p *MCPServiceProvider) AttestationCallerPolicy(_ context.Context) (any, error) {
	h := p.attestationReporting
	if h == nil || h.Policy == nil {
		return calleradmission.Description{AdmitsNobody: true}, nil
	}
	return h.Policy.Describe(), nil
}
