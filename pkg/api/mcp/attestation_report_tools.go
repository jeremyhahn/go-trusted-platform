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

package mcp

import "context"

// AttestationReportProvider is the optional MCP provider for the attestation
// reporting service (#226): cached device verdicts with their age, the
// operator "attest now" trigger, and the node's caller-admission policy.
//
// It is an optional provider (the type-assertion pattern
// deviceProfileProvider uses) so a node without the reporting service keeps
// the tools registered but answers "not configured", which an operator can
// tell from "unknown tool".
type AttestationReportProvider interface {
	// AttestationDeviceReport returns one device's report, or ok=false
	// when the device has never been collected.
	AttestationDeviceReport(ctx context.Context, deviceID string) (report any, ok bool, err error)
	// AttestationDeviceReports returns every cached report.
	AttestationDeviceReports(ctx context.Context) ([]any, error)
	// AttestationRefreshDevice enqueues collection for a device.
	AttestationRefreshDevice(ctx context.Context, deviceID string) error
	// AttestationCallerPolicy describes the compiled caller policy.
	AttestationCallerPolicy(ctx context.Context) (any, error)
}

// ErrAttestationReportingNotConfigured reports a node with no reporting
// service behind the MCP tools.
var ErrAttestationReportingNotConfigured = &AttestationError{
	Code:    "ATTESTATION_REPORTING_NOT_CONFIGURED",
	Message: "the attestation reporting service is not configured on this node",
}

// ErrReportDeviceIDRequired reports a report tool called without a device.
var ErrReportDeviceIDRequired = &AttestationError{
	Code:    "DEVICE_ID_REQUIRED",
	Message: "device_id is required",
}

// ErrNoDeviceReport reports a device that has never been collected. It is
// deliberately not a failed verdict.
type ErrNoDeviceReport struct {
	DeviceID string
}

func (e ErrNoDeviceReport) Error() string {
	return "attestation: no report has been collected for device " + e.DeviceID
}

func (r *ToolRegistry) attestationReportProvider() AttestationReportProvider {
	if p, ok := r.service.(AttestationReportProvider); ok {
		return p
	}
	return nil
}

func (r *ToolRegistry) registerAttestationReportTools() {
	r.addTool(ToolDefinition{
		Name:        "attestation_device_report",
		Description: "Get a device's most recent verified attestation report from the reporting cache, with its age. Never triggers a quote.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
			},
			"required": []string{"device_id"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "attestation_device_reports",
		Description: "List every cached device attestation report with its age and freshness. Never triggers a quote.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "attestation_device_refresh",
		Description: "Ask the reporting collector to refresh a device's attestation out of cycle. Enqueues only; read the report for the verdict.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"device_id": map[string]interface{}{"type": "string", "description": "Device ID"},
			},
			"required": []string{"device_id"},
		},
	})
	r.addTool(ToolDefinition{
		Name:        "attestation_caller_policy",
		Description: "Describe this node's compiled caller-admission policy for the quote-producing attestation endpoints.",
		InputSchema: map[string]interface{}{
			"type":       "object",
			"properties": map[string]interface{}{},
		},
	})
}

type attestationReportToolFunc func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var attestationReportToolDispatch = map[string]attestationReportToolFunc{
	"attestation_device_report":  (*ToolRegistry).executeAttestationDeviceReport,
	"attestation_device_reports": (*ToolRegistry).executeAttestationDeviceReports,
	"attestation_device_refresh": (*ToolRegistry).executeAttestationDeviceRefresh,
	"attestation_caller_policy":  (*ToolRegistry).executeAttestationCallerPolicy,
}

func (r *ToolRegistry) dispatchAttestationReportTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := attestationReportToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

func (r *ToolRegistry) executeAttestationDeviceReport(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.attestationReportProvider()
	if p == nil {
		return nil, ErrAttestationReportingNotConfigured
	}
	id := getString(args, "device_id")
	if id == "" {
		return nil, ErrReportDeviceIDRequired
	}
	report, ok, err := p.AttestationDeviceReport(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoDeviceReport{DeviceID: id}
	}
	return marshalResult(report)
}

func (r *ToolRegistry) executeAttestationDeviceReports(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.attestationReportProvider()
	if p == nil {
		return nil, ErrAttestationReportingNotConfigured
	}
	reports, err := p.AttestationDeviceReports(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(map[string]interface{}{"reports": reports, "count": len(reports)})
}

func (r *ToolRegistry) executeAttestationDeviceRefresh(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.attestationReportProvider()
	if p == nil {
		return nil, ErrAttestationReportingNotConfigured
	}
	id := getString(args, "device_id")
	if id == "" {
		return nil, ErrReportDeviceIDRequired
	}
	if err := p.AttestationRefreshDevice(ctx, id); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"device_id": id,
		"enqueued":  true,
		"note":      "collection enqueued with the collector; read the report for the verdict and its age",
	}, nil
}

func (r *ToolRegistry) executeAttestationCallerPolicy(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	p := r.attestationReportProvider()
	if p == nil {
		return nil, ErrAttestationReportingNotConfigured
	}
	desc, err := p.AttestationCallerPolicy(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(desc)
}
