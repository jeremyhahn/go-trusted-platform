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

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reportProvider embeds the base mock so it satisfies ServiceProvider and
// adds the optional AttestationReportProvider methods.
type reportProvider struct {
	*mockServiceProvider
	report    any
	reportOK  bool
	reportErr error
	reports   []any
	refreshed []string
	refresErr error
	policy    any
}

func (p *reportProvider) AttestationDeviceReport(_ context.Context, id string) (any, bool, error) {
	return p.report, p.reportOK, p.reportErr
}
func (p *reportProvider) AttestationDeviceReports(context.Context) ([]any, error) {
	return p.reports, p.reportErr
}
func (p *reportProvider) AttestationRefreshDevice(_ context.Context, id string) error {
	p.refreshed = append(p.refreshed, id)
	return p.refresErr
}
func (p *reportProvider) AttestationCallerPolicy(context.Context) (any, error) {
	return p.policy, p.reportErr
}

func newReportRegistry(t *testing.T, p ServiceProvider) *ToolRegistry {
	t.Helper()
	r := NewToolRegistry(p, newTestLogger())
	return r
}

func TestAttestationReportTools_RegisteredAndMapped(t *testing.T) {
	r := newReportRegistry(t, newMockServiceProvider())
	for _, name := range []string{"attestation_device_report", "attestation_device_reports", "attestation_device_refresh", "attestation_caller_policy"} {
		_, ok := attestationReportToolDispatch[name]
		assert.True(t, ok, name)
		found := false
		for _, tool := range r.ListTools() {
			if tool.Name == name {
				found = true
			}
		}
		assert.True(t, found, "%s must be registered", name)
	}
	checker := NewAuthorizationChecker(nil, nil)
	for _, name := range []string{"attestation_device_report", "attestation_device_reports", "attestation_caller_policy"} {
		assert.Equal(t, "attestation:read", checker.toolPermissions[name], name)
	}
	assert.Equal(t, "attestation:write", checker.toolPermissions["attestation_device_refresh"])
}

func TestAttestationReportTools_NotConfiguredWithoutProvider(t *testing.T) {
	r := newReportRegistry(t, newMockServiceProvider())
	for _, name := range []string{"attestation_device_report", "attestation_device_reports", "attestation_device_refresh", "attestation_caller_policy"} {
		_, err := r.ExecuteTool(context.Background(), name, map[string]interface{}{"device_id": "1"})
		assert.ErrorIs(t, err, ErrAttestationReportingNotConfigured, name)
	}
}

func TestAttestationReportTools_Execute(t *testing.T) {
	p := &reportProvider{mockServiceProvider: newMockServiceProvider(), report: map[string]any{"device_id": "42", "verified": true}, reportOK: true,
		reports: []any{map[string]any{"device_id": "42"}}, policy: map[string]any{"strategy": "allowlist"}}
	r := newReportRegistry(t, p)

	out, err := r.ExecuteTool(context.Background(), "attestation_device_report", map[string]interface{}{"device_id": "42"})
	require.NoError(t, err)
	assert.Contains(t, out.(map[string]interface{}), "device_id")

	_, err = r.ExecuteTool(context.Background(), "attestation_device_report", map[string]interface{}{})
	assert.ErrorIs(t, err, ErrReportDeviceIDRequired)

	p.reportOK = false
	_, err = r.ExecuteTool(context.Background(), "attestation_device_report", map[string]interface{}{"device_id": "never"})
	var none ErrNoDeviceReport
	require.ErrorAs(t, err, &none)
	assert.Equal(t, "never", none.DeviceID)

	out, err = r.ExecuteTool(context.Background(), "attestation_device_reports", map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, float64(1), out.(map[string]interface{})["count"])

	out, err = r.ExecuteTool(context.Background(), "attestation_device_refresh", map[string]interface{}{"device_id": "42"})
	require.NoError(t, err)
	assert.Equal(t, true, out.(map[string]interface{})["enqueued"])
	assert.Equal(t, []string{"42"}, p.refreshed)
	_, err = r.ExecuteTool(context.Background(), "attestation_device_refresh", map[string]interface{}{})
	assert.ErrorIs(t, err, ErrReportDeviceIDRequired)
	p.refresErr = errors.New("stopped")
	_, err = r.ExecuteTool(context.Background(), "attestation_device_refresh", map[string]interface{}{"device_id": "42"})
	assert.ErrorContains(t, err, "stopped")

	out, err = r.ExecuteTool(context.Background(), "attestation_caller_policy", map[string]interface{}{})
	require.NoError(t, err)
	assert.Equal(t, "allowlist", out.(map[string]interface{})["strategy"])

	p.reportErr = errors.New("backend down")
	p.reportOK = true
	_, err = r.ExecuteTool(context.Background(), "attestation_device_report", map[string]interface{}{"device_id": "42"})
	assert.ErrorContains(t, err, "backend down")
	_, err = r.ExecuteTool(context.Background(), "attestation_device_reports", map[string]interface{}{})
	assert.ErrorContains(t, err, "backend down")
	_, err = r.ExecuteTool(context.Background(), "attestation_caller_policy", map[string]interface{}{})
	assert.ErrorContains(t, err, "backend down")
}
