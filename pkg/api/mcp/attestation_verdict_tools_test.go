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
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// verdictPollProvider embeds the base mock and records each verdict poll.
type verdictPollProvider struct {
	*mockServiceProvider
	page    json.RawMessage
	err     error
	cursors []string
	waits   []uint32
}

func (p *verdictPollProvider) AttestationPollDeviceVerdicts(_ context.Context, cursor string, waitMs uint32) (any, error) {
	p.cursors = append(p.cursors, cursor)
	p.waits = append(p.waits, waitMs)
	return p.page, p.err
}

func TestAttestationVerdictTool_RegisteredAndScoped(t *testing.T) {
	r := newReportRegistry(t, newMockServiceProvider())
	found := false
	for _, tool := range r.ListTools() {
		if tool.Name == "attestation_device_verdicts_poll" {
			found = true
		}
	}
	assert.True(t, found, "attestation_device_verdicts_poll must be registered")
	assert.Equal(t, "attestation:read", NewAuthorizationChecker(nil, nil).toolPermissions["attestation_device_verdicts_poll"])
}

func TestAttestationVerdictTool_NotConfiguredWithoutProvider(t *testing.T) {
	r := newReportRegistry(t, newMockServiceProvider())
	_, err := r.ExecuteTool(context.Background(), "attestation_device_verdicts_poll", map[string]interface{}{})
	assert.ErrorIs(t, err, ErrDeviceVerdictsNotConfigured)
}

func TestAttestationVerdictTool_PollsWithTheCursorAndWait(t *testing.T) {
	p := &verdictPollProvider{mockServiceProvider: newMockServiceProvider(),
		page: json.RawMessage(`{"cursor":"18f.2","verdicts":[{"event_id":"ev-1","device_id":"7"}]}`)}
	r := newReportRegistry(t, p)

	out, err := r.ExecuteTool(context.Background(), "attestation_device_verdicts_poll",
		map[string]interface{}{"cursor": "18f.1", "wait_ms": float64(2500)})
	require.NoError(t, err)
	page := out.(map[string]interface{})
	assert.Equal(t, "18f.2", page["cursor"])
	assert.Len(t, page["verdicts"], 1)
	assert.Equal(t, []string{"18f.1"}, p.cursors)
	assert.Equal(t, []uint32{2500}, p.waits)
}

func TestAttestationVerdictTool_ClampsTheWait(t *testing.T) {
	p := &verdictPollProvider{mockServiceProvider: newMockServiceProvider(), page: json.RawMessage(`{"cursor":"18f.0"}`)}
	r := newReportRegistry(t, p)

	for _, wait := range []interface{}{float64(-1), float64(math.MaxUint32) + 1, "not a number"} {
		_, err := r.ExecuteTool(context.Background(), "attestation_device_verdicts_poll", map[string]interface{}{"wait_ms": wait})
		require.NoError(t, err)
	}
	assert.Equal(t, []uint32{0, math.MaxUint32, 0}, p.waits)
}

func TestAttestationVerdictTool_ReturnsTheProviderError(t *testing.T) {
	p := &verdictPollProvider{mockServiceProvider: newMockServiceProvider(), err: errors.New("verdicts were missed")}
	r := newReportRegistry(t, p)
	_, err := r.ExecuteTool(context.Background(), "attestation_device_verdicts_poll", map[string]interface{}{"cursor": "18f.0"})
	assert.ErrorContains(t, err, "verdicts were missed")
}
