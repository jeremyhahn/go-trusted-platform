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
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteSDNSetPortState_PassesTheRates(t *testing.T) {
	var got PortRates
	port := map[string]interface{}{"id": "eth0", "bridge_id": "br0"}
	svc := newMockServiceProvider()
	svc.sdnSetPortStateFunc = func(ctx context.Context, bridgeName, portName, state string, rates PortRates) (interface{}, error) {
		got = rates
		return port, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	// JSON numbers arrive as float64.
	result, err := registry.ExecuteTool(context.Background(), "sdn_set_port_state", map[string]interface{}{
		"bridge_name": "br0", "port_name": "eth0", "state": "up",
		"ingress_rate": float64(10_000_000), "ingress_burst": float64(1_000_000),
		"egress_rate": float64(20_000_000), "egress_burst": float64(2_000_000),
	})

	require.NoError(t, err)
	assert.Equal(t, PortRates{
		IngressRate: 10_000_000, IngressBurst: 1_000_000,
		EgressRate: 20_000_000, EgressBurst: 2_000_000,
	}, got)
	// The updated port comes back, so a client can show the port it changed.
	assert.Equal(t, map[string]interface{}{"success": true, "port": port}, result)
}

func TestExecuteSDNSetPortState_RejectsInvalidRateArgs(t *testing.T) {
	invalid := map[string]map[string]interface{}{
		"negative rate":            {"ingress_rate": float64(-1000)},
		"fractional rate":          {"ingress_rate": 1000.5},
		"non-numeric rate":         {"ingress_rate": "fast"},
		"boolean burst":            {"ingress_rate": float64(1000), "ingress_burst": true},
		"negative egress rate":     {"egress_rate": float64(-1000)},
		"non-numeric egress burst": {"egress_rate": float64(1000), "egress_burst": "big"},
	}
	for name, extra := range invalid {
		t.Run(name, func(t *testing.T) {
			called := false
			svc := newMockServiceProvider()
			svc.sdnSetPortStateFunc = func(ctx context.Context, bridgeName, portName, state string, rates PortRates) (interface{}, error) {
				called = true
				return nil, nil
			}
			registry := NewToolRegistry(svc, newTestLogger())
			args := map[string]interface{}{"bridge_name": "br0", "port_name": "eth0", "state": "up"}
			for k, v := range extra {
				args[k] = v
			}

			_, err := registry.ExecuteTool(context.Background(), "sdn_set_port_state", args)

			var invalidArg ErrInvalidArgument
			require.ErrorAs(t, err, &invalidArg)
			assert.False(t, called, "the service is not called")
		})
	}
}

func TestOptionalUint64Arg(t *testing.T) {
	valid := map[string]struct {
		raw  interface{}
		want uint64
	}{
		"absent":      {nil, 0},
		"float64":     {float64(5000), 5000},
		"int":         {7, 7},
		"int64":       {int64(8), 8},
		"uint64":      {uint64(math.MaxUint64), math.MaxUint64},
		"json.Number": {json.Number("9000"), 9000},
		"string":      {" 42 ", 42},
	}
	for name, tc := range valid {
		t.Run(name, func(t *testing.T) {
			got, err := optionalUint64Arg(map[string]interface{}{"n": tc.raw}, "n")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	invalid := map[string]interface{}{
		"negative float":   float64(-1),
		"fraction":         0.5,
		"float too large":  math.MaxFloat64,
		"negative int":     -1,
		"negative int64":   int64(-1),
		"negative number":  json.Number("-1"),
		"non-numeric text": "abc",
		"wrong type":       []int{1},
	}
	for name, raw := range invalid {
		t.Run("rejects "+name, func(t *testing.T) {
			_, err := optionalUint64Arg(map[string]interface{}{"n": raw}, "n")
			var invalidArg ErrInvalidArgument
			require.ErrorAs(t, err, &invalidArg)
			assert.Contains(t, err.Error(), "n must be a non-negative integer")
		})
	}
}
