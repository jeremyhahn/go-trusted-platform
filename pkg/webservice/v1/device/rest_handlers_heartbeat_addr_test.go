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
package device

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// TestDeviceToResponse_CarriesLastHeartbeatAddr proves the operator surface
// reports where a device's last authenticated heartbeat came from (#226,
// #428): the address the collector will dial when platform DNS has none.
func TestDeviceToResponse_CarriesLastHeartbeatAddr(t *testing.T) {
	handler, _, _ := newTestHandler()
	resp := handler.deviceToResponse(&entities.Device{ID: 1, LastHeartbeatAddr: "10.4.6.103:49152"})
	assert.Equal(t, "10.4.6.103:49152", resp.LastHeartbeatAddr)

	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"last_heartbeat_addr":"10.4.6.103:49152"`)
}

// TestDeviceToResponse_NoHeartbeatAddrOmitted proves a device that has never
// heartbeated sends no address rather than an empty string a console might
// render as a value.
func TestDeviceToResponse_NoHeartbeatAddrOmitted(t *testing.T) {
	handler, _, _ := newTestHandler()
	raw, err := json.Marshal(handler.deviceToResponse(&entities.Device{ID: 2}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "last_heartbeat_addr")
}

// TestRequestToDevice_CannotSetLastHeartbeatAddr pins that the address is
// server-recorded: a body naming it reaches the entity with none.
func TestRequestToDevice_CannotSetLastHeartbeatAddr(t *testing.T) {
	handler, _, _ := newTestHandler()
	var req DeviceRequest
	require.NoError(t, json.Unmarshal([]byte(`{"serial":"SN","last_heartbeat_addr":"10.0.0.1:1"}`), &req))
	assert.Empty(t, handler.requestToDevice(&req).LastHeartbeatAddr)
}
