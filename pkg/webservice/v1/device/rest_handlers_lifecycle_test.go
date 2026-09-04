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

package device

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// The WebUI's Enable / Disable Device control is disabled (#229) because
// the generic device update cannot carry a lifecycle transition. These
// tests pin that premise on the server side.
//
// `device.Service.Update` restores every server-owned field from the
// stored record precisely so an ordinary edit cannot move a device
// between lifecycle states: "a caller that really owns one of these
// transitions goes through its dedicated flow (activation, quarantine,
// heartbeat), never a generic update" (pkg/device/service.go). The REST
// contract enforces the same rule one layer up by never decoding a
// caller-supplied state at all.
//
// When the device lifecycle transition flow lands (#250) and state
// becomes settable here, these tests fail — and that failure is the
// reminder to re-enable the WebUI control and drop
// DEVICE_TOGGLE_UNAVAILABLE from web/src/lib/device-lifecycle.ts.

// TestUpdateDevice_DropsCallerSuppliedState proves PUT /api/v1/devices/{id}
// cannot suspend a device: a caller-supplied state never reaches the
// entity handed to the device service.
func TestUpdateDevice_DropsCallerSuppliedState(t *testing.T) {
	bodies := map[string]string{
		"flat": `{"serial": "SN001", "state": "suspended"}`,
		"nested SDK envelope": `{"device": {"id": 1, "serial": "SN001",` +
			` "state": "suspended", "status": "disabled", "enabled": false}}`,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			handler, deviceSvc, _ := newTestHandler()
			deviceSvc.devices[1] = &entities.Device{
				ID:     1,
				Serial: "SN001",
				State:  entities.DeviceStateAttested,
			}

			req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
			req = mux.SetURLVars(req, map[string]string{"id": "1"})
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.UpdateDevice(w, req)

			// The request is accepted — it is a legitimate edit of the
			// fields the contract does carry — it just cannot transition
			// the device.
			require.Equal(t, http.StatusOK, w.Code)

			updated := deviceSvc.devices[1]
			require.NotNil(t, updated)
			assert.Empty(t, string(updated.State),
				"the update contract must not carry a lifecycle state; the real"+
					" service then restores the stored one")
			assert.NotEqual(t, entities.DeviceStateSuspended, updated.State,
				"a generic update must never suspend a device")
		})
	}
}

// TestUpdateDevice_ResponseDoesNotEchoRequestedState proves the handler
// does not report the transition back to the client either. The WebUI
// derives its Disabled badge from the state in this response
// (web/src/lib/device-status.ts), so echoing a requested state would put
// a device that is still live behind a Disabled badge.
func TestUpdateDevice_ResponseDoesNotEchoRequestedState(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Serial: "SN001",
		State:  entities.DeviceStateAttested,
	}

	body := `{"serial": "SN001", "state": "suspended"}`
	req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), string(entities.DeviceStateSuspended),
		"the response must not report a suspension the platform never performed")
}
