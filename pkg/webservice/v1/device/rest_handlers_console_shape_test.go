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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// What the console's Register Device form actually produces on the wire.
// The console reaches this handler, not pkg/api/rest's
// handleRegisterDevice: its SDK baseUrl is "/api"
// (web/src/app/providers.tsx:27), same-origin with the webservice that
// serves the console, and DeviceService appends "/v1/devices".
//
// The form posts `{device: {serial, name}}` — the nested SDK envelope
// from the proto's `CreateDeviceRequest { Device device = 1; }`, plus a
// `name` the proto has no field for.

// savedDevice returns the single device the mock service holds, failing
// if the handler saved none or more than one.
func savedDevice(t *testing.T, svc *mockDeviceService) *entities.Device {
	t.Helper()
	require.Len(t, svc.devices, 1, "expected exactly one saved device")
	for _, d := range svc.devices {
		return d
	}
	return nil
}

func postConsoleBody(t *testing.T, body string) (*httptest.ResponseRecorder, *mockDeviceService) {
	t.Helper()
	handler, deviceSvc, _ := newTestHandler()
	req := httptest.NewRequest(http.MethodPost, "/devices", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.CreateDevice(w, req)
	return w, deviceSvc
}

// putConsoleBody exercises the other requestToDevice caller. UpdateDevice
// reads the id from the route, so the request needs mux vars.
func putConsoleBody(t *testing.T, id uint64, existing *entities.Device, body string) (*httptest.ResponseRecorder, *mockDeviceService) {
	t.Helper()
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[id] = existing

	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/devices/%d", id), bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", id)})
	w := httptest.NewRecorder()
	handler.UpdateDevice(w, req)
	return w, deviceSvc
}

// =============================================================================
// The fix: a display name is never written into the serial
// =============================================================================

// TestCreateDeviceDoesNotStoreTheNameAsTheSerial is the regression for
// the coercion removed from requestToDevice. It previously read:
//
//	if d.Serial == "" && req.Device.Name != "" { d.Serial = req.Device.Name }
//
// The form's serial is optional and its name is required, so the
// ordinary path — operator names a device, leaves serial blank — saved a
// device with Serial "rack-3 node" and answered 201. That row is keyed
// on something that is not a TPM serial: it can never match one at
// enrollment, and RecordHeartbeat (pkg/device/service.go:322) resolves a
// device by Serial or Hostname against the mTLS identity, so the machine
// could not heartbeat either.
//
// The request now falls through to CreateDevice's existing synthesis,
// which is visibly synthetic rather than a plausible-looking lie.
func TestCreateDeviceDoesNotStoreTheNameAsTheSerial(t *testing.T) {
	w, deviceSvc := postConsoleBody(t, `{"device":{"name":"rack-3 node"}}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.NotEqual(t, "rack-3 node", saved.Serial,
		"a display name must never be written into the serial")
	assert.Regexp(t, `^dev-\d+$`, saved.Serial,
		"a name-only request falls through to the synthesised serial")
}

// TestCreateDeviceDoesNotStoreTheFlatNameAsTheSerial covers the second
// nesting level. The same coercion existed on the flat field
// (`if d.Serial == "" && req.Name != ""`), so a caller posting a
// top-level name rather than the SDK envelope hit it too.
func TestCreateDeviceDoesNotStoreTheFlatNameAsTheSerial(t *testing.T) {
	w, deviceSvc := postConsoleBody(t, `{"name":"rack-3 node"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.NotEqual(t, "rack-3 node", saved.Serial,
		"the flat name must never be written into the serial either")
	assert.Regexp(t, `^dev-\d+$`, saved.Serial)
}

// TestUpdateDeviceDoesNotOverwriteASerialWithAName is the sharper half.
// UpdateDevice shares requestToDevice but has no synthesis fallback, and
// the service layer preserves an existing serial only when the incoming
// one is empty (pkg/device/service.go:214). The coercion made it
// non-empty, so a PUT carrying a name and no serial replaced a real TPM
// serial with the display name — the identity-erasure class of #252,
// which pkg/device/service.go:178-186 was written to stop.
//
// The mock Update replaces rather than merging, so this asserts on the
// entity the handler hands down: with an empty serial the service's
// preservation is what restores it.
func TestUpdateDeviceDoesNotOverwriteASerialWithAName(t *testing.T) {
	existing := &entities.Device{ID: 7, Serial: "TPM-SERIAL-0007", Model: "X10SDV"}
	w, deviceSvc := putConsoleBody(t, 7, existing, `{"name":"rack-3 node"}`)

	require.Equal(t, http.StatusOK, w.Code)
	updated := deviceSvc.devices[7]
	require.NotNil(t, updated)
	assert.NotEqual(t, "rack-3 node", updated.Serial,
		"a PUT carrying only a name must not rename the device's serial")
	assert.Empty(t, updated.Serial,
		"the handler leaves the serial empty so the service layer preserves the existing one")
}

// =============================================================================
// Behaviour pinned as-is
// =============================================================================

// TestCreateDeviceAcceptsTheConsoleEnvelope asserts the serial inside
// the `{device: {...}}` envelope reaches the saved entity. The envelope
// is the proto and JS SDK shape, and requestToDevice overlays it onto
// the flat fields, so a serial the operator typed is not lost.
func TestCreateDeviceAcceptsTheConsoleEnvelope(t *testing.T) {
	w, deviceSvc := postConsoleBody(t,
		`{"device":{"serial":"SN-0001","name":"rack-3 node"}}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.Equal(t, "SN-0001", saved.Serial,
		"the serial inside the SDK envelope must reach the entity")
	assert.NotZero(t, saved.ID, "the handler allocates an id when none is supplied")
}

// TestCreateDeviceDiscardsTheName pins that the name reaches no
// persisted field at all. entities.Device has no name, so the operator's
// label is dropped and the 201 still reports success.
//
// PINS A DEFECT: the form collects a name the platform cannot store.
// Whether a device gains a first-class display name is open on #455;
// resolving it removes this test.
func TestCreateDeviceDiscardsTheName(t *testing.T) {
	w, deviceSvc := postConsoleBody(t,
		`{"device":{"serial":"SN-0001","name":"rack-3 node"}}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.Equal(t, "SN-0001", saved.Serial)
	assert.NotContains(t, saved.Model, "rack-3 node",
		"the name is not stored in Model either")
}

// TestCreateDeviceIgnoresTheFormsTPMFields pins the fields the form
// collects and the wire type declares, but which reach no persisted
// field: `type`, `description`, `tpm_version` and `tpm_firmware_version`
// decode into DeviceRequest and are then discarded.
//
// PINS A DEFECT: four more fields the console collects and the platform
// cannot store, the same #455 question as the name. Note the form does
// not even send these — it puts only serial and name on the wire — so
// this documents the server half of the gap.
func TestCreateDeviceIgnoresTheFormsTPMFields(t *testing.T) {
	w, deviceSvc := postConsoleBody(t, `{
		"serial": "SN-0001",
		"type": "physical",
		"description": "top of rack",
		"tpm_manufacturer": "Infineon",
		"tpm_version": "2.0",
		"tpm_firmware_version": "5.40"
	}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.Equal(t, "SN-0001", saved.Serial)
	assert.Empty(t, saved.Model,
		"tpm_manufacturer is not the Model; only the `manufacturer` key reaches it")
}

// TestCreateDeviceMapsManufacturerToModel pins the one UI-only field
// that does reach the entity, so the distinction above is not an
// accident of the test body.
func TestCreateDeviceMapsManufacturerToModel(t *testing.T) {
	w, deviceSvc := postConsoleBody(t,
		`{"serial":"SN-0001","manufacturer":"Infineon"}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.Equal(t, "Infineon", saved.Model,
		"requestToDevice falls back to manufacturer for an empty model")
}

// TestCreateDeviceEnvelopeOverridesFlatFields pins the precedence
// requestToDevice documents: the nested envelope wins over the flat
// fields, so a client that sends both is not silently served the flat
// value.
func TestCreateDeviceEnvelopeOverridesFlatFields(t *testing.T) {
	w, deviceSvc := postConsoleBody(t,
		`{"serial":"FLAT","model":"FlatModel","device":{"serial":"NESTED","model":"NestedModel"}}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.Equal(t, "NESTED", saved.Serial)
	assert.Equal(t, "NestedModel", saved.Model)
}

// TestCreateDeviceWithNoIdentifierAtAll pins the synthesis: an empty
// body yields a 201 and a saved device whose serial is "dev-<id>".
//
// PINS A DEFECT: the daemon REST handler rejects the identical body with
// 400 (pkg/api/rest/device_handlers.go:538), so the two handlers for
// this route disagree on whether a serial is required. Tracked in
// docs/device/api.md §2.1; reconciling them removes this test.
func TestCreateDeviceWithNoIdentifierAtAll(t *testing.T) {
	w, deviceSvc := postConsoleBody(t, `{}`)

	require.Equal(t, http.StatusCreated, w.Code)
	saved := savedDevice(t, deviceSvc)
	assert.NotZero(t, saved.ID)
	assert.Regexp(t, `^dev-\d+$`, saved.Serial,
		"an empty request is accepted with a synthesised serial, not rejected")
}
