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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

const testAttestCertPEM = "-----BEGIN CERTIFICATE-----\nenrolled-iak\n-----END CERTIFICATE-----\n"

// newRealServiceHandler wires the CRUD handler to the production device
// service over in-memory storage. The live REST update handler builds its
// entity from the request alone and relies on device.Service.Update to
// restore server-owned fields (docs/device/api.md §3.3), so the round trip
// below has to run through the real service to prove anything.
func newRealServiceHandler(t *testing.T) *CRUDHandler {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	svc, err := devicepkg.NewService(devicepkg.NewDatastore(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	return &CRUDHandler{
		logger:         logging.DefaultLogger(),
		responseWriter: &mockResponseWriter{},
		deviceService:  svc,
		profileService: newMockProfileService(),
	}
}

func liveRESTDeviceCall(t *testing.T, call func(http.ResponseWriter, *http.Request), method, path, id, body string, want int) DeviceResponse {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if id != "" {
		req = mux.SetURLVars(req, map[string]string{"id": id})
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	call(w, req)
	require.Equal(t, want, w.Code, w.Body.String())
	var resp DeviceResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// TestCRUDHandler_AttestCert_SurvivesUpdateWithoutIt is the live REST round
// trip: POST with a certificate, GET, PUT without it, GET again.
func TestCRUDHandler_AttestCert_SurvivesUpdateWithoutIt(t *testing.T) {
	handler := newRealServiceHandler(t)

	body, err := json.Marshal(map[string]any{
		"id": 4040, "serial": "SN-4040", "model": "X10SDV", "attest_pub": "pub", "attest_cert": testAttestCertPEM,
	})
	require.NoError(t, err)
	created := liveRESTDeviceCall(t, handler.CreateDevice, http.MethodPost, "/devices", "", string(body), http.StatusCreated)
	assert.Equal(t, testAttestCertPEM, created.AttestCert)

	got := liveRESTDeviceCall(t, handler.GetDevice, http.MethodGet, "/devices/4040", "4040", "", http.StatusOK)
	assert.Equal(t, testAttestCertPEM, got.AttestCert)

	// The dashboard edit: identity fields only, no certificate.
	updated := liveRESTDeviceCall(t, handler.UpdateDevice, http.MethodPut, "/devices/4040", "4040",
		`{"serial": "SN-4040", "model": "X10SDV-TP8F"}`, http.StatusOK)
	assert.Equal(t, "X10SDV-TP8F", updated.Model)
	assert.Equal(t, testAttestCertPEM, updated.AttestCert, "the update response reports the preserved certificate")

	again := liveRESTDeviceCall(t, handler.GetDevice, http.MethodGet, "/devices/4040", "4040", "", http.StatusOK)
	assert.Equal(t, testAttestCertPEM, again.AttestCert, "a PUT that omits attest_cert must not erase the trust anchor")
	assert.Equal(t, "pub", again.AttestPub)
}

// TestRequestToDevice_AttestCert_FlatAndNested proves both request shapes
// (flat legacy and the SDK's {device: {...}} envelope) carry the certificate,
// and that the envelope overrides the flat field exactly as attest_pub does.
func TestRequestToDevice_AttestCert_FlatAndNested(t *testing.T) {
	flat, err := (&DeviceRequest{RequestFields: devicepkg.RequestFields{Serial: "SN", AttestCert: testAttestCertPEM}}).ToDevice()
	require.NoError(t, err)
	assert.Equal(t, testAttestCertPEM, flat.AttestCert)

	nested, err := (&DeviceRequest{
		RequestFields: devicepkg.RequestFields{Serial: "SN"},
		Device:        &devicepkg.RequestFields{AttestCert: testAttestCertPEM},
	}).ToDevice()
	require.NoError(t, err)
	assert.Equal(t, testAttestCertPEM, nested.AttestCert)

	_, err = (&DeviceRequest{
		RequestFields: devicepkg.RequestFields{Serial: "SN", AttestCert: "flat-differs"},
		Device:        &devicepkg.RequestFields{AttestCert: testAttestCertPEM},
	}).ToDevice()
	assert.Equal(t, devicepkg.ErrDeviceRequestConflict{Field: "attest_cert"}, err,
		"a certificate set flat and nested to different values is refused, not resolved by precedence")

	empty, err := (&DeviceRequest{RequestFields: devicepkg.RequestFields{Serial: "SN"}, Device: &devicepkg.RequestFields{}}).ToDevice()
	require.NoError(t, err)
	assert.Empty(t, empty.AttestCert, "an empty envelope must not clear or invent a certificate")
}

// TestDeviceToResponse_AttestCert pins the response serialiser and its
// omitempty behaviour.
func TestDeviceToResponse_AttestCert(t *testing.T) {
	handler, _, _ := newTestHandler()
	assert.Equal(t, testAttestCertPEM, handler.deviceToResponse(&entities.Device{ID: 1, AttestCert: testAttestCertPEM}).AttestCert)

	raw, err := json.Marshal(handler.deviceToResponse(&entities.Device{ID: 2}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "attest_cert")
}
