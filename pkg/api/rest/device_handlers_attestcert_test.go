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
package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const testAttestCertPEM = "-----BEGIN CERTIFICATE-----\nenrolled-iak\n-----END CERTIFICATE-----\n"

func restDeviceCall(t *testing.T, router *mux.Router, method, path string, body interface{}, want int) DeviceResponse {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, want, w.Code, w.Body.String())
	var resp DeviceResponse
	decodeDeviceResponse(t, w.Body, &resp)
	return resp
}

// TestDeviceHandlers_AttestCert_SurvivesUpdateWithoutIt is the REST round
// trip: register with a certificate, get, update without it, get again. This
// handler merges the update onto the stored record itself.
func TestDeviceHandlers_AttestCert_SurvivesUpdateWithoutIt(t *testing.T) {
	_, router := setupDeviceTestHandler(newMockDeviceService(), newMockProfileService())

	registered := restDeviceCall(t, router, http.MethodPost, "/api/v1/devices", device.RequestFields{
		Serial: "SN-404", Model: "X10SDV", AttestPub: "pub", AttestCert: testAttestCertPEM,
	}, http.StatusCreated)
	assert.Equal(t, testAttestCertPEM, registered.AttestCert)
	path := fmt.Sprintf("/api/v1/devices/%d", registered.ID)

	got := restDeviceCall(t, router, http.MethodGet, path, nil, http.StatusOK)
	assert.Equal(t, testAttestCertPEM, got.AttestCert)

	updated := restDeviceCall(t, router, http.MethodPut, path, device.RequestFields{Model: "X10SDV-TP8F"}, http.StatusOK)
	assert.Equal(t, "X10SDV-TP8F", updated.Model)
	assert.Equal(t, testAttestCertPEM, updated.AttestCert)

	again := restDeviceCall(t, router, http.MethodGet, path, nil, http.StatusOK)
	assert.Equal(t, testAttestCertPEM, again.AttestCert, "an update that omits attest_cert must not erase it")
	assert.Equal(t, "pub", again.AttestPub)
}

// TestDeviceHandlers_AttestCert_UpdateReplaces proves a caller that names
// the field still wins, mirroring attest_pub.
func TestDeviceHandlers_AttestCert_UpdateReplaces(t *testing.T) {
	deviceSvc := newMockDeviceService()
	deviceSvc.addDevice(&entities.Device{ID: 9, Serial: "SN-9", AttestCert: "old"})
	_, router := setupDeviceTestHandler(deviceSvc, newMockProfileService())

	updated := restDeviceCall(t, router, http.MethodPut, "/api/v1/devices/9", device.RequestFields{AttestCert: testAttestCertPEM}, http.StatusOK)
	assert.Equal(t, testAttestCertPEM, updated.AttestCert)
	assert.Equal(t, testAttestCertPEM, deviceSvc.devices[9].AttestCert)
}

// TestDeviceToResponse_CarriesAttestCert pins the serialiser every device
// reply goes through, including the omitempty behaviour for an absent one.
func TestDeviceToResponse_CarriesAttestCert(t *testing.T) {
	handlers, _ := setupDeviceTestHandler(newMockDeviceService(), newMockProfileService())
	resp := handlers.deviceToResponse(&entities.Device{ID: 1, AttestCert: testAttestCertPEM})
	assert.Equal(t, testAttestCertPEM, resp.AttestCert)

	raw, err := json.Marshal(handlers.deviceToResponse(&entities.Device{ID: 2}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "attest_cert", "an absent certificate is omitted, not sent as an empty string")
}
