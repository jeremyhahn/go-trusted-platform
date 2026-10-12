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

package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const testTLSServerName = "compute.example.internal"

func restProfileCall(t *testing.T, router *mux.Router, method, path string, body interface{}, want int) ProfileResponse {
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
	var resp ProfileResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp
}

// TestDeviceHandlers_TLSServerName_SurvivesUpdateWithoutIt is the dark REST
// round trip: create with the name, get, update without it, get again. This
// handler merges the update onto the stored record itself.
func TestDeviceHandlers_TLSServerName_SurvivesUpdateWithoutIt(t *testing.T) {
	_, router := setupDeviceTestHandler(newMockDeviceService(), newMockProfileService())

	created := restProfileCall(t, router, http.MethodPost, "/api/v1/devices/profiles", ProfileCreateRequest{
		Name: "compute", Role: "worker", TLSServerName: testTLSServerName,
	}, http.StatusCreated)
	assert.Equal(t, testTLSServerName, created.TLSServerName)
	path := fmt.Sprintf("/api/v1/devices/profiles/%d", created.ID)

	got := restProfileCall(t, router, http.MethodGet, path, nil, http.StatusOK)
	assert.Equal(t, testTLSServerName, got.TLSServerName)

	updated := restProfileCall(t, router, http.MethodPut, path, ProfileUpdateRequest{Model: "X10SDV"}, http.StatusOK)
	assert.Equal(t, "X10SDV", updated.Model)
	assert.Equal(t, testTLSServerName, updated.TLSServerName)

	again := restProfileCall(t, router, http.MethodGet, path, nil, http.StatusOK)
	assert.Equal(t, testTLSServerName, again.TLSServerName, "an update that omits tls_server_name must not erase it")
}

// TestDeviceHandlers_TLSServerName_UpdateReplaces proves a caller that names
// the field still wins.
func TestDeviceHandlers_TLSServerName_UpdateReplaces(t *testing.T) {
	profiles := newMockProfileService()
	profiles.profiles[9] = &entities.DeviceProfile{ID: 9, Name: "gw", TLSServerName: "old"}
	_, router := setupDeviceTestHandler(newMockDeviceService(), profiles)

	updated := restProfileCall(t, router, http.MethodPut, "/api/v1/devices/profiles/9", map[string]string{"tls_server_name": testTLSServerName}, http.StatusOK)
	assert.Equal(t, testTLSServerName, updated.TLSServerName)
	assert.Equal(t, testTLSServerName, profiles.profiles[9].TLSServerName)
}

// TestDeviceHandlers_TLSServerName_ExplicitClear is the dark REST #462 round
// trip: set → clear with "" → get shows none, the clear reaching the service
// as the explicit option it honours, while an omitted or null name asks for
// no clear and keeps the stored one.
func TestDeviceHandlers_TLSServerName_ExplicitClear(t *testing.T) {
	profiles := newMockProfileService()
	profiles.profiles[11] = &entities.DeviceProfile{ID: 11, Name: "compute", TLSServerName: testTLSServerName}
	_, router := setupDeviceTestHandler(newMockDeviceService(), profiles)

	for _, body := range []string{`{"model": "X10SDV"}`, `{"tls_server_name": null}`} {
		restProfileCall(t, router, http.MethodPut, "/api/v1/devices/profiles/11", json.RawMessage(body), http.StatusOK)
		assert.NotContains(t, profiles.updateOpts, device.ClearTLSServerName, body)
		assert.Equal(t, testTLSServerName, profiles.profiles[11].TLSServerName, body)
	}

	cleared := restProfileCall(t, router, http.MethodPut, "/api/v1/devices/profiles/11", json.RawMessage(`{"tls_server_name": ""}`), http.StatusOK)
	assert.Contains(t, profiles.updateOpts, device.ClearTLSServerName, "the clear must reach the service explicitly")
	assert.Empty(t, cleared.TLSServerName)
	got := restProfileCall(t, router, http.MethodGet, "/api/v1/devices/profiles/11", nil, http.StatusOK)
	assert.Empty(t, got.TLSServerName, "get after clear still reports a name")
}

// TestProfileToResponse_CarriesPCRBaseline pins the serialiser every profile
// reply goes through, including omission of an absent baseline.
func TestProfileToResponse_CarriesPCRBaseline(t *testing.T) {
	handlers, _ := setupDeviceTestHandler(newMockDeviceService(), newMockProfileService())
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	resp := handlers.profileToResponse(&entities.DeviceProfile{ID: 1, Name: "p", PCRBaseline: &entities.PCRBaseline{
		Values: map[int][]byte{0: {0xaa, 0xbb}, 7: {0x01}}, Source: entities.BaselineSourceTOFU, RecordedAt: recorded, RecordedFromDeviceID: 77,
	}})
	require.NotNil(t, resp.PCRBaseline)
	assert.Equal(t, map[string]string{"0": "aabb", "7": "01"}, resp.PCRBaseline.Values)
	assert.Equal(t, "tofu", resp.PCRBaseline.Source)
	assert.True(t, recorded.Equal(resp.PCRBaseline.RecordedAt))
	assert.Equal(t, uint64(77), resp.PCRBaseline.RecordedFromDeviceID)

	raw, err := json.Marshal(handlers.profileToResponse(&entities.DeviceProfile{ID: 2, Name: "q"}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "pcr_baseline", "an absent baseline is omitted, not sent as an empty object")
	assert.NotContains(t, string(raw), "tls_server_name", "an absent name is omitted")
	assert.Nil(t, pcrBaselineEntityToResponse(nil))
}

// TestDeviceHandlers_PCRBaseline_ReadOnly pins that a JSON body naming
// pcr_baseline on create or update reaches the stored profile with none,
// while a get reports the baseline the verifier recorded.
func TestDeviceHandlers_PCRBaseline_ReadOnly(t *testing.T) {
	profiles := newMockProfileService()
	_, router := setupDeviceTestHandler(newMockDeviceService(), profiles)
	supplied := map[string]interface{}{
		"name": "workers", "role": "worker",
		"pcr_baseline": map[string]interface{}{"values": map[string]string{"0": "ee"}, "source": "signed", "recorded_at": "2026-09-01T12:00:00Z"},
	}

	created := restProfileCall(t, router, http.MethodPost, "/api/v1/devices/profiles", supplied, http.StatusCreated)
	assert.Nil(t, created.PCRBaseline, "a caller-supplied baseline must not be stored")
	assert.Nil(t, profiles.profiles[created.ID].PCRBaseline)

	profiles.profiles[created.ID].PCRBaseline = &entities.PCRBaseline{
		Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: time.Now().UTC(),
	}
	path := fmt.Sprintf("/api/v1/devices/profiles/%d", created.ID)
	updated := restProfileCall(t, router, http.MethodPut, path, map[string]interface{}{
		"model":        "X10SDV",
		"pcr_baseline": map[string]interface{}{"values": map[string]string{"0": "ee"}, "source": "signed", "recorded_at": "2026-09-01T12:00:00Z"},
	}, http.StatusOK)
	require.NotNil(t, updated.PCRBaseline)
	assert.Equal(t, "tofu", updated.PCRBaseline.Source)
	assert.Equal(t, "bb", updated.PCRBaseline.Values["7"])
}
