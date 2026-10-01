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

const testTLSServerName = "compute.example.internal"

// TestProfileMapping_CarriesTLSServerName pins the one request mapping and
// the one response mapping both carry tls_server_name (#430), and neither
// invents one.
func TestProfileMapping_CarriesTLSServerName(t *testing.T) {
	profile, err := profileRequestToEntity(&ProfileRequest{ID: 1, Name: "compute", Role: "worker", TLSServerName: testTLSServerName})
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, profile.TLSServerName)

	resp := profileToResponse(&entities.DeviceProfile{ID: 1, Name: "compute", Role: entities.DeviceRoleWorker, TLSServerName: testTLSServerName})
	assert.Equal(t, testTLSServerName, resp.TLSServerName)

	empty, err := profileRequestToEntity(&ProfileRequest{ID: 2, Name: "q", Role: "worker"})
	require.NoError(t, err)
	assert.Empty(t, empty.TLSServerName)
	raw, err := json.Marshal(profileToResponse(&entities.DeviceProfile{ID: 2, Name: "q", Role: entities.DeviceRoleWorker}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "tls_server_name", "an absent name is omitted, not sent empty")
}

// TestCRUDHandler_UpdateProfile_PreservesTLSServerName is the live REST round
// trip for #430: a console PUT whose body predates the field reaches the real
// ProfileService and the collector's server name survives, with the response
// reporting it; a PUT that names it replaces it.
func TestCRUDHandler_UpdateProfile_PreservesTLSServerName(t *testing.T) {
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	profiles, err := devicepkg.NewProfileService(devicepkg.NewDatastore(storage, logging.DefaultLogger()))
	require.NoError(t, err)
	handler := &CRUDHandler{
		logger:         logging.DefaultLogger(),
		responseWriter: &mockResponseWriter{},
		deviceService:  newMockDeviceService(),
		profileService: profiles,
	}
	require.NoError(t, profiles.Save(context.Background(), &entities.DeviceProfile{
		ID: 4480, Name: "compute", Role: entities.DeviceRoleWorker, TLSServerName: testTLSServerName,
	}))

	put := func(body string) ProfileFullResponse {
		req := httptest.NewRequest(http.MethodPut, "/device/profiles/4480", bytes.NewBufferString(body))
		req = mux.SetURLVars(req, map[string]string{"id": "4480"})
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateProfile(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp ProfileFullResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		return resp
	}

	resp := put(`{"name": "compute-renamed", "role": "worker"}`)
	assert.Equal(t, "compute-renamed", resp.Name)
	assert.Equal(t, testTLSServerName, resp.TLSServerName, "the update response must report the preserved name")
	stored, err := profiles.Get(context.Background(), 4480)
	require.NoError(t, err)
	assert.Equal(t, testTLSServerName, stored.TLSServerName, "a PUT that cannot carry the name must not erase it")

	resp = put(`{"name": "compute-renamed", "role": "worker", "tls_server_name": "gw.example.internal"}`)
	assert.Equal(t, "gw.example.internal", resp.TLSServerName)
	stored, err = profiles.Get(context.Background(), 4480)
	require.NoError(t, err)
	assert.Equal(t, "gw.example.internal", stored.TLSServerName)
}
