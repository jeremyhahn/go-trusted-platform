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

const (
	testRESTDICEDeviceID = "00112233445566778899aabbccddeeff"
	testRESTGoldenFWHash = "aa00000000000000000000000000000000000000000000000000000000000001"
)

// TestProfileMapping_CarriesDICEFields pins that the REST request and
// response mappings both carry dice_device_id and golden_fw_hash (#1699),
// and that an absent value is omitted rather than sent empty.
func TestProfileMapping_CarriesDICEFields(t *testing.T) {
	profile, err := profileRequestToEntity(&ProfileRequest{
		ID: 1, Name: "avr", Role: "worker",
		DICEDeviceID: testRESTDICEDeviceID, GoldenFWHash: testRESTGoldenFWHash,
	})
	require.NoError(t, err)
	assert.Equal(t, testRESTDICEDeviceID, profile.DICEDeviceID)
	assert.Equal(t, testRESTGoldenFWHash, profile.GoldenFWHash)

	resp := profileToResponse(&entities.DeviceProfile{
		ID: 1, Name: "avr", Role: entities.DeviceRoleWorker,
		DICEDeviceID: testRESTDICEDeviceID, GoldenFWHash: testRESTGoldenFWHash,
	})
	assert.Equal(t, testRESTDICEDeviceID, resp.DICEDeviceID)
	assert.Equal(t, testRESTGoldenFWHash, resp.GoldenFWHash)

	raw, err := json.Marshal(profileToResponse(&entities.DeviceProfile{ID: 2, Name: "q", Role: entities.DeviceRoleWorker}))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "dice_device_id")
	assert.NotContains(t, string(raw), "golden_fw_hash")
}

// TestCRUDHandler_UpdateProfile_DICEFieldsRoundTrip drives the REST PUT
// against the real ProfileService: a body that names both DICE fields
// stores and reports them, and a later body that omits them keeps them.
func TestCRUDHandler_UpdateProfile_DICEFieldsRoundTrip(t *testing.T) {
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
		ID: 1699, Name: "avr", Role: entities.DeviceRoleWorker,
	}))

	put := func(body string) ProfileFullResponse {
		req := httptest.NewRequest(http.MethodPut, "/device/profiles/1699", bytes.NewBufferString(body))
		req = mux.SetURLVars(req, map[string]string{"id": "1699"})
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.UpdateProfile(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp ProfileFullResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
		return resp
	}

	resp := put(`{"name": "avr", "role": "worker", "dice_device_id": "` + testRESTDICEDeviceID +
		`", "golden_fw_hash": "` + testRESTGoldenFWHash + `"}`)
	assert.Equal(t, testRESTDICEDeviceID, resp.DICEDeviceID)
	assert.Equal(t, testRESTGoldenFWHash, resp.GoldenFWHash)

	resp = put(`{"name": "avr-renamed", "role": "worker"}`)
	assert.Equal(t, "avr-renamed", resp.Name)
	assert.Equal(t, testRESTDICEDeviceID, resp.DICEDeviceID, "a PUT that omits the DICE id must keep it")
	assert.Equal(t, testRESTGoldenFWHash, resp.GoldenFWHash, "a PUT that omits the golden FWHash must keep it")

	stored, err := profiles.Get(context.Background(), 1699)
	require.NoError(t, err)
	assert.Equal(t, testRESTDICEDeviceID, stored.DICEDeviceID)
	assert.Equal(t, testRESTGoldenFWHash, stored.GoldenFWHash)
}
