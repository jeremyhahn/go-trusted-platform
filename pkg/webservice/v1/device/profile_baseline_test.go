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
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// TestProfileToResponse_CarriesPCRBaseline proves the profile's baseline
// reaches the operator surface with hex digests, string-keyed indices, the
// source, the recording time and the seeding device (#404).
func TestProfileToResponse_CarriesPCRBaseline(t *testing.T) {
	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	resp := profileToResponse(&entities.DeviceProfile{
		ID:   1,
		Name: "workers",
		Role: entities.DeviceRoleWorker,
		PCRBaseline: &entities.PCRBaseline{
			Values:               map[int][]byte{0: {0xaa, 0xbb}, 7: {0x01}},
			Source:               entities.BaselineSourceTOFU,
			RecordedAt:           recorded,
			RecordedFromDeviceID: 9007199254740993,
		},
	})
	require.NotNil(t, resp.PCRBaseline)
	assert.Equal(t, map[string]string{"0": "aabb", "7": "01"}, resp.PCRBaseline.Values)
	assert.Equal(t, "tofu", resp.PCRBaseline.Source)
	assert.True(t, recorded.Equal(resp.PCRBaseline.RecordedAt))

	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"recorded_from_device_id":"9007199254740993"`,
		"the seeding device id is a JSON string so it survives a JavaScript client (§3.4)")
	assert.Contains(t, string(raw), `"pcr_baseline":{`)
}

// TestProfileToResponse_NoBaselineOmitted proves a profile without a
// baseline sends none rather than an empty object a console would render
// as a baseline of nothing.
func TestProfileToResponse_NoBaselineOmitted(t *testing.T) {
	resp := profileToResponse(&entities.DeviceProfile{ID: 1, Name: "p", Role: entities.DeviceRoleWorker})
	assert.Nil(t, resp.PCRBaseline)
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "pcr_baseline")
	assert.Nil(t, pcrBaselineEntityToResponse(nil))
}

// TestProfileRequest_CannotCarryPCRBaseline pins that the baseline is
// read-only over REST: a body that names pcr_baseline reaches the entity
// with no baseline. A caller-supplied baseline is the defect #373 removed
// from the attest path; it must not come back through the profile route.
func TestProfileRequest_CannotCarryPCRBaseline(t *testing.T) {
	var req ProfileRequest
	body := `{"id": 1, "name": "p", "role": "worker", "pcr_baseline": {"values": {"0": "aabb"}, "source": "signed", "recorded_at": "2026-09-01T12:00:00Z"}}`
	require.NoError(t, json.Unmarshal([]byte(body), &req))

	profile, err := profileRequestToEntity(&req)
	require.NoError(t, err)
	assert.Nil(t, profile.PCRBaseline, "the request contract has no baseline field; the verifier alone writes it")
}

// TestCRUDHandler_UpdateProfile_PreservesPCRBaseline is the live REST round
// trip for #446: a profile edit through PUT (whose body cannot carry a
// baseline) reaches the real ProfileService and the captured baseline
// survives, with the response reporting it.
func TestCRUDHandler_UpdateProfile_PreservesPCRBaseline(t *testing.T) {
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	ds := devicepkg.NewDatastore(storage, logging.DefaultLogger())
	profiles, err := devicepkg.NewProfileService(ds)
	require.NoError(t, err)
	handler := &CRUDHandler{
		logger:         logging.DefaultLogger(),
		responseWriter: &mockResponseWriter{},
		deviceService:  newMockDeviceService(),
		profileService: profiles,
	}

	recorded := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, profiles.Save(context.Background(), &entities.DeviceProfile{
		ID: 4460, Name: "workers", Role: entities.DeviceRoleWorker,
		PCRBaseline: &entities.PCRBaseline{
			Values: map[int][]byte{7: {0xbb}}, Source: entities.BaselineSourceTOFU, RecordedAt: recorded, RecordedFromDeviceID: 77,
		},
	}))

	req := httptest.NewRequest(http.MethodPut, "/device/profiles/4460",
		bytes.NewBufferString(`{"name": "workers-renamed", "role": "worker"}`))
	req = mux.SetURLVars(req, map[string]string{"id": "4460"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.UpdateProfile(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp ProfileFullResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "workers-renamed", resp.Name)
	require.NotNil(t, resp.PCRBaseline, "the update response must report the preserved baseline")
	assert.Equal(t, "tofu", resp.PCRBaseline.Source)
	assert.Equal(t, "bb", resp.PCRBaseline.Values["7"])

	stored, err := profiles.Get(context.Background(), 4460)
	require.NoError(t, err)
	require.NotNil(t, stored.PCRBaseline, "a PUT that cannot carry the baseline must not erase it")
	assert.True(t, recorded.Equal(stored.PCRBaseline.RecordedAt))
}
