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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// storedProfile returns a profile as the device-profile store hands it back:
// decoded with UseNumber (#125), so its config numbers are json.Number.
func storedProfile(t *testing.T) *entities.DeviceProfile {
	t.Helper()
	stored := []byte(`{"id":1,"name":"compute","role":"worker",` +
		`"config":{"webservice":{"port":8443,"timeout":1.5}}}`)
	var profile entities.DeviceProfile
	require.NoError(t, datastore.DecodeEntity(stored, &profile))
	return &profile
}

// newYAMLProfileHandler returns a CRUD handler that writes through the real
// response writer, so Accept: application/yaml takes the shared YAML path.
func newYAMLProfileHandler(t *testing.T) *CRUDHandler {
	t.Helper()
	handler, _, profileSvc := newTestHandler()
	handler.responseWriter = newTestResponseWriter()
	profileSvc.profiles[1] = storedProfile(t)
	return handler
}

// TestProfileYAMLResponse_KeepsStoredNumbers covers the ordinary profile GET
// and list responses: a stored config number must come back as a YAML number,
// not as the quoted string a json.Number would otherwise encode to.
func TestProfileYAMLResponse_KeepsStoredNumbers(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		vars    map[string]string
		respond func(h *CRUDHandler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:    "get",
			target:  "/device/profiles/1",
			vars:    map[string]string{"id": "1"},
			respond: (*CRUDHandler).GetProfileByID,
		},
		{
			name:    "list",
			target:  "/device/profiles",
			respond: (*CRUDHandler).ListProfiles,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newYAMLProfileHandler(t)
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			req.Header.Set("Accept", "application/yaml")
			if tt.vars != nil {
				req = mux.SetURLVars(req, tt.vars)
			}
			w := httptest.NewRecorder()

			tt.respond(handler, w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "application/yaml", w.Header().Get("Content-Type"))
			body := w.Body.String()
			assert.Contains(t, body, "port: 8443\n")
			assert.Contains(t, body, "timeout: 1.5\n")
			assert.NotContains(t, body, `"8443"`)
			assert.NotContains(t, body, `"1.5"`)
		})
	}
}

// TestProfileYAMLResponse_UnknownProfile checks the YAML path still reports a
// missing stored profile as an error rather than an empty document.
func TestProfileYAMLResponse_UnknownProfile(t *testing.T) {
	handler := newYAMLProfileHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/device/profiles/999", nil)
	req.Header.Set("Accept", "application/yaml")
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handler.GetProfileByID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.NotContains(t, w.Body.String(), "port:")
}
