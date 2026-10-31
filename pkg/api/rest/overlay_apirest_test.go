package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// overlayErrorMessage decodes the OverlayErrorResponse an overlay handler wrote.
func overlayErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp OverlayErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, rec.Code, resp.Code, "the body carries the status it was sent with")
	return resp.Error
}

// The router never yields an empty or undecodable path variable; the handlers
// still refuse one when called directly, so a mis-registered route cannot
// reach the overlay with it.
func TestOverlayAPIRest_PathVariableRefusals(t *testing.T) {
	t.Parallel()
	h, _ := setupOverlayTestHandler(newMockOverlayService())

	_, unescapeErr := url.PathUnescape("aa%zz")
	require.Error(t, unescapeErr)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		vars    map[string]string
		want    string
	}{
		{"get VTEP", h.handleGetVTEP, map[string]string{"node_id": ""}, ErrInvalidNodeID{}.Error()},
		{"delete VNI", h.handleDeleteVNI, map[string]string{"vni": ""}, ErrInvalidVNI{}.Error()},
		{"forget empty MAC", h.handleForgetMAC, map[string]string{"mac": ""}, ErrInvalidMAC{}.Error()},
		{"forget undecodable MAC", h.handleForgetMAC, map[string]string{"mac": "aa%zz"}, ErrInvalidMAC{MAC: "aa%zz"}.Error()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/", nil), tc.vars)
			rec := httptest.NewRecorder()

			tc.handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want, overlayErrorMessage(t, rec))
		})
	}
}

// A VLAN the overlay itself refuses is the caller's fault, not the server's.
func TestOverlayAPIRest_ServiceRefusesVLAN(t *testing.T) {
	t.Parallel()
	svc := newMockOverlayService()
	svc.createVNIErr = ErrInvalidVLAN{VLAN: 7}
	_, router := setupOverlayTestHandler(svc)
	body, err := json.Marshal(VNIConfigRequest{VNI: 100, VLAN: 7})
	require.NoError(t, err)
	rec := sdnServe(router, http.MethodPost, "/api/v1/sdn/overlay/vnis", string(body))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	want := ErrOverlayOperationFailed{Operation: "create_vni", Cause: ErrInvalidVLAN{VLAN: 7}}.Error()
	assert.Equal(t, want, overlayErrorMessage(t, rec))
}

func TestOverlayAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	t.Parallel()
	h := NewOverlayHandlers(nil, nil)
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
