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

package switchapi

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

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// decodeErrorResponse reads the response envelope and returns its error text.
func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, rec.Code, resp.Code)
	return resp.Error
}

func TestDecodeVar(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"plain name", "core-01", "core-01"},
		{"encoded slash", "Eth1%2F3", "Eth1/3"},
		{"encoded space", "Gi%200%2F1", "Gi 0/1"},
		{"empty", "", ""},
		{"malformed escape is kept raw", "Eth%zz", "Eth%zz"},
		{"truncated escape is kept raw", "Eth1%2", "Eth1%2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, decodeVar(tt.raw))
		})
	}
}

// The handlers reject a request whose route carries no switch or port name
// with a 400 and the typed error, before any manager lookup. The service has
// no managers, so a handler that skipped the check would answer 404 instead.
func TestHandlers_MissingPathVars(t *testing.T) {
	h := newTestHandlers(&mockSwitchService{managers: map[string]switchmgmt.Manager{}})
	vlanBody := `{"vlan_id":200}`

	tests := []struct {
		name    string
		handler http.HandlerFunc
		vars    map[string]string
		wantErr error
	}{
		{"ListPorts no switch", h.ListPorts, map[string]string{}, ErrMissingSwitchName{}},
		{"GetPortStatus no switch", h.GetPortStatus, map[string]string{"port": "Eth1%2F3"}, ErrMissingSwitchName{}},
		{"GetPortStatus no port", h.GetPortStatus, map[string]string{"switch": "core-01"}, ErrMissingPortName{}},
		{"SetPortVLAN no switch", h.SetPortVLAN, map[string]string{"port": "Eth1%2F3"}, ErrMissingSwitchName{}},
		{"SetPortVLAN no port", h.SetPortVLAN, map[string]string{"switch": "core-01"}, ErrMissingPortName{}},
		{"EnablePort no switch", h.EnablePort, map[string]string{"port": "Eth1%2F3"}, ErrMissingSwitchName{}},
		{"EnablePort no port", h.EnablePort, map[string]string{"switch": "core-01"}, ErrMissingPortName{}},
		{"DisablePort no switch", h.DisablePort, map[string]string{"port": "Eth1%2F3"}, ErrMissingSwitchName{}},
		{"DisablePort no port", h.DisablePort, map[string]string{"switch": "core-01", "port": ""}, ErrMissingPortName{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(vlanBody)))
			req = mux.SetURLVars(req, tt.vars)
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tt.wantErr.Error(), decodeErrorResponse(t, rec))
		})
	}
}

// A switch name is percent-decoded before the manager lookup, as a port name is.
func TestListPorts_EncodedSwitchName(t *testing.T) {
	mgr := &mockManager{
		listPortsFunc: func(context.Context) ([]*switchwire.PortStatus, error) {
			return []*switchwire.PortStatus{{Port: "Eth1/1", Enabled: true}}, nil
		},
	}
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"rack/01": mgr}}
	router := newTestRouter(newTestHandlers(svc))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/rack%2F01/ports", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Success bool                     `json:"success"`
		Payload []*switchwire.PortStatus `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	require.Len(t, resp.Payload, 1)
	assert.Equal(t, "Eth1/1", resp.Payload[0].Port)
}

func TestGetPortStatus_SwitchNotFound(t *testing.T) {
	called := false
	mgr := &mockManager{
		getPortStatusFunc: func(context.Context, string) (*switchwire.PortStatus, error) {
			called = true
			return nil, nil
		},
	}
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	router := newTestRouter(newTestHandlers(svc))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/nonexistent/ports/Eth1%2F3", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, ErrSwitchNotFound{Name: "nonexistent"}.Error(), decodeErrorResponse(t, rec))
	assert.False(t, called, "no manager may be queried for an unknown switch")
}
