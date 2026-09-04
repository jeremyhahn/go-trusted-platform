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

	"github.com/stretchr/testify/assert"

	platformdevice "github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

// wsVLANErrorCases are the two shapes the mapping must recognise: the typed
// error as the service layer returns it, and the same error wrapped, which a
// bare type assertion would miss.
func wsVLANErrorCases() []struct {
	name string
	err  error
} {
	return []struct {
		name string
		err  error
	}{
		{"typed error", platformdevice.ErrProfileVLANsNotDistinct{VLAN: 200}},
		{"wrapped typed error", &platformdevice.WrappedError{Msg: "failed to save profile", Err: platformdevice.ErrProfileVLANsNotDistinct{VLAN: 200}}},
	}
}

// TestCRUDHandler_handleServiceError_VLANsNotDistinct asserts the webservice
// CRUD handler reports the typed validation failure as 400 even when
// wrapped; the bare type assertion it replaced only matched the unwrapped
// value.
func TestCRUDHandler_handleServiceError_VLANsNotDistinct(t *testing.T) {
	for _, tc := range wsVLANErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newTestHandler()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/devices/profiles", nil)

			handler.handleServiceError(rec, req, tc.err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

// TestCRUDHandler_handleServiceError_UnrelatedStaysInternal guards the other
// direction: a genuine server failure must not be reported as a client error.
func TestCRUDHandler_handleServiceError_UnrelatedStaysInternal(t *testing.T) {
	handler, _, _ := newTestHandler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/profiles", nil)

	handler.handleServiceError(rec, req, &platformdevice.WrappedError{Msg: "failed to save profile", Err: assert.AnError})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestHandleServiceErr_VLANsNotDistinct covers the package-level helper the
// template routes use, which had no client-error arm for this error at all
// and returned 500.
func TestHandleServiceErr_VLANsNotDistinct(t *testing.T) {
	for _, tc := range wsVLANErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/devices/templates/1/create-profile", nil)

			handleServiceErr(&mockResponseWriter{}, rec, req, tc.err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

// TestHandleServiceErr_UnrelatedStaysInternal is its error-direction
// counterpart.
func TestHandleServiceErr_UnrelatedStaysInternal(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/1/create-profile", nil)

	handleServiceErr(&mockResponseWriter{}, rec, req, &platformdevice.WrappedError{Msg: "failed to save profile", Err: assert.AnError})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
