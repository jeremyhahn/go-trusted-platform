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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
)

func vlanErrTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// vlanErrorCases are the two shapes the mapping has to recognise: the typed
// error as the service layer returns it, and the same error wrapped, which a
// bare type assertion would miss.
func vlanErrorCases() []struct {
	name string
	err  error
} {
	return []struct {
		name string
		err  error
	}{
		{"typed error", device.ErrProfileVLANsNotDistinct{VLAN: 200}},
		{"wrapped typed error", &device.WrappedError{Msg: "failed to save profile", Err: device.ErrProfileVLANsNotDistinct{VLAN: 200}}},
	}
}

// TestDeviceHandlers_writeProfileError_VLANsNotDistinct asserts REST reports
// the typed validation failure as 400. Before #133 it reached the default
// arm and returned 500: the error message carries no "ID", so the
// string-matching isInvalidIDError arm never fired for it.
func TestDeviceHandlers_writeProfileError_VLANsNotDistinct(t *testing.T) {
	h := &DeviceHandlers{logger: vlanErrTestLogger()}

	for _, tc := range vlanErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.writeProfileError(rec, "save", tc.err)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}

// TestDeviceHandlers_writeProfileError_UnrelatedStaysInternal guards the
// other direction: the new typed arm must not swallow genuine server
// failures into a 400.
func TestDeviceHandlers_writeProfileError_UnrelatedStaysInternal(t *testing.T) {
	h := &DeviceHandlers{logger: vlanErrTestLogger()}

	rec := httptest.NewRecorder()
	h.writeProfileError(rec, "save", &device.WrappedError{Msg: "failed to save profile", Err: assert.AnError})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
