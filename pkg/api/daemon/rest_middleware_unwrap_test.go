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

package daemon

import (
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The REST middleware wraps the response writer; a route that moves its write
// deadline (compute stop and reboot) must still reach the connection through
// the wrappers, or the move fails and the reply is cut off at the server's
// write timeout.
func TestRESTMiddlewareWritersReachTheConnection(t *testing.T) {
	wrappers := map[string]func(http.ResponseWriter) http.ResponseWriter{
		"status": func(w http.ResponseWriter) http.ResponseWriter {
			return &statusWriter{ResponseWriter: w, status: http.StatusOK}
		},
		"gzip": func(w http.ResponseWriter) http.ResponseWriter {
			return &gzipResponseWriter{Writer: gzip.NewWriter(w), ResponseWriter: w}
		},
	}
	for name, wrap := range wrappers {
		t.Run(name, func(t *testing.T) {
			deadlineErr := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				deadlineErr <- http.NewResponseController(wrap(w)).SetWriteDeadline(time.Now().Add(time.Minute))
			}))
			t.Cleanup(server.Close)

			resp, err := server.Client().Get(server.URL)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			assert.NoError(t, <-deadlineErr)
		})
	}
}

// A writer that does not unwrap cannot move the deadline: the refusal the
// Unwrap methods above exist to avoid.
func TestRESTMiddlewareWriterWithoutUnwrapCannotMoveTheDeadline(t *testing.T) {
	type opaqueWriter struct{ http.ResponseWriter }
	deadlineErr := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		deadlineErr <- http.NewResponseController(opaqueWriter{w}).SetWriteDeadline(time.Now().Add(time.Minute))
	}))
	t.Cleanup(server.Close)

	resp, err := server.Client().Get(server.URL)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.True(t, errors.Is(<-deadlineErr, http.ErrNotSupported))
}
