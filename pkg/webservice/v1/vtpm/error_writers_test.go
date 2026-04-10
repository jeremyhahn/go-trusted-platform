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

package vtpm

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newErrorTestHandler(t *testing.T) RestHandler {
	t.Helper()
	logger := logging.DefaultLogger()
	svc := &testableGeneratorService{}
	respWriter := response.NewResponseWriter(logger, nil)
	h, err := NewHandler(HandlerParams{
		Logger:           logger,
		GeneratorService: svc,
		ResponseWriter:   respWriter,
	})
	require.NoError(t, err)
	return h
}

// writeServiceError tests

func TestWriteServiceError_NotFound(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "get", errors.New("instance not found"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteServiceError_Invalid(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("field is invalid"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteServiceError_Required(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("name is required"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteServiceError_MustBe(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("value must be positive"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteServiceError_CannotBe(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("value cannot be empty"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteServiceError_AlreadyExists(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("instance already exists"))
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestWriteServiceError_AlreadyRunning(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "start", errors.New("instance is already running"))
	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestWriteServiceError_DoesNotExist(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "get", errors.New("resource does not exist"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteServiceError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeServiceError(rec, req, "create", errors.New("unexpected disk failure"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeGetByProfileError tests

func TestWriteGetByProfileError_NotFound(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeGetByProfileError(rec, req, 42, errors.New("profile not found"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteGetByProfileError_NotAssociated(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeGetByProfileError(rec, req, 42, errors.New("device not associated with profile"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteGetByProfileError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeGetByProfileError(rec, req, 42, errors.New("database connection failed"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeDeleteError tests

func TestWriteDeleteError_NotFound(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/test", nil)

	h.(*handler).writeDeleteError(rec, req, "vtpm-1", errors.New("instance not found"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteDeleteError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/test", nil)

	h.(*handler).writeDeleteError(rec, req, "vtpm-1", errors.New("failed to clean up resources"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeStartError tests

func TestWriteStartError_NotFound(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStartError(rec, req, "vtpm-1", errors.New("instance not found"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteStartError_AlreadyRunning(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStartError(rec, req, "vtpm-1", errors.New("instance already running"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteStartError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStartError(rec, req, "vtpm-1", errors.New("failed to start swtpm process"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeStopError tests

func TestWriteStopError_NotFound(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStopError(rec, req, "vtpm-1", errors.New("instance not found"))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWriteStopError_NotRunning(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStopError(rec, req, "vtpm-1", errors.New("instance is not running"))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWriteStopError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	h.(*handler).writeStopError(rec, req, "vtpm-1", errors.New("signal failed"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeGetError non-found path

func TestWriteGetError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeGetError(rec, req, "vtpm-1", errors.New("database connection refused"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeEKExportError non-found path

func TestWriteEKExportError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeEKExportError(rec, req, "vtpm-1", errors.New("certificate encoding failed"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// writeEKFingerprintError non-found path

func TestWriteEKFingerprintError_InternalError(t *testing.T) {
	h := newErrorTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	h.(*handler).writeEKFingerprintError(rec, req, "vtpm-1", errors.New("fingerprint computation failed"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// containsAny edge cases

func TestContainsAny_NoMatch(t *testing.T) {
	h := newErrorTestHandler(t)
	result := h.(*handler).containsAny("all good here", "error", "failure")
	assert.False(t, result)
}

func TestContainsAny_CaseInsensitive(t *testing.T) {
	h := newErrorTestHandler(t)
	result := h.(*handler).containsAny("NOT FOUND anywhere", "not found")
	assert.True(t, result)
}

func TestContainsAny_EmptySubstrings(t *testing.T) {
	h := newErrorTestHandler(t)
	result := h.(*handler).containsAny("some text")
	assert.False(t, result)
}
