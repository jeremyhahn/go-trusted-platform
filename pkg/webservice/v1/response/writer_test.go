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

package response

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSession struct{}

func (m *mockSession) ConsistencyLevel() datastore.ConsistencyLevel {
	return datastore.ConsistencyLevelLocal
}

func (m *mockSession) Close() {}

func (m *mockSession) IsSystemSession() bool {
	return false
}

func (m *mockSession) Logger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, os.Stdout)
}

func (m *mockSession) RequestedServiceID() uint64 {
	return 1
}

func (m *mockSession) SetLogger(*logging.Logger) {}

func (m *mockSession) User() *entities.User {
	return nil
}

func (m *mockSession) UserID() uint64 {
	return 123
}

// unmarshallableYAML is a type that always fails yaml.Marshal
type unmarshallableYAML struct{}

func (u unmarshallableYAML) MarshalYAML() (interface{}, error) {
	return nil, fmt.Errorf("cannot marshal this type to YAML")
}

// unmarshallableJSON is a type that always fails json.Marshal
type unmarshallableJSON struct{}

func (u unmarshallableJSON) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("cannot marshal this type to JSON")
}

func TestNewResponseWriter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	session := &mockSession{}

	writer := NewResponseWriter(logger, session)
	require.NotNil(t, writer)

	rw, ok := writer.(*ResponseWriter)
	require.True(t, ok)
	assert.NotNil(t, rw.logger)
	assert.Equal(t, session, rw.session)
}

func TestSetSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil).(*ResponseWriter)

	session := &mockSession{}
	writer.SetSession(session)

	assert.Equal(t, session, writer.session)
}

func TestWrite(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	tests := []struct {
		name           string
		acceptHeader   string
		response       interface{}
		expectedHeader string
		status         int
	}{
		{
			name:           "JSON accept header",
			acceptHeader:   "application/json",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/json",
			status:         http.StatusOK,
		},
		{
			name:           "text/json accept header",
			acceptHeader:   "text/json",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/json",
			status:         http.StatusOK,
		},
		{
			name:           "YAML accept header",
			acceptHeader:   "application/yaml",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/yaml",
			status:         http.StatusOK,
		},
		{
			name:           "text/yaml accept header",
			acceptHeader:   "text/yaml",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/yaml",
			status:         http.StatusOK,
		},
		{
			name:           "unknown accept header defaults to JSON",
			acceptHeader:   "text/html",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/json",
			status:         http.StatusOK,
		},
		{
			name:           "empty accept header defaults to JSON",
			acceptHeader:   "",
			response:       map[string]string{"key": "value"},
			expectedHeader: "application/json",
			status:         http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("accept", tt.acceptHeader)
			rec := httptest.NewRecorder()

			writer.Write(rec, req, tt.status, tt.response)

			assert.Equal(t, tt.status, rec.Code)
			assert.Equal(t, tt.expectedHeader, rec.Header().Get("Content-Type"))
		})
	}
}

func TestWriteJson(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	t.Run("successful JSON write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		response := map[string]interface{}{
			"success": true,
			"message": "test message",
			"count":   42,
		}

		writer.WriteJson(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), `"success":true`)
		assert.Contains(t, rec.Body.String(), `"message":"test message"`)
		assert.Contains(t, rec.Body.String(), `"count":42`)
	})

	t.Run("handles unmarshalable types", func(t *testing.T) {
		rec := httptest.NewRecorder()

		// Channel cannot be marshaled to JSON
		response := make(chan int)

		writer.WriteJson(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "ResponseWriter failed to marshal")
	})

	t.Run("writes complex nested structure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		response := WebServiceResponse{
			Code:    200,
			Success: true,
			Error:   "",
			Payload: map[string]interface{}{
				"nested": map[string]string{
					"key": "value",
				},
			},
		}

		writer.WriteJson(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"code":200`)
		assert.Contains(t, rec.Body.String(), `"success":true`)
	})

	t.Run("handles nested marshal error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		// Even error responses should be marshaled properly
		errorResponse := WebServiceResponse{
			Code:    500,
			Success: false,
			Error:   "test error",
			Payload: nil,
		}

		writer.WriteJson(rec, http.StatusInternalServerError, errorResponse)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), `"error":"test error"`)
	})

	t.Run("handles custom unmarshallable JSON type", func(t *testing.T) {
		rec := httptest.NewRecorder()

		// Custom type that returns error from MarshalJSON
		response := unmarshallableJSON{}

		writer.WriteJson(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "ResponseWriter failed to marshal")
	})
}

func TestWriteYaml(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	t.Run("successful YAML write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		response := map[string]interface{}{
			"success": true,
			"message": "test message",
			"count":   42,
		}

		writer.WriteYaml(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "success: true")
		assert.Contains(t, rec.Body.String(), "message: test message")
		assert.Contains(t, rec.Body.String(), "count: 42")
	})

	t.Run("writes valid YAML structure", func(t *testing.T) {
		rec := httptest.NewRecorder()
		response := WebServiceResponse{
			Code:    200,
			Success: true,
			Error:   "",
			Payload: map[string]interface{}{
				"nested": map[string]string{
					"key": "value",
				},
			},
		}

		writer.WriteYaml(rec, http.StatusOK, response)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "code: 200")
		assert.Contains(t, rec.Body.String(), "success: true")
	})

	t.Run("handles complex YAML structures", func(t *testing.T) {
		rec := httptest.NewRecorder()
		// Test with various types that YAML can handle
		complexResponse := map[string]interface{}{
			"string":  "value",
			"number":  42,
			"boolean": true,
			"array":   []string{"a", "b", "c"},
			"null":    nil,
		}
		writer.WriteYaml(rec, http.StatusOK, complexResponse)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "string: value")
		assert.Contains(t, rec.Body.String(), "number: 42")
	})

	t.Run("handles custom unmarshallable YAML type", func(t *testing.T) {
		rec := httptest.NewRecorder()

		// Custom type that returns error from MarshalYAML
		response := unmarshallableYAML{}

		writer.WriteYaml(rec, http.StatusOK, response)

		// The error path is triggered, resulting in 500 status
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "YamlWriter failed to marshal")
	})
}

func TestSuccess200(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	t.Run("success with payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("accept", "application/json")
		rec := httptest.NewRecorder()

		payload := map[string]string{"result": "success"}
		writer.Success200(rec, req, payload)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
		assert.Contains(t, rec.Body.String(), `"code":200`)
		assert.Contains(t, rec.Body.String(), `"result":"success"`)
	})

	t.Run("success with nil payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("accept", "application/json")
		rec := httptest.NewRecorder()

		writer.Success200(rec, req, nil)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
		assert.Contains(t, rec.Body.String(), `"payload":null`)
	})
}

func TestSuccess201(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	t.Run("created with payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/resources", nil)
		req.Header.Set("accept", "application/json")
		rec := httptest.NewRecorder()

		payload := map[string]interface{}{
			"id":   123,
			"name": "new resource",
		}
		writer.Success201(rec, req, payload)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
		assert.Contains(t, rec.Body.String(), `"code":201`)
		assert.Contains(t, rec.Body.String(), `"id":123`)
		assert.Contains(t, rec.Body.String(), `"name":"new resource"`)
	})

	t.Run("created with nil payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/resources", nil)
		req.Header.Set("accept", "application/json")
		rec := httptest.NewRecorder()

		writer.Success201(rec, req, nil)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
		assert.Contains(t, rec.Body.String(), `"code":201`)
		assert.Contains(t, rec.Body.String(), `"payload":null`)
	})

	t.Run("created with YAML accept header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/resources", nil)
		req.Header.Set("accept", "application/yaml")
		rec := httptest.NewRecorder()

		payload := map[string]string{"status": "created"}
		writer.Success201(rec, req, payload)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))
		assert.Contains(t, rec.Body.String(), "success: true")
		assert.Contains(t, rec.Body.String(), "code: 201")
	})

	t.Run("created with session logging", func(t *testing.T) {
		session := &mockSession{}
		writerWithSession := NewResponseWriter(logger, session)

		req := httptest.NewRequest(http.MethodPost, "/resources", nil)
		req.Header.Set("accept", "application/json")
		rec := httptest.NewRecorder()

		payload := map[string]string{"resource": "created"}
		writerWithSession.Success201(rec, req, payload)

		assert.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Body.String(), `"success":true`)
	})
}

func TestSuccess404(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	payload := map[string]string{"info": "not found"}
	err := errors.New("resource not found")
	writer.Success404(rec, req, payload, err)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":true`)
	assert.Contains(t, rec.Body.String(), `"code":404`)
	assert.Contains(t, rec.Body.String(), `"error":"resource not found"`)
	assert.Contains(t, rec.Body.String(), `"info":"not found"`)
}

func TestError200(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("validation failed")
	writer.Error200(rec, req, err)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"code":200`)
	assert.Contains(t, rec.Body.String(), `"payload":"validation failed"`)
}

func TestError400(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("bad request")
	writer.Error400(rec, req, err)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"code":400`)
	assert.Contains(t, rec.Body.String(), `"error":"bad request"`)
}

func TestError401(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("unauthorized")
	writer.Error401(rec, req, err)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"code":401`)
	assert.Contains(t, rec.Body.String(), `"error":"unauthorized"`)
}

func TestError403(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("forbidden")
	payload := map[string]string{"reason": "insufficient permissions"}
	writer.Error403(rec, req, err, payload)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), `"code":403`)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"error":"forbidden"`)
	assert.Contains(t, rec.Body.String(), `"reason":"insufficient permissions"`)
}

func TestError404(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("not found")
	writer.Error404(rec, req, err)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"code":404`)
	assert.Contains(t, rec.Body.String(), `"error":"not found"`)
}

func TestError500(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	writer := NewResponseWriter(logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	err := errors.New("internal server error")
	writer.Error500(rec, req, err)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"success":false`)
	assert.Contains(t, rec.Body.String(), `"code":500`)
	assert.Contains(t, rec.Body.String(), `"error":"internal server error"`)
}

func TestResponseWriterWithSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	session := &mockSession{}
	writer := NewResponseWriter(logger, session)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("accept", "application/json")
	rec := httptest.NewRecorder()

	writer.Success200(rec, req, map[string]string{"data": "test"})

	assert.Equal(t, http.StatusOK, rec.Code)
	// Session info should be logged but not included in response
	assert.Contains(t, rec.Body.String(), "data")
}

func TestLogErrorWithSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	session := &mockSession{}
	rw := &ResponseWriter{
		logger:  logger,
		session: session,
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := errors.New("test error")

	// This mainly tests that logging doesn't panic with a session
	rw.logError(req, err)

	// Also test without session
	rw.session = nil
	rw.logError(req, err)

	// No assertion - just ensuring no panic
	assert.True(t, true)
}

func TestLogRequestWithSession(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	session := &mockSession{}
	rw := &ResponseWriter{
		logger:  logger,
		session: session,
	}

	req := httptest.NewRequest(http.MethodGet, "/test?param=value", nil)

	// This mainly tests that logging doesn't panic with a session
	rw.logRequest(req)

	// Also test without session
	rw.session = nil
	rw.logRequest(req)

	// No assertion - just ensuring no panic
	assert.True(t, true)
}

func TestLogResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelInfo, os.Stdout)
	rw := &ResponseWriter{
		logger:  logger,
		session: nil,
	}

	rec := httptest.NewRecorder()
	rw.logResponse(rec, http.StatusOK, "test response")

	// No assertion - just ensuring no panic
	assert.True(t, true)
}

func TestWebServiceResponse(t *testing.T) {
	t.Run("creates valid response structure", func(t *testing.T) {
		response := WebServiceResponse{
			Code:    200,
			Error:   "",
			Success: true,
			Payload: map[string]string{"key": "value"},
		}

		assert.Equal(t, 200, response.Code)
		assert.True(t, response.Success)
		assert.Empty(t, response.Error)
		assert.NotNil(t, response.Payload)
	})

	t.Run("creates error response structure", func(t *testing.T) {
		response := WebServiceResponse{
			Code:    500,
			Error:   "internal error",
			Success: false,
			Payload: nil,
		}

		assert.Equal(t, 500, response.Code)
		assert.False(t, response.Success)
		assert.Equal(t, "internal error", response.Error)
		assert.Nil(t, response.Payload)
	})
}

func TestErrServiceNotFound(t *testing.T) {
	// Test that the error type is correctly defined and usable
	err := ErrServiceNotFound
	assert.NotNil(t, err)
	assert.Equal(t, "service not found", err.Error())

	// Test that it can be used with errors.Is
	wrappedErr := fmt.Errorf("wrapped: %w", ErrServiceNotFound)
	assert.True(t, errors.Is(wrappedErr, ErrServiceNotFound))
}
