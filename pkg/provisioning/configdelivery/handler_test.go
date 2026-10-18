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

package configdelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	devicewire "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

func testHandler(t *testing.T) (RestHandler, *Service) {
	t.Helper()
	return testHandlerWithDeps(t, &mockProfileResolver{}, &mockEABService{})
}

func testHandlerWithDeps(t *testing.T, profileSvc ProfileResolver, eabSvc eab.Service) (RestHandler, *Service) {
	t.Helper()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	svc, err := NewService(ServiceParams{
		ProfileService: profileSvc,
		EABService:     eabSvc,
		BaseURL:        "https://platform.example.com",
		RequireEKMatch: boolPtr(false),
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}

	rw := response.NewResponseWriter(logger, nil)

	h, err := NewHandler(HandlerParams{
		Service:        svc,
		ResponseWriter: rw,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error creating handler: %v", err)
	}

	return h, svc
}

func TestHandler_GetNonce(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/nonce", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.GetNonce(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
}

func TestHandler_GetNonce_ReturnsNonceField(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/nonce", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.GetNonce(w, req)

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", resp.Payload)
	}

	nonce, ok := payload["nonce"]
	if !ok || nonce == "" {
		t.Fatal("expected nonce field in payload")
	}
}

func TestHandler_FetchConfig_InvalidBody(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FetchConfig_MissingFields(t *testing.T) {
	h, _ := testHandler(t)

	body, _ := json.Marshal(ConfigRequest{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FetchConfig_Found(t *testing.T) {
	expectedConfig := map[string]string{"platform": "config"}
	profileSvc := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: 1, Config: expectedConfig}, nil
		},
	}
	h, svc := testHandlerWithDeps(t, profileSvc, &mockEABService{profileID: 1})

	nonce := issueValidNonce(t, svc)

	body, _ := json.Marshal(ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", resp.Payload)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", payload["status"])
	}
}

func TestHandler_FetchConfig_Pending(t *testing.T) {
	profileSvc := &mockProfileResolver{
		findConfigFunc: func(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
			return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
		},
	}
	h, svc := testHandlerWithDeps(t, profileSvc, nil)

	nonce := issueValidNonce(t, svc)

	body, _ := json.Marshal(ConfigRequest{
		EKSerial: "ek-unknown",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", resp.Payload)
	}

	sessionID, ok := payload["session_id"]
	if !ok || sessionID == "" {
		t.Fatal("expected session_id in pending response")
	}
}

func TestHandler_FetchConfig_InvalidNonce(t *testing.T) {
	h, _ := testHandler(t)

	body, _ := json.Marshal(ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    "bad-nonce",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_PollSession_Pending(t *testing.T) {
	h, svc := testHandler(t)

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/"+session.ID+"/poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", resp.Payload)
	}

	status, ok := payload["status"]
	if !ok || status != "pending" {
		t.Fatalf("expected status=pending, got %v", status)
	}
}

func TestHandler_PollSession_Fulfilled(t *testing.T) {
	h, svc := testHandler(t)

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	svc.sessionsMu.Lock()
	session.Fulfilled = true
	session.Profile = &entities.DeviceProfile{ID: 1, Config: "test-config"}
	svc.sessionsMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/"+session.ID+"/poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be map, got %T", resp.Payload)
	}

	status, ok := payload["status"]
	if !ok || status != "ok" {
		t.Fatalf("expected status=ok, got %v", status)
	}
}

// TestHandler_PollSession_FulfilledWithoutProfile verifies the REST handler
// maps the typed profile-missing invalid-state error to 500 instead of
// panicking on a session fulfilled through the profile-less path.
func TestHandler_PollSession_FulfilledWithoutProfile(t *testing.T) {
	h, svc := testHandler(t)

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	svc.sessionsMu.Lock()
	session.Fulfilled = true
	session.Profile = nil
	svc.sessionsMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/"+session.ID+"/poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Success {
		t.Fatal("expected failure response")
	}
	want := ErrSessionProfileMissing{SessionID: session.ID}.Error()
	if resp.Error != want {
		t.Fatalf("expected error %q, got %q", want, resp.Error)
	}
}

func TestHandler_PollSession_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/nonexistent/poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": "nonexistent"})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_PollSession_Expired(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		BaseURL:        "https://platform.example.com",
		SessionTTL:     1 * time.Nanosecond,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	rw := response.NewResponseWriter(logger, nil)
	h, err := NewHandler(HandlerParams{
		Service:        svc,
		ResponseWriter: rw,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/"+session.ID+"/poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_Success(t *testing.T) {
	profileSvc := &mockProfileResolver{
		getFunc: func(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: id, Config: "test-config"}, nil
		},
	}
	h, svc := testHandlerWithDeps(t, profileSvc, &mockEABService{})

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	body, _ := json.Marshal(FulfillRequest{
		SessionID: session.ID,
		ProfileID: 1,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/"+session.ID+"/fulfill", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	body, _ := json.Marshal(FulfillRequest{
		SessionID: "nonexistent",
		ProfileID: 1,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/nonexistent/fulfill", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": "nonexistent"})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_ZeroProfileID(t *testing.T) {
	h, svc := testHandlerWithDeps(t, &mockProfileResolver{}, &mockEABService{})

	for name, body := range map[string]string{
		"zero":    `{"profile_id": 0}`,
		"missing": `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
			req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/"+session.ID+"/fulfill", strings.NewReader(body))
			req.Header.Set("Accept", "application/json")
			req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
			w := httptest.NewRecorder()

			h.FulfillSession(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), ErrProfileIDRequired{}.Error()) {
				t.Fatalf("body = %s, want the ErrProfileIDRequired text", w.Body.String())
			}
		})
	}
}

func TestHandler_FulfillSession_Expired(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, err := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		BaseURL:        "https://platform.example.com",
		SessionTTL:     1 * time.Nanosecond,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	rw := response.NewResponseWriter(logger, nil)
	h, err := NewHandler(HandlerParams{
		Service:        svc,
		ResponseWriter: rw,
		Logger:         logger,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(FulfillRequest{
		SessionID: session.ID,
		ProfileID: 1,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/"+session.ID+"/fulfill", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_AlreadyFulfilled(t *testing.T) {
	h, svc := testHandler(t)

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	svc.sessionsMu.Lock()
	session.Fulfilled = true
	session.Profile = &entities.DeviceProfile{ID: 1, Config: "test-config"}
	svc.sessionsMu.Unlock()

	body, _ := json.Marshal(FulfillRequest{
		SessionID: session.ID,
		ProfileID: 2,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/"+session.ID+"/fulfill", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_GetSession_NotFound(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/nonexistent", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": "nonexistent"})
	w := httptest.NewRecorder()

	h.GetSession(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestHandler_GetSession_Found(t *testing.T) {
	h, svc := testHandler(t)

	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/"+session.ID, nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()

	h.GetSession(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestHandler_ListSessions(t *testing.T) {
	h, svc := testHandler(t)

	svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	svc.CreateSession("ek-2", "aa:bb:cc:dd:ee:02")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.ListSessions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
}

func TestHandler_FetchConfig_InvalidEAB(t *testing.T) {
	eabSvc := &mockEABService{
		validateFunc: func(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error) {
			return nil, eab.ErrInvalidCredential{Reason: "hmac mismatch"}
		},
	}
	h, svc := testHandlerWithDeps(t, &mockProfileResolver{}, eabSvc)

	nonce := issueValidNonce(t, svc)
	body, _ := json.Marshal(ConfigRequest{
		EKSerial: "ek-123",
		EABKeyID: "key-1",
		EABHMAC:  validEABHMAC(),
		Nonce:    nonce,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/config", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	h.FetchConfig(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", w.Code)
	}
}

func TestNewHandler_MissingLogger(t *testing.T) {
	_, err := NewHandler(HandlerParams{})
	if err == nil {
		t.Fatal("expected error for missing logger")
	}

	var missing ErrMissingLogger
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrMissingLogger, got %T: %v", err, err)
	}
}

func TestNewHandler_MissingService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	_, err := NewHandler(HandlerParams{
		Logger: logger,
	})
	if err == nil {
		t.Fatal("expected error for missing service")
	}

	var missing ErrMissingService
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrMissingService, got %T: %v", err, err)
	}
}

func TestNewHandler_MissingResponseWriter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	svc, _ := NewService(ServiceParams{
		ProfileService: &mockProfileResolver{},
		EABService:     &mockEABService{},
		Logger:         logger,
	})

	_, err := NewHandler(HandlerParams{
		Logger:  logger,
		Service: svc,
	})
	if err == nil {
		t.Fatal("expected error for missing response writer")
	}

	var missing ErrMissingResponseWriter
	if !errors.As(err, &missing) {
		t.Fatalf("expected ErrMissingResponseWriter, got %T: %v", err, err)
	}
}

func TestHandler_PollSession_MissingSessionID(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions//poll", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": ""})
	w := httptest.NewRecorder()

	h.PollSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_GetSession_MissingSessionID(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provision/sessions/", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": ""})
	w := httptest.NewRecorder()

	h.GetSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_InvalidBody(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions/abc/fulfill", bytes.NewReader([]byte("not json")))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": "abc"})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandler_FulfillSession_MissingSessionID(t *testing.T) {
	h, _ := testHandler(t)

	body, _ := json.Marshal(FulfillRequest{
		ProfileID: 1,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provision/sessions//fulfill", bytes.NewReader(body))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": ""})
	w := httptest.NewRecorder()

	h.FulfillSession(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

// fulfilWithBody posts a raw JSON body to FulfillSession for a fresh session
// and returns the recorder plus the profile id the service resolved.
func fulfilWithBody(t *testing.T, body string) (*httptest.ResponseRecorder, uint64) {
	t.Helper()
	var resolved uint64
	profileSvc := &mockProfileResolver{
		getFunc: func(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
			resolved = id
			return &entities.DeviceProfile{ID: id, Config: "test-config"}, nil
		},
	}
	h, svc := testHandlerWithDeps(t, profileSvc, &mockEABService{})
	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/provisioning/sessions/"+session.ID+"/fulfill", bytes.NewReader([]byte(body)))
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()
	h.FulfillSession(w, req)
	return w, resolved
}

// TestHandler_FulfillSession_ProfileIDAcceptsStringOrNumber is the #375 rule
// applied to this route (#418): a JavaScript client can only carry an id above
// 2^53 as a string, and before this the plain uint64 refused it.
func TestHandler_FulfillSession_ProfileIDAcceptsStringOrNumber(t *testing.T) {
	const above2p53 = "9007199254740993"

	w, resolved := fulfilWithBody(t, `{"profile_id": "`+above2p53+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("string id: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if resolved != 9007199254740993 {
		t.Fatalf("string id: service resolved %d, want %s exactly", resolved, above2p53)
	}

	w, resolved = fulfilWithBody(t, `{"profile_id": 42}`)
	if w.Code != http.StatusOK {
		t.Fatalf("number id: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if resolved != 42 {
		t.Fatalf("number id: service resolved %d, want 42", resolved)
	}
}

// TestHandler_FulfillSession_ProfileIDRejectsNonNumeric is the negative: a
// string that is not an unsigned integer is a typed 400, never a zero handed
// to the service — which is what a wrong key used to produce (#418).
func TestHandler_FulfillSession_ProfileIDRejectsNonNumeric(t *testing.T) {
	for _, body := range []string{`{"profile_id": "forty-two"}`, `{"profile_id": -1}`, `{"profile_id": 4.2}`} {
		w, resolved := fulfilWithBody(t, body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
		if resolved != 0 {
			t.Errorf("%s: service was reached with id %d; the decode must fail first", body, resolved)
		}
		var want devicewire.ErrInvalidID
		if !strings.Contains(w.Body.String(), strings.SplitN(want.Error(), ", got", 2)[0]) {
			t.Errorf("%s: 400 body does not carry the typed id error: %s", body, w.Body.String())
		}
	}
}

// TestHandler_GetSession_ProfileIDIsAJSONString pins the response half of the
// #375 rule on this surface (#425): a fulfilled session's profile_id goes out
// as a decimal string, so a JavaScript client above 2^53 reads it exactly.
func TestHandler_GetSession_ProfileIDIsAJSONString(t *testing.T) {
	const above2p53 = "9007199254740993"
	profileSvc := &mockProfileResolver{
		getFunc: func(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
			return &entities.DeviceProfile{ID: id, Config: "test-config"}, nil
		},
	}
	h, svc := testHandlerWithDeps(t, profileSvc, &mockEABService{})
	session := svc.CreateSession("ek-1", "aa:bb:cc:dd:ee:01")
	if err := svc.FulfillSession(context.Background(), session.ID, 9007199254740993); err != nil {
		t.Fatalf("fulfil: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/provisioning/sessions/"+session.ID, nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"sessionID": session.ID})
	w := httptest.NewRecorder()
	h.GetSession(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// The raw bytes are what matters: a string token, not a number that a
	// JavaScript JSON.parse would already have rounded.
	if !strings.Contains(w.Body.String(), `"profile_id":"`+above2p53+`"`) {
		t.Fatalf("profile_id is not emitted as a JSON string: %s", w.Body.String())
	}
}
