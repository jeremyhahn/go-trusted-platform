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

package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
)

// mockUnifiedLoginClient is a boundary mock of the quicbaas SDK unified
// login surface. It records the requests it received so tests can assert
// the platform drives the BeginLogin/FinishLogin ceremony with the mTLS
// factor and consumes the returned OIDC bearer. It deliberately performs
// no cryptographic verification — that semantic is owned by the quicbaas
// server, not the platform, and mocking it here would be wrong.
type mockUnifiedLoginClient struct {
	beginReq  *quicbaas.BeginLoginRequest
	finishReq *quicbaas.FinishLoginRequest

	beginResp *quicbaas.BeginLoginResponse
	beginErr  error

	finishResp *quicbaas.FinishLoginResponse
	finishErr  error
}

// newFinishLoginResponse builds a quicbaas FinishLoginResponse with its
// embedded qrdb-owned response allocated. The embedded type is reached via
// type inference (newEmbedded) because layerguard forbids importing go-qrdb
// directly, including from _test.go files.
func newFinishLoginResponse(bearer string, expiresAt time.Time, identity *quicbaas.Identity) *quicbaas.FinishLoginResponse {
	resp := &quicbaas.FinishLoginResponse{}
	resp.FinishLoginResponse = newEmbedded(resp.FinishLoginResponse)
	resp.Bearer = bearer
	resp.ExpiresAt = expiresAt
	resp.Identity = identity
	return resp
}

// newEmbedded allocates a zero value of the pointee type carried by p.
func newEmbedded[T any](p *T) *T { return new(T) }

func (m *mockUnifiedLoginClient) BeginLogin(ctx context.Context, req quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error) {
	cp := req
	m.beginReq = &cp
	if m.beginErr != nil {
		return nil, m.beginErr
	}
	return m.beginResp, nil
}

func (m *mockUnifiedLoginClient) FinishLogin(ctx context.Context, req quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error) {
	cp := req
	m.finishReq = &cp
	if m.finishErr != nil {
		return nil, m.finishErr
	}
	return m.finishResp, nil
}

// newLoginHandler builds a *RestHandler with a real signing JWT service
// (so RefreshToken/Verify keep working) and the supplied unified login
// client wired in.
func newLoginHandler(t *testing.T, loginClient UnifiedLoginClient) (*RestHandler, *MockUserService) {
	t.Helper()
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	if _, err := ks.GenerateKey(context.Background(), params.KeyAttrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwtService, err := NewService(context.Background(), params)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)
	h, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	if err != nil {
		t.Fatalf("NewRestHandler: %v", err)
	}
	rh := h.(*RestHandler)
	if loginClient != nil {
		rh.SetUnifiedLoginClient(loginClient)
	}
	return rh, mockUserService
}

func loginRequest(t *testing.T, email string) *http.Request {
	t.Helper()
	body, err := json.Marshal(service.UserCredential{Email: email})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Accept", "application/json")
	return req
}

// TestGenerateToken_UnifiedLoginSuccess asserts the migrated /login path
// drives the SDK BeginLogin/FinishLogin mTLS ceremony and returns the
// SDK-issued OIDC bearer verbatim (not a locally minted JWT).
func TestGenerateToken_UnifiedLoginSuccess(t *testing.T) {
	const wantBearer = "oidc-bearer-token-xyz"
	mc := &mockUnifiedLoginClient{
		beginResp: &quicbaas.BeginLoginResponse{
			SessionID: "sess-123",
			Nonce:     []byte("nonce"),
			ExpiresAt: time.Now().Add(time.Minute),
		},
		finishResp: newFinishLoginResponse(
			wantBearer,
			time.Now().Add(time.Hour),
			&quicbaas.Identity{Subject: "admin@example.com", TenantID: "default"},
		),
	}
	handler, _ := newLoginHandler(t, mc)

	w := httptest.NewRecorder()
	handler.GenerateToken(w, loginRequest(t, "admin@example.com"))

	assert.Equal(t, http.StatusOK, w.Code)

	var resp response.WebServiceResponse
	assert.Nil(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, wantBearer, resp.Payload)

	// The platform must drive the mTLS factor and carry the email hint.
	if assert.NotNil(t, mc.beginReq) {
		assert.Equal(t, quicbaas.FactorTypeMTLS, mc.beginReq.Type)
		assert.Equal(t, "admin@example.com", mc.beginReq.Hint)
	}
	// FinishLogin must echo the BeginLogin session id and the same factor.
	if assert.NotNil(t, mc.finishReq) {
		assert.Equal(t, "sess-123", mc.finishReq.SessionID)
		assert.Equal(t, quicbaas.FactorTypeMTLS, mc.finishReq.Type)
	}
}

// TestGenerateToken_BeginLoginError asserts a BeginLogin failure surfaces
// as 401 and FinishLogin is not called.
func TestGenerateToken_BeginLoginError(t *testing.T) {
	mc := &mockUnifiedLoginClient{beginErr: errors.New("no enrolled mtls factor")}
	handler, _ := newLoginHandler(t, mc)

	w := httptest.NewRecorder()
	handler.GenerateToken(w, loginRequest(t, "nobody@example.com"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotNil(t, mc.beginReq)
	assert.Nil(t, mc.finishReq, "FinishLogin must not run after BeginLogin fails")
}

// TestGenerateToken_FinishLoginError asserts a FinishLogin failure (e.g.
// the server rejected the proof) surfaces as 401.
func TestGenerateToken_FinishLoginError(t *testing.T) {
	mc := &mockUnifiedLoginClient{
		beginResp: &quicbaas.BeginLoginResponse{SessionID: "sess-9", ExpiresAt: time.Now().Add(time.Minute)},
		finishErr: errors.New("proof verification failed"),
	}
	handler, _ := newLoginHandler(t, mc)

	w := httptest.NewRecorder()
	handler.GenerateToken(w, loginRequest(t, "admin@example.com"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotNil(t, mc.finishReq)
}

// TestGenerateToken_EmptyBearer asserts that an authenticated ceremony
// that yields no bearer is treated as a failure rather than a success.
func TestGenerateToken_EmptyBearer(t *testing.T) {
	mc := &mockUnifiedLoginClient{
		beginResp:  &quicbaas.BeginLoginResponse{SessionID: "sess-1", ExpiresAt: time.Now().Add(time.Minute)},
		finishResp: newFinishLoginResponse("", time.Time{}, nil),
	}
	handler, _ := newLoginHandler(t, mc)

	w := httptest.NewRecorder()
	handler.GenerateToken(w, loginRequest(t, "admin@example.com"))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestGenerateToken_NoLoginClient asserts the endpoint fails closed when
// no unified login client is wired (no insecure local-JWT fallback).
func TestGenerateToken_NoLoginClient(t *testing.T) {
	handler, _ := newLoginHandler(t, nil)

	w := httptest.NewRecorder()
	handler.GenerateToken(w, loginRequest(t, "admin@example.com"))

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestGenerateToken_InvalidBody asserts malformed JSON is rejected before
// any login attempt.
func TestGenerateToken_InvalidBody(t *testing.T) {
	mc := &mockUnifiedLoginClient{}
	handler, _ := newLoginHandler(t, mc)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("not-json"))
	w := httptest.NewRecorder()
	handler.GenerateToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Nil(t, mc.beginReq, "BeginLogin must not run on a malformed body")
}
