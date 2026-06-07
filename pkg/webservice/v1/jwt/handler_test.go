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
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock UserService
type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Get(ctx context.Context, id uint64) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserService) Save(ctx context.Context, user *entities.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserService) Delete(ctx context.Context, id uint64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserService) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserService) GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.User), args.Error(1)
}

func (m *MockUserService) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

func TestNewRestHandler(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)
	assert.NotNil(t, handler)
}

func TestHandlerGenerateToken_NoLoginClientFailsClosed(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request with user credentials
	userCred := service.UserCredential{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, err := json.Marshal(userCred)
	assert.Nil(t, err)

	req := httptest.NewRequest("POST", "/token", bytes.NewBuffer(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).GenerateToken(w, req)

	// With no unified login client wired the /login endpoint must fail
	// closed: the locked architecture forbids minting an unverified JWT.
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp response.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.False(t, resp.Success)
}

func TestHandlerGenerateToken_InvalidJSON(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request with invalid JSON
	req := httptest.NewRequest("POST", "/token", bytes.NewBufferString("invalid json"))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).GenerateToken(w, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp response.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.False(t, resp.Success)
}

func TestHandlerRefreshToken_Success(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Create request with the token
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).RefreshToken(w, req)

	// Check response
	assert.Equal(t, http.StatusOK, w.Code)

	var resp response.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Payload)
}

func TestHandlerRefreshToken_MissingToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request without Authorization header
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).RefreshToken(w, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlerRefreshToken_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request with invalid token
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).RefreshToken(w, req)

	// Check response
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandlerRefreshToken_ExpiredToken tests the RefreshToken handler when the token
// parses successfully but is marked as invalid (expired token scenario).
// This covers the token.Valid check at handler.go:206-208.
func TestHandlerRefreshToken_ExpiredToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	// Create service with short expiration for testing expired tokens
	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create an expired token manually
	now := time.Now()
	expiredClaims := TokenClaims{
		UserID: 12345,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{params.Audience},
			Issuer:    params.Issuer,
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired 1 hour ago
			NotBefore: jwt.NewNumericDate(now.Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwtService.signingMethod, expiredClaims)
	tokenString, err := token.SignedString(jwtService.signer)
	assert.Nil(t, err)

	// Create request with the expired token
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	handler.(*RestHandler).RefreshToken(w, req)

	// The token should fail validation due to expiration
	// This triggers the error path in RefreshToken
	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestHandlerVerify_Success(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Create request with the token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Track if next handler was called
	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}

	// Call handler
	handler.(*RestHandler).Verify(w, req, next)

	// Check that next handler was called
	assert.True(t, nextCalled)
}

func TestHandlerVerify_MissingToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request without Authorization header
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Track if next handler was called
	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}

	// Call handler
	handler.(*RestHandler).Verify(w, req, next)

	// Check that next handler was NOT called
	assert.False(t, nextCalled)
}

func TestHandlerVerify_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request with invalid token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Track if next handler was called
	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}

	// Call handler
	handler.(*RestHandler).Verify(w, req, next)

	// Check that next handler was NOT called
	assert.False(t, nextCalled)
}

// TestHandlerVerify_VerificationFailure tests the Verify handler when the token
// parses correctly but fails verification (e.g., wrong audience).
// This covers the jwtService.Verify error path at handler.go:272-274.
func TestHandlerVerify_VerificationFailure(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	params.Audience = "correct-audience"

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create a token with different audience
	now := time.Now()
	wrongAudienceClaims := TokenClaims{
		UserID: 12345,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{"wrong-audience"}, // Different from service audience
			Issuer:    params.Issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwtService.signingMethod, wrongAudienceClaims)
	tokenString, err := token.SignedString(jwtService.signer)
	assert.Nil(t, err)

	// Create request with the wrong audience token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Track if next handler was called
	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}

	// Call handler
	handler.(*RestHandler).Verify(w, req, next)

	// Check that next handler was NOT called due to audience mismatch
	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateSession_Success(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return the user
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(user, nil)

	// Create request with the token
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, user, session.User())

	mockUserService.AssertExpectations(t)
}

func TestCreateSession_WithOrgID(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return the user
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(user, nil)

	// Create request with the token and org_id parameter
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Setup mux vars to simulate path parameters
	req = mux.SetURLVars(req, map[string]string{
		"organization_id": "999",
	})

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, uint64(999), session.RequestedOrganizationID())

	mockUserService.AssertExpectations(t)
}

func TestCreateSession_WithServiceID(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return the user
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(user, nil)

	// Create request with the token and service_id parameter
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Setup mux vars to simulate path parameters
	req = mux.SetURLVars(req, map[string]string{
		"service_id": "777",
	})

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, uint64(777), session.RequestedServiceID())

	mockUserService.AssertExpectations(t)
}

func TestCreateSession_InvalidOrgID(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Create request with the token and invalid org_id parameter
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Setup mux vars with invalid org_id
	req = mux.SetURLVars(req, map[string]string{
		"organization_id": "invalid",
	})

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Equal(t, ErrInvalidOrganiztionID, err)
	assert.Nil(t, session)
}

func TestCreateSession_UserServiceError(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return an error
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(nil, assert.AnError)

	// Create request with the token
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.NotNil(t, err)
	assert.Nil(t, session)

	mockUserService.AssertExpectations(t)
}

func TestCreateSession_MissingToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Create request without Authorization header
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Equal(t, ErrAuthorizationHeaderRequired, err)
	assert.Nil(t, session)
}

func TestCreateSession_ParseServiceIDError(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return the user
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(user, nil)

	// Create request with the token and invalid service_id parameter
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	// Setup mux vars with invalid service_id (should be ignored)
	req = mux.SetURLVars(req, map[string]string{
		"service_id": "not-a-number",
	})

	// Call handler - should succeed but service_id should be 0
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	// service_id parsing errors are ignored, so it should be 0
	assert.Equal(t, uint64(0), session.RequestedServiceID())

	mockUserService.AssertExpectations(t)
}

func TestTokenClaims_Organizations(t *testing.T) {
	claims := &TokenClaims{
		Organizations: []uint64{1, 2, 3},
		Services:      []uint64{4, 5},
		UserID:        12345,
	}

	assert.Equal(t, []uint64{1, 2, 3}, claims.Organizations)
	assert.Equal(t, []uint64{4, 5}, claims.Services)
	assert.Equal(t, uint64(12345), claims.UserID)
}

func TestErrInvalidOrganiztionID(t *testing.T) {
	err := ErrInvalidOrganiztionID
	assert.NotNil(t, err)
	assert.Equal(t, "rest/jwt: invalid organization id", err.Error())
}

func TestCreateSession_ParseUintEdgeCases(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(params)
	assert.Nil(t, err)

	logger := logging.DefaultLogger()
	responseWriter := response.NewResponseWriter(logger, nil)
	mockUserService := new(MockUserService)

	handler, err := NewRestHandler(logger, responseWriter, jwtService, mockUserService)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// Setup mock to return the user
	mockUserService.On("Get", mock.Anything, uint64(12345)).Return(user, nil)

	// Test with maximum uint64 value
	req := httptest.NewRequest("GET", "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	maxUint64 := strconv.FormatUint(^uint64(0), 10)
	req = mux.SetURLVars(req, map[string]string{
		"organization_id": maxUint64,
	})

	// Call handler
	session, err := handler.(*RestHandler).CreateSession(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, ^uint64(0), session.RequestedOrganizationID())

	mockUserService.AssertExpectations(t)
}
