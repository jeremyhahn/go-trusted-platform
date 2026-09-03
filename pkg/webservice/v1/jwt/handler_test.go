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

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	// The refresh re-reads the user, so the store is the authority on the
	// claims the replacement token carries.
	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	// Create service with short expiration for testing expired tokens
	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

func TestCreateSession_WithServiceID(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

func TestCreateSession_UserServiceError(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	jwtService, err := NewService(context.Background(), params)
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

// TestHandlerVerify_PublishesSession proves the live verifier hands the
// RBAC route guards a session built from the SAME token it just verified.
// Without this, every guard mounted downstream would 401 unconditionally.
func TestHandlerVerify_PublishesSession(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		jwtService, new(MockUserService))
	require.NoError(t, err)

	user := entities.NewUser("admin")
	user.TenantID = "system"
	user.AddRole(&entities.Role{Name: "admin"})
	tokenString, err := jwtService.GenerateToken(user)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")

	var published iammw.IAMSession
	var ok bool
	handler.(*RestHandler).Verify(httptest.NewRecorder(), req,
		func(w http.ResponseWriter, r *http.Request) {
			published, ok = iammw.GetSessionFromContext(r.Context())
		})

	require.True(t, ok, "Verify must publish a session for the route guards")
	require.NotNil(t, published)
	assert.Equal(t, "system", published.TenantID())
	assert.Equal(t, "admin", published.Email())
	assert.True(t, published.HasRole("admin"))
	assert.False(t, published.HasRole("so"))
}

// TestHandlerVerify_PublishesNoRolesForAnUnprivilegedToken is the negative
// half: a token with no roles claim must not satisfy a role guard.
func TestHandlerVerify_PublishesNoRolesForAnUnprivilegedToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		jwtService, new(MockUserService))
	require.NoError(t, err)

	tokenString, err := jwtService.GenerateToken(entities.NewUser("nobody@localhost"))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")

	var published iammw.IAMSession
	handler.(*RestHandler).Verify(httptest.NewRecorder(), req,
		func(w http.ResponseWriter, r *http.Request) {
			published, _ = iammw.GetSessionFromContext(r.Context())
		})

	require.NotNil(t, published)
	assert.Empty(t, published.Roles())
	assert.False(t, published.HasRole("admin"))
}

func TestSessionFromClaims_NilClaims(t *testing.T) {
	assert.Nil(t, sessionFromClaims(nil))
}

// TestHandlerRefreshToken_PreservesTenantAndRoles is a lockout regression.
// GenerateToken derives tenant_id, email and roles from the user it is
// handed; refreshing from a bare {ID} stub returned a token with no roles
// and tenant "default". Harmless while nothing enforced those claims —
// but the IAM routes are now gated on the roles claim, so an admin would
// have been locked out of the console on their first refresh.
func TestHandlerRefreshToken_PreservesTenantAndRoles(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	users := new(MockUserService)
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		jwtService, users)
	require.NoError(t, err)

	user := entities.NewUser("admin")
	user.TenantID = "system"
	user.IsTenantOwner = true
	user.AddRole(&entities.Role{Name: "admin"})
	original, err := jwtService.GenerateToken(user)
	require.NoError(t, err)

	// The store is the authority the refresh reads back.
	users.On("Get", mock.Anything, user.ID).Return(user, nil)

	req := httptest.NewRequest("POST", "/login/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+original)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.(*RestHandler).RefreshToken(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Read the refreshed token back out of the response envelope and
	// verify the claims a route guard would act on survived.
	var env struct {
		Payload string `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	require.NotEmpty(t, env.Payload)

	refreshed, err := jwtService.ParseTokenString(env.Payload)
	require.NoError(t, err)
	claims, ok := refreshed.Claims.(*TokenClaims)
	require.True(t, ok)

	assert.Equal(t, "system", claims.TenantID, "tenant must survive a refresh")
	assert.Equal(t, []string{"admin"}, claims.Roles, "roles must survive a refresh")
	assert.Equal(t, "admin", claims.Email)
	assert.True(t, claims.IsTenantOwner)

	// And the refreshed token still satisfies a role guard.
	session := sessionFromClaims(claims)
	require.NotNil(t, session)
	assert.True(t, session.HasRole("admin"))
}

// TestHandlerRefreshToken_PicksUpARevocation is the other half of the
// refresh contract. Minting from the presented token's claims would let
// someone whose admin role was revoked roll it forward indefinitely by
// refreshing before each expiry; minting from the store means the refresh
// observes the revocation.
func TestHandlerRefreshToken_PicksUpARevocation(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	users := new(MockUserService)
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		jwtService, users)
	require.NoError(t, err)

	// The caller holds a token minted while they were an admin.
	wasAdmin := entities.NewUser("admin")
	wasAdmin.TenantID = "system"
	wasAdmin.AddRole(&entities.Role{Name: "admin"})
	original, err := jwtService.GenerateToken(wasAdmin)
	require.NoError(t, err)

	// The role has since been revoked in the store.
	revoked := entities.NewUser("admin")
	revoked.TenantID = "system"
	users.On("Get", mock.Anything, wasAdmin.ID).Return(revoked, nil)

	req := httptest.NewRequest("POST", "/login/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+original)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.(*RestHandler).RefreshToken(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var env struct {
		Payload string `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
	refreshed, err := jwtService.ParseTokenString(env.Payload)
	require.NoError(t, err)
	claims, ok := refreshed.Claims.(*TokenClaims)
	require.True(t, ok)

	assert.Empty(t, claims.Roles, "a revoked role must not survive a refresh")
	assert.False(t, sessionFromClaims(claims).HasRole("admin"))
}

// TestHandlerRefreshToken_FailsClosedWhenTheUserIsGone: a token for a
// deleted user must not be renewable.
func TestHandlerRefreshToken_FailsClosedWhenTheUserIsGone(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	users := new(MockUserService)
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		jwtService, users)
	require.NoError(t, err)

	user := entities.NewUser("gone@localhost")
	tokenString, err := jwtService.GenerateToken(user)
	require.NoError(t, err)

	users.On("Get", mock.Anything, user.ID).
		Return((*entities.User)(nil), errors.New("no such user"))

	req := httptest.NewRequest("POST", "/login/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.(*RestHandler).RefreshToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandlerRefreshToken_RejectsAWrongAudienceToken closes a laundering
// path: /login/refresh checked only the signature, so a token this signer
// produced for a DIFFERENT audience — one every protected route rejects
// via jwtService.Verify — could be exchanged here for a fresh,
// correctly-audienced platform token.
func TestHandlerRefreshToken_RejectsAWrongAudienceToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	// Two services over the SAME signer and key, differing only in the
	// audience they mint and accept.
	foreign := params
	foreign.Audience = "some-other-audience"
	foreignService, err := NewService(context.Background(), foreign)
	require.NoError(t, err)

	local := params
	local.Audience = "this-platform"
	localService, err := NewService(context.Background(), local)
	require.NoError(t, err)

	user := entities.NewUser("admin")
	user.TenantID = "system"
	user.AddRole(&entities.Role{Name: "admin"})

	// Signed by the same key, but for the wrong audience.
	foreignToken, err := foreignService.GenerateToken(user)
	require.NoError(t, err)

	// Sanity: a protected route would reject it.
	parsed, err := localService.ParseTokenString(foreignToken)
	require.NoError(t, err)
	require.Error(t, localService.Verify(parsed),
		"precondition: the local service must reject this audience")

	logger := logging.DefaultLogger()
	users := new(MockUserService)
	users.On("Get", mock.Anything, user.ID).Return(user, nil)
	handler, err := NewRestHandler(logger, response.NewResponseWriter(logger, nil),
		localService, users)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/login/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+foreignToken)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.(*RestHandler).RefreshToken(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"refresh must not launder a token the protected routes reject")
}

// stubLoginClient is a UnifiedLoginClient that returns a fixed bearer, so a
// test can exercise what /login hands back without a live broker.
type stubLoginClient struct {
	bearer string
}

func (c *stubLoginClient) BeginLogin(
	_ context.Context, _ quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error) {
	return &quicbaas.BeginLoginResponse{SessionID: "session-1"}, nil
}

// FinishLogin builds the response through JSON rather than a composite
// literal. Bearer is promoted from an embedded *go-qrdb transport type that
// the quicbaas SDK does not re-export, and naming go-qrdb here would fail
// the layer guard — pkg/arch/layerguard_test.go scans _test.go files too.
// Unmarshalling allocates the embedded struct and sets the field without
// the platform naming the upstream package.
func (c *stubLoginClient) FinishLogin(
	_ context.Context, _ quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error) {

	resp := &quicbaas.FinishLoginResponse{}
	encoded, err := json.Marshal(map[string]string{"bearer": c.bearer})
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(encoded, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// login drives POST /login and returns the bearer in the response envelope.
func login(t *testing.T, handler *RestHandler) string {
	t.Helper()

	body, err := json.Marshal(service.UserCredential{Email: "admin@system", Password: "x"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	handler.GenerateToken(w, req)
	require.Equal(t, http.StatusOK, w.Code, "login must succeed")

	var resp response.WebServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Success)

	bearer, ok := resp.Payload.(string)
	require.True(t, ok, "payload = %T, want the bearer string", resp.Payload)
	require.NotEmpty(t, bearer)
	return bearer
}

// TestLoginBearerIsRejectedByTheDefaultProtectedRouteSeam is the end-to-end
// check issue #168 says did not exist: log in, then present the returned
// token to the seam every JWT-protected route runs.
//
// It asserts the CURRENT, defective behaviour deliberately. /login returns
// the quicbaas broker bearer while the default seam (JWT.PlatformToken
// disabled) validates only platform-local JWTs, so a successful login
// yields a token the same server rejects. That is a fail-CLOSED mismatch —
// nothing is admitted that should not be — and it is pre-existing on main:
// this branch changes neither GenerateToken nor the seam selection.
//
// Owner ruling 2026-09-02 (#202) converges the two token types by retiring
// the local issuer, which closes #168 and #166. When that lands this test
// flips to asserting 200, and it will fail loudly until someone does so —
// which is the point of pinning it here rather than leaving the gap
// untested.
func TestLoginBearerIsRejectedByTheDefaultProtectedRouteSeam(t *testing.T) {
	handler := newHandlerForLoginTest(t)
	handler.SetUnifiedLoginClient(&stubLoginClient{bearer: "broker.issued.bearer"})

	bearer := login(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	reached := false
	handler.Verify(w, req, func(http.ResponseWriter, *http.Request) { reached = true })

	assert.False(t, reached, "the broker bearer must not reach a protected handler")
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"the default seam validates platform-local JWTs only (#168, closed by #202)")
}

// TestPlatformMintedTokenIsAcceptedByTheDefaultProtectedRouteSeam is the
// positive control for the test above: the seam is not rejecting every
// token, it is rejecting the one /login returns. Without this the 401 above
// would prove nothing.
func TestPlatformMintedTokenIsAcceptedByTheDefaultProtectedRouteSeam(t *testing.T) {
	handler := newHandlerForLoginTest(t)

	minted, err := handler.jwtService.GenerateToken(&entities.User{
		ID:    1,
		Email: "admin@system",
		Roles: []*entities.Role{{Name: "admin"}},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
	req.Header.Set("Authorization", "Bearer "+minted)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	reached := false
	handler.Verify(w, req, func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		session, ok := iammw.GetSessionFromContext(r.Context())
		require.True(t, ok, "the seam must publish the verified session")
		assert.Equal(t, "admin@system", session.Email())
	})

	assert.True(t, reached, "a platform-minted token must reach the protected handler")
}

// newHandlerForLoginTest builds a RestHandler over a real jwt.Service and
// signing key, which is what makes the two tests above a like-for-like
// comparison of the same seam.
func newHandlerForLoginTest(t *testing.T) *RestHandler {
	t.Helper()

	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	jwtService, err := NewService(context.Background(), params)
	require.NoError(t, err)

	logger := logging.DefaultLogger()
	handler, err := NewRestHandler(
		logger, response.NewResponseWriter(logger, nil), jwtService, new(MockUserService))
	require.NoError(t, err)
	return handler.(*RestHandler)
}

// TestHandlerVerify_UnauthenticatedRequestIsToldSo pins the status, not
// just that the protected handler was skipped. Verify used to return
// silently when ParseToken failed — on the false assumption that ParseToken
// had written the response — so a request with no credential, or one this
// signer did not produce, received an empty 200 OK. Access was never
// granted, but every client was told the opposite of what happened.
func TestHandlerVerify_UnauthenticatedRequestIsToldSo(t *testing.T) {
	handler := newHandlerForLoginTest(t)

	for name, authorization := range map[string]string{
		"no credential":  "",
		"foreign token":  "Bearer not.a.platform.jwt",
		"bare scheme":    "Bearer ",
		"wrong scheme":   "Basic dXNlcjpwYXNz",
		"unsigned token": "Bearer eyJhbGciOiJub25lIn0.e30.",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
			if authorization != "" {
				req.Header.Set("Authorization", authorization)
			}
			req.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()

			reached := false
			handler.Verify(w, req, func(http.ResponseWriter, *http.Request) { reached = true })

			assert.False(t, reached, "the protected handler must not run")
			assert.Equal(t, http.StatusUnauthorized, w.Code)

			var resp response.WebServiceResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.False(t, resp.Success)
			assert.NotEmpty(t, resp.Error, "the client must be told why")
		})
	}
}
