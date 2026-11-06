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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	loginpkg "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login/logintest"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
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
	t.Parallel()
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
	t.Parallel()
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

	var resp restwire.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.False(t, resp.Success)
}

// TestHandlerGenerateToken_IgnoresTheRequestBody replaces the former
// invalid-JSON test, whose premise the unified ceremony removed.
//
// An mtls login has no credential IN the request: the certificate the peer
// presented during the handshake is the credential, and the backbone
// derives the lookup key from it. There is therefore nothing in the body
// to validate, and a body the caller made up must not influence the
// outcome. With no driver wired the route fails closed with 403, which is
// the same refusal it gives a well-formed body.
func TestHandlerGenerateToken_IgnoresTheRequestBody(t *testing.T) {
	t.Parallel()
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

	req := httptest.NewRequest("POST", "/token", bytes.NewBufferString("invalid json"))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	handler.(*RestHandler).GenerateToken(w, req)

	// Fail closed on the missing driver, not on the body.
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp restwire.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.False(t, resp.Success)
}

func TestHandlerRefreshToken_Success(t *testing.T) {
	t.Parallel()
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

	var resp restwire.WebServiceResponse
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Nil(t, err)
	assert.True(t, resp.Success)
	assert.NotNil(t, resp.Payload)
}

func TestHandlerRefreshToken_MissingToken(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
		UID: "12345",
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
	t.Parallel()
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

// TestHandlerVerify_VerificationFailure tests the Verify handler when the token
// parses correctly but fails verification (e.g., wrong audience).
// This covers the jwtService.Verify error path at handler.go:272-274.
func TestHandlerVerify_VerificationFailure(t *testing.T) {
	t.Parallel()
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
		UID: "12345",
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
	t.Parallel()
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

	// Generate a valid token for an id a float64 cannot hold exactly
	user := hostileUser(t)
	tokenString, err := jwtService.GenerateToken(user)
	assert.Nil(t, err)

	// The store must be asked for exactly the id that was issued
	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	assert.Nil(t, sessionFromClaims(nil))
}

// TestHandlerRefreshToken_PreservesTenantAndRoles is a lockout regression.
// GenerateToken derives tenant_id, email and roles from the user it is
// handed; refreshing from a bare {ID} stub returned a token with no roles
// and tenant "default". Harmless while nothing enforced those claims —
// but the IAM routes are now gated on the roles claim, so an admin would
// have been locked out of the console on their first refresh.
func TestHandlerRefreshToken_PreservesTenantAndRoles(t *testing.T) {
	t.Parallel()
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

	user := hostileUser(t)
	user.TenantID = "system"
	user.IsTenantOwner = true
	user.AddRole(&entities.Role{Name: "admin"})
	original, err := jwtService.GenerateToken(user)
	require.NoError(t, err)

	// The store is the authority the refresh reads back, keyed by exactly
	// the id that was issued.
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
	assert.Equal(t, user.Email, claims.Email)
	assert.True(t, claims.IsTenantOwner)
	refreshedID, err := claims.PlatformUserID()
	require.NoError(t, err)
	assert.Equal(t, user.ID, refreshedID, "the user id must survive a refresh")

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// backboneSessionRequest returns a request bearing a backbone-issued
// session whose subject is all digits: it parses as a uint64, so a reader
// that took the platform user id from "user_id" or "sub" would resolve
// whichever unrelated platform user holds that key.
func backboneSessionRequest(t *testing.T, handler *RestHandler, target string) *http.Request {
	t.Helper()
	bearer, _, err := handler.jwtService.IssueSession(&quicbaas.Identity{
		Subject: "5083343080743762020", TenantID: "tenant-a",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, target, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return req
}

func TestHandlerRefreshToken_RefusesABackboneSession(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	rec := httptest.NewRecorder()

	handler.RefreshToken(rec, backboneSessionRequest(t, handler, "/login/refresh"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	handler.userService.(*MockUserService).AssertNotCalled(t, "Get", mock.Anything, mock.Anything)
}

func TestCreateSession_RefusesABackboneSession(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	rec := httptest.NewRecorder()

	session, err := handler.CreateSession(rec, backboneSessionRequest(t, handler, "/session"))

	assert.ErrorIs(t, err, ErrInvalidUserClaim)
	assert.Nil(t, session)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	handler.userService.(*MockUserService).AssertNotCalled(t, "Get", mock.Anything, mock.Anything)
}

// stubLoginClient is a UnifiedLoginClient that returns a fixed bearer and
// a resolved identity, so a test can exercise what /login hands back
// without a live broker.
type stubLoginClient struct {
	bearer string

	// identity is the principal the ceremony resolved. Nil drives the
	// path where the backbone issued a bearer naming nobody.
	identity *logintest.Identity

	// beginCalls counts ceremonies opened, so a test can assert that a
	// declined factor never reached the backbone at all.
	beginCalls int
}

func (c *stubLoginClient) BeginLogin(
	_ context.Context, _ quicbaas.BeginLoginRequest) (*quicbaas.BeginLoginResponse, error) {
	c.beginCalls++
	return &quicbaas.BeginLoginResponse{SessionID: "session-1"}, nil
}

// FinishLogin builds the response through the shared logintest fixture,
// which exists because Bearer and Identity are promoted from an embedded
// *go-qrdb transport type the quicbaas SDK does not re-export — and naming
// go-qrdb here would fail the layer guard, which scans _test.go files too.
func (c *stubLoginClient) FinishLogin(
	_ context.Context, _ quicbaas.FinishLoginRequest) (*quicbaas.FinishLoginResponse, error) {

	return logintest.FinishResponse(
		c.bearer, "", time.Now().Add(time.Hour), time.Now().Add(24*time.Hour), c.identity)
}

// completeLogin runs a WebAuthn login to completion on the supplied driver
// and returns the bearer from the session it issued.
//
// It drives the fido2 factor rather than /login's mtls one because mtls
// deliberately declines until its certificate can be bound to the ceremony
// (login/mtls.go, jeremyhahn/go-quicbaas#857). What this helper exists to
// obtain is a credential from a COMPLETED ceremony, and fido2 is the factor
// that completes.
func completeLogin(t *testing.T, driver *loginpkg.Driver) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish",
		bytes.NewBufferString(`{"id":"Q1JFRC1JRA","type":"public-key","response":{}}`))
	req.Header.Set(loginpkg.SessionIDHeader, "sess-1")
	req.Header.Set("Accept", "application/json")

	w := httptest.NewRecorder()
	driver.Finish(w, req, quicbaas.FactorTypeFIDO2)
	require.Equal(t, http.StatusOK, w.Code, "login must succeed: %s", w.Body.String())

	var resp restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.True(t, resp.Success)

	session, ok := resp.Payload.(map[string]any)
	require.True(t, ok, "payload = %T, want the issued session", resp.Payload)
	bearer, ok := session["bearer"].(string)
	require.True(t, ok, "session carries no bearer: %v", session)
	require.NotEmpty(t, bearer)
	return bearer
}

// TestGenerateTokenDeclinesTheUnbindableMTLSFactor pins what /login now
// answers. mtls is the factor that route drives, and its binder declines
// until the caller's certificate can be bound to the ceremony — so the
// route reports the surface as closed (403) rather than opening a ceremony
// that a remote transport would resolve against PLATFORMD's certificate.
//
// 403 and not 401: the caller's certificate was never the problem.
func TestGenerateTokenDeclinesTheUnbindableMTLSFactor(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	client := &stubLoginClient{bearer: "broker.issued.bearer"}
	handler.SetLoginDriver(newLoginDriverForTest(t, client, handler.jwtService, nil))

	body, err := json.Marshal(service.UserCredential{Email: "admin@system", Password: "x"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	handler.GenerateToken(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	assert.Zero(t, client.beginCalls,
		"a declined factor must not open a ceremony on the backbone")
}

// TestLoginSessionIsAcceptedByTheDefaultProtectedRouteSeam is the
// end-to-end check issue #168 says did not exist, and the regression test
// for the blocking defect on #646: log in, then present the credential the
// login returned to the seam every JWT-protected route runs.
//
// It is the one property that makes a login a login. The ceremony now runs
// entirely on the unified backbone, but the backbone's OIDC bearer is
// signed by quicbaas's token service and the default seam
// (JWT.PlatformToken disabled) validates only tokens the PLATFORM's signer
// produced — so forwarding that bearer would leave every post-login call
// answering 401. The driver therefore mints the session from the identity
// the backbone resolved, through the same signer this seam verifies with.
//
// When the SDK grows a working inbound validator for the backbone bearer
// (#202, phases 3 and 4 of #644) the mint goes away and the backbone's
// bearer is forwarded — and this test is what proves the replacement is
// actually accepted before the mint is removed.
func TestLoginSessionIsAcceptedByTheDefaultProtectedRouteSeam(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	driver := newLoginDriverForTest(t, &stubLoginClient{
		bearer: "broker.issued.bearer",
		identity: &logintest.Identity{
			Subject:  "operator@platform",
			TenantID: "tenant-a",
			Roles:    []string{"admin"},
		},
	}, handler.jwtService, staticRoles{"owner"})
	handler.SetLoginDriver(driver)

	bearer := completeLogin(t, driver)
	require.NotEqual(t, "broker.issued.bearer", bearer,
		"the backbone bearer must not be what the client is handed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	reached := false
	handler.Verify(w, req, func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		session, ok := iammw.GetSessionFromContext(r.Context())
		require.True(t, ok, "the seam must publish the verified session")
		assert.Equal(t, "operator@platform", session.UserID(),
			"the session principal is the identity the backbone resolved")
		assert.Equal(t, "operator@platform", session.Email())
		// The ceremony ran in the operating tenant ("tenant-a"); the
		// session lands in the principal's own workspace (#662), with the
		// roles the principal holds THERE, not the operating tenant's.
		assert.Equal(t, "workspace-a", session.TenantID())
		assert.Equal(t, []string{"owner"}, session.Roles())
	})

	assert.True(t, reached,
		"a completed login must produce a credential the protected routes accept")
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestLoginWorkspaceSessionOfAnOperatingAdminIsRefusedByTheAdminGuard is the
// #662 regression: an admin of the operating tenant who is a plain member of
// their workspace must not carry "admin" into the workspace session, so the
// IAM router's admin guard refuses them there.
func TestLoginWorkspaceSessionOfAnOperatingAdminIsRefusedByTheAdminGuard(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	driver := newLoginDriverForTest(t, &stubLoginClient{
		bearer: "broker.issued.bearer",
		identity: &logintest.Identity{
			Subject:  "operator@platform",
			TenantID: "tenant-a",
			Roles:    []string{"admin"},
		},
	}, handler.jwtService, staticRoles{"member"})
	handler.SetLoginDriver(driver)

	bearer := completeLogin(t, driver)

	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	guard, err := iammw.NewSessionGuard(logger, response.NewResponseWriter(logger, nil))
	require.NoError(t, err)
	requireAdmin := guard.RequireRoles("admin")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	reachedAdmin := false
	var roles []string
	handler.Verify(w, req, func(w http.ResponseWriter, r *http.Request) {
		if session, ok := iammw.GetSessionFromContext(r.Context()); ok {
			roles = session.Roles()
		}
		requireAdmin(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reachedAdmin = true
		})).ServeHTTP(w, r)
	})

	assert.Equal(t, []string{"member"}, roles,
		"the workspace session carries the workspace roles only")
	assert.False(t, reachedAdmin,
		"an operating-tenant admin must not pass the admin guard in a workspace they only belong to")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestLoginRefusesWhenTheCeremonyNamesNobody is the negative half: the
// seam accepting the login credential must not mean it accepts one minted
// for an unresolved principal. A ceremony that returns a bearer without
// saying who it belongs to has authenticated nobody, and no credential may
// come out of it.
func TestLoginRefusesWhenTheCeremonyNamesNobody(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	driver := newLoginDriverForTest(t,
		&stubLoginClient{bearer: "broker.issued.bearer"}, handler.jwtService, nil)

	req := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish",
		bytes.NewBufferString(`{"id":"Q1JFRC1JRA","type":"public-key","response":{}}`))
	req.Header.Set(loginpkg.SessionIDHeader, "sess-1")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	driver.Finish(w, req, quicbaas.FactorTypeFIDO2)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a bearer with no identity authenticates nobody")
	assert.NotContains(t, w.Body.String(), "broker.issued.bearer",
		"and nothing resembling a credential may reach the client")
}

// TestPlatformMintedTokenIsAcceptedByTheDefaultProtectedRouteSeam is the
// positive control for the test above: the seam is not rejecting every
// token, it is rejecting the one /login returns. Without this the 401 above
// would prove nothing.
func TestPlatformMintedTokenIsAcceptedByTheDefaultProtectedRouteSeam(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

			var resp restwire.WebServiceResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.False(t, resp.Success)
			assert.NotEmpty(t, resp.Error, "the client must be told why")
		})
	}
}

// newLoginDriverForTest builds the mtls-only driver /login runs on, over
// the REAL jwt.Service as its session issuer, so the seam test exercises
// the whole path — ceremony, mint, verification — rather than a stand-in
// on either end of it.
// staticWorkspace resolves every principal to one workspace, standing in
// for the platform's tenant user service.
type staticWorkspace string

func (w staticWorkspace) Workspace(context.Context, string) (string, error) {
	return string(w), nil
}

func newLoginDriverForTest(
	t *testing.T, client loginpkg.UnifiedLoginClient, issuer loginpkg.SessionIssuer,
	roles loginpkg.RoleResolver) *loginpkg.Driver {

	t.Helper()
	logger := logging.NewLogger(slog.LevelError, os.Stderr)
	// Both factors: mtls is the one /login drives (and declines), fido2 the
	// one that completes, so a single driver serves the route test and the
	// end-to-end seam test without either needing its own fixture.
	fido2, err := loginpkg.NewFIDO2Binder("tenant-a", staticWorkspace("workspace-a"))
	require.NoError(t, err)
	driver, err := loginpkg.NewDriver(loginpkg.DriverParams{
		Client:         client,
		Binders:        []loginpkg.Binder{loginpkg.NewMTLSBinder(), fido2},
		SessionIssuer:  issuer,
		Roles:          roles,
		Logger:         logger,
		ResponseWriter: response.NewResponseWriter(logger, nil),
	})
	require.NoError(t, err)
	return driver
}

// staticRoles answers one role list for every principal in every tenant,
// standing in for the IAM-backed restiam.WorkspaceRoleResolver.
type staticRoles []string

func (r staticRoles) Roles(context.Context, string, string) ([]string, error) {
	return r, nil
}
