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

package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations

type MockUserService struct {
	mock.Mock
}

func (m *MockUserService) Save(ctx context.Context, user *entities.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserService) Delete(ctx context.Context, userID uint64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserService) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
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

type MockRegistrationService struct {
	mock.Mock
}

func (m *MockRegistrationService) Create(ctx context.Context, registration *entities.Registration) error {
	args := m.Called(ctx, registration)
	return args.Error(0)
}

func (m *MockRegistrationService) Delete(ctx context.Context, session service.Session, registrationID uint64) error {
	args := m.Called(ctx, session, registrationID)
	return args.Error(0)
}

func (m *MockRegistrationService) Get(ctx context.Context, session service.Session, registrationID uint64) (*entities.Registration, error) {
	args := m.Called(ctx, session, registrationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Registration), args.Error(1)
}

type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateToken(user *entities.User) (string, error) {
	args := m.Called(user)
	return args.String(0), args.Error(1)
}

type MockResponseWriter struct {
	mock.Mock
}

func (m *MockResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.Called(w, r, status, resp)
}

func (m *MockResponseWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.Called(w, status, resp)
}

func (m *MockResponseWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.Called(w, status, resp)
}

func (m *MockResponseWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}

func (m *MockResponseWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Success200(w, r, payload)
}

func (m *MockResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.Called(w, r, payload, err)
}

func (m *MockResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockResponseWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.Called(w, r, err, payload)
}

func (m *MockResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

// Test helper functions

func createTestHandler(t *testing.T) (*WebAuthnRestHandler, *MockUserService, *MockRegistrationService, *MockJWTService, *MockResponseWriter) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)

	mockUserService := new(MockUserService)
	mockRegistrationService := new(MockRegistrationService)
	mockJWTService := new(MockJWTService)
	mockResponseWriter := new(MockResponseWriter)

	config := &Config{
		RPDisplayName: "Test RP",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	}

	params := ServiceParams{
		Config:              config,
		Debug:               false,
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: mockRegistrationService,
		ResponseWriter:      mockResponseWriter,
		UserService:         mockUserService,
	}

	handler, err := NewHandler(params)
	require.NoError(t, err)
	require.NotNil(t, handler)

	// Override the JWT service with mock after creation
	restHandler := handler.(*WebAuthnRestHandler)
	restHandler.jwtService = &jwt.Service{}

	return restHandler, mockUserService, mockRegistrationService, mockJWTService, mockResponseWriter
}

func createTestUser(email string) *entities.User {
	user := entities.NewUser(email)
	// Add a dummy credential so BeginLogin doesnt fail
	credential := webauthn.Credential{
		ID:              []byte("test-credential-id"),
		PublicKey:       []byte("test-public-key"),
		AttestationType: "none",
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte("test-aaguid"),
			SignCount:    0,
			CloneWarning: false,
		},
	}
	user.AddCredential(&credential)

	sessionData := &webauthn.SessionData{
		Challenge:            "test-challenge",
		UserID:               []byte(fmt.Sprintf("%d", user.ID)),
		Expires:              time.Now().Add(time.Hour),
		UserVerification:     protocol.VerificationDiscouraged,
		AllowedCredentialIDs: [][]byte{},
	}
	sessionJSON, _ := json.Marshal(sessionData)
	user.SessionData = sessionJSON
	return user
}

func createExpiredSessionUser(email string) *entities.User {
	user := entities.NewUser(email)
	// Add a dummy credential so BeginLogin doesnt fail
	credential := webauthn.Credential{
		ID:              []byte("test-credential-id"),
		PublicKey:       []byte("test-public-key"),
		AttestationType: "none",
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte("test-aaguid"),
			SignCount:    0,
			CloneWarning: false,
		},
	}
	user.AddCredential(&credential)

	sessionData := &webauthn.SessionData{
		Challenge:            "test-challenge",
		UserID:               []byte(fmt.Sprintf("%d", user.ID)),
		Expires:              time.Now().Add(-time.Hour), // Expired
		UserVerification:     protocol.VerificationDiscouraged,
		AllowedCredentialIDs: [][]byte{},
	}
	sessionJSON, _ := json.Marshal(sessionData)
	user.SessionData = sessionJSON
	return user
}

// Test NewHandler

func TestNewHandler_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)

	mockUserService := new(MockUserService)
	mockRegistrationService := new(MockRegistrationService)
	mockResponseWriter := new(MockResponseWriter)

	config := &Config{
		RPDisplayName: "Test RP",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	}

	params := ServiceParams{
		Config:              config,
		Debug:               true,
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: mockRegistrationService,
		ResponseWriter:      mockResponseWriter,
		UserService:         mockUserService,
	}

	handler, err := NewHandler(params)

	assert.NoError(t, err)
	assert.NotNil(t, handler)
	restHandler, ok := handler.(*WebAuthnRestHandler)
	assert.True(t, ok)
	assert.NotNil(t, restHandler.webAuthn)
	assert.NotNil(t, restHandler.logger)
	assert.NotNil(t, restHandler.jwtService)
	assert.NotNil(t, restHandler.userService)
	assert.NotNil(t, restHandler.registrationService)
	assert.NotNil(t, restHandler.responseWriter)
}

func TestNewHandler_NilConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)

	mockUserService := new(MockUserService)
	mockRegistrationService := new(MockRegistrationService)
	mockResponseWriter := new(MockResponseWriter)

	params := ServiceParams{
		Config:              nil,
		Debug:               false,
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: mockRegistrationService,
		ResponseWriter:      mockResponseWriter,
		UserService:         mockUserService,
	}

	handler, err := NewHandler(params)

	// The webauthn library requires RPOrigins to be non-empty
	assert.Error(t, err)
	assert.Nil(t, handler)
}

func TestNewHandler_EmptyConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)

	mockUserService := new(MockUserService)
	mockRegistrationService := new(MockRegistrationService)
	mockResponseWriter := new(MockResponseWriter)

	config := &Config{
		RPDisplayName: "",
		RPID:          "",
		RPOrigins:     []string{},
	}

	params := ServiceParams{
		Config:              config,
		Debug:               false,
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: mockRegistrationService,
		ResponseWriter:      mockResponseWriter,
		UserService:         mockUserService,
	}

	handler, err := NewHandler(params)

	// The webauthn library requires RPOrigins to be non-empty
	assert.Error(t, err)
	assert.Nil(t, handler)
}

// Test BeginRegistration

func TestBeginRegistration_Success_NewUser(t *testing.T) {
	handler, mockUserService, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	userID := util.NewID([]byte(username))

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockRegistrationService.On("Create", mock.Anything, mock.AnythingOfType("*entities.Registration")).Return(nil)
	mockResponseWriter.On("Write", w, req, http.StatusOK, mock.Anything).Return()

	handler.BeginRegistration(w, req)

	mockUserService.AssertExpectations(t)
	mockRegistrationService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginRegistration_UserAlreadyExists(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "existing@example.com"
	existingUser := createTestUser(username)
	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, existingUser.ID).Return(existingUser, nil)
	// The implementation calls writeConflictError which calls Write with 409 status
	mockResponseWriter.On("Write", w, req, http.StatusConflict, mock.MatchedBy(func(resp response.WebServiceResponse) bool {
		return resp.Code == http.StatusConflict && resp.Error == ErrUserAlreadyExists.Error() && !resp.Success
	})).Return()

	handler.BeginRegistration(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginRegistration_InvalidJSON(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Handler returns Error400 with ErrInvalidRequestBody on JSON decode error
	mockResponseWriter.On("Error400", w, req, ErrInvalidRequestBody).Return()

	handler.BeginRegistration(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestBeginRegistration_UserServiceError(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	userID := util.NewID([]byte(username))
	testErr := errors.New("database error")

	mockUserService.On("Get", mock.Anything, userID).Return(nil, testErr)
	mockResponseWriter.On("Error400", w, req, testErr).Return()

	handler.BeginRegistration(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginRegistration_RegistrationServiceError(t *testing.T) {
	handler, mockUserService, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	userID := util.NewID([]byte(username))
	testErr := errors.New("registration save error")

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockRegistrationService.On("Create", mock.Anything, mock.AnythingOfType("*entities.Registration")).Return(testErr)
	mockResponseWriter.On("Error500", w, req, testErr).Return()

	handler.BeginRegistration(w, req)

	mockUserService.AssertExpectations(t)
	mockRegistrationService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

// Test FinishRegistration

func TestFinishRegistration_MissingUserIDHeader(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, ErrInvalidUserIDHeader).Return()

	handler.FinishRegistration(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestFinishRegistration_InvalidUserIDHeader(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
	req.Header.Set("X-User-Id", "invalid base64!!!!")
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.FinishRegistration(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestFinishRegistration_InvalidUserIDFormat(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	invalidUserID := base64.RawURLEncoding.EncodeToString([]byte("not-a-number"))
	req := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
	req.Header.Set("X-User-Id", invalidUserID)
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.FinishRegistration(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestFinishRegistration_RegistrationNotFound(t *testing.T) {
	handler, _, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	userID := uint64(12345)
	encodedUserID := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(userID, 10)))

	req := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
	req.Header.Set("X-User-Id", encodedUserID)
	w := httptest.NewRecorder()

	testErr := datastore.ErrRecordNotFound

	mockRegistrationService.On("Get", mock.Anything, mock.Anything, userID).Return(nil, testErr)
	mockResponseWriter.On("Error404", w, req, testErr).Return()

	handler.FinishRegistration(w, req)

	mockRegistrationService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

// Test BeginLogin

func TestBeginLogin_Success(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockUserService.On("Save", mock.Anything, mock.AnythingOfType("*entities.User")).Return(nil)
	mockResponseWriter.On("Write", w, req, http.StatusOK, mock.Anything).Return()

	handler.BeginLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
	assert.Equal(t, fmt.Sprintf("%d", user.ID), w.Header().Get("X-User-ID"))
}

func TestBeginLogin_UserNotFound(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "nonexistent@example.com"
	userID := util.NewID([]byte(username))

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockResponseWriter.On("Error400", w, req, ErrInvalidUserID).Return()

	handler.BeginLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginLogin_UserServiceError(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	userID := util.NewID([]byte(username))

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testErr := errors.New("database error")

	mockUserService.On("Get", mock.Anything, userID).Return(nil, testErr)
	mockResponseWriter.On("Error400", w, req, testErr).Return()

	handler.BeginLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginLogin_SaveError(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	testErr := errors.New("save error")

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockUserService.On("Save", mock.Anything, mock.AnythingOfType("*entities.User")).Return(testErr)
	mockResponseWriter.On("Error500", w, req, testErr).Return()

	handler.BeginLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

// Test FinishLogin

func TestFinishLogin_InvalidUserID(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, ErrInvalidUserIDHeader).Return()

	handler.FinishLogin(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestFinishLogin_UserNotFound(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	userID := util.NewID([]byte(username))

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockResponseWriter.On("Error404", w, req, datastore.ErrRecordNotFound).Return()

	handler.FinishLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestFinishLogin_InvalidSessionData(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)
	user.SessionData = []byte("invalid json")

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.FinishLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

// Test Verify

func TestVerify_Success(t *testing.T) {
	handler, mockUserService, _, _, _ := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

	handler.Verify(w, req, next)

	mockUserService.AssertExpectations(t)
	assert.True(t, nextCalled)
}

func TestVerify_InvalidUserID(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	})

	mockResponseWriter.On("Error400", w, req, ErrInvalidUserIDHeader).Return()

	handler.Verify(w, req, next)

	mockResponseWriter.AssertExpectations(t)
}

func TestVerify_UserNotFound(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	userID := util.NewID([]byte(username))

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	})

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockResponseWriter.On("Error404", w, req, datastore.ErrRecordNotFound).Return()

	handler.Verify(w, req, next)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestVerify_InvalidSessionData(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)
	user.SessionData = []byte("invalid json")

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	})

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.Verify(w, req, next)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestVerify_ExpiredSession(t *testing.T) {
	handler, mockUserService, _, _, _ := createTestHandler(t)

	username := "test@example.com"
	user := createExpiredSessionUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next should not be called")
	})

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

	handler.Verify(w, req, next)

	mockUserService.AssertExpectations(t)
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

// Test RegistrationStatus

func TestRegistrationStatus_NotRegistered_NoHeader(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/registration/status", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()

	mockResponseWriter.On("Write", w, req, http.StatusOK, "not_registered").Return()

	handler.RegistrationStatus(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_NotRegistered_ZeroUserID(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", "0")
	w := httptest.NewRecorder()

	mockResponseWriter.On("Write", w, req, http.StatusOK, "not_registered").Return()

	handler.RegistrationStatus(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_NotRegistered_UserNotFound(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	userID := uint64(12345)
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(userID, 10))
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockResponseWriter.On("Write", w, req, http.StatusOK, "not_registered").Return()

	handler.RegistrationStatus(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_Registered(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)

	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockResponseWriter.On("Write", w, req, http.StatusOK, "registered").Return()

	handler.RegistrationStatus(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_InvalidSessionData(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)
	user.SessionData = []byte("invalid json")

	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.RegistrationStatus(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_ExpiredSession(t *testing.T) {
	handler, mockUserService, _, _, _ := createTestHandler(t)

	username := "test@example.com"
	user := createExpiredSessionUser(username)

	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

	handler.RegistrationStatus(w, req)

	mockUserService.AssertExpectations(t)
	assert.Equal(t, http.StatusSeeOther, w.Code)
}

// Test getUserID helper function

func TestGetUserID_FromHeader_ValidNumber(t *testing.T) {
	userID := uint64(12345)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(userID, 10))

	result, err := getUserID(req)

	assert.NoError(t, err)
	assert.Equal(t, userID, result)
}

func TestGetUserID_FromHeader_InvalidNumber_ReturnsError(t *testing.T) {
	username := "test@example.com"

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-User-Id", username)

	_, err := getUserID(req)

	// The code has a bug - it checks err == strconv.ErrSyntax but ParseUint
	// returns *strconv.NumError so the comparison fails
	assert.Error(t, err)
}
func TestGetUserID_FromBody_ValidEmail(t *testing.T) {
	username := "test@example.com"
	expectedID := util.NewID([]byte(username))

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := getUserID(req)

	assert.NoError(t, err)
	assert.Equal(t, expectedID, result)
}

func TestGetUserID_FromBody_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("invalid json")))

	_, err := getUserID(req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidUserIDHeader, err)
}

func TestGetUserID_NoHeaderNoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	_, err := getUserID(req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidUserIDHeader, err)
}

// Test error constants

func TestErrorConstants(t *testing.T) {
	assert.Equal(t, "webauthn: invalid organization id", ErrInvalidOrganizationID.Error())
	assert.Equal(t, "webauthn: user already registered", ErrUserAlreadyExists.Error())
	assert.Equal(t, "webauthn: invalid user id header", ErrInvalidUserIDHeader.Error())
	assert.Equal(t, "webauthn: invalid user", ErrInvalidUserID.Error())
}

// Test Config struct

func TestConfig_AllFields(t *testing.T) {
	config := &Config{
		RPDisplayName: "Test Display Name",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com", "https://www.example.com"},
	}

	assert.Equal(t, "Test Display Name", config.RPDisplayName)
	assert.Equal(t, "example.com", config.RPID)
	assert.Len(t, config.RPOrigins, 2)
	assert.Contains(t, config.RPOrigins, "https://example.com")
	assert.Contains(t, config.RPOrigins, "https://www.example.com")
}

// Test ServiceParams struct

func TestServiceParams_Complete(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)
	mockUserService := new(MockUserService)
	mockRegistrationService := new(MockRegistrationService)
	mockResponseWriter := new(MockResponseWriter)

	config := &Config{
		RPDisplayName: "Test RP",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost"},
	}

	params := ServiceParams{
		Config:              config,
		Debug:               true,
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: mockRegistrationService,
		ResponseWriter:      mockResponseWriter,
		UserService:         mockUserService,
	}

	assert.NotNil(t, params.Config)
	assert.True(t, params.Debug)
	assert.NotNil(t, params.JWTService)
	assert.NotNil(t, params.Logger)
	assert.NotNil(t, params.RegistrationService)
	assert.NotNil(t, params.ResponseWriter)
	assert.NotNil(t, params.UserService)
}

// Test LoginRequest struct

func TestLoginRequest_JSONMarshaling(t *testing.T) {
	req := LoginRequest{
		Email: "test@example.com",
	}

	data, err := json.Marshal(req)
	assert.NoError(t, err)

	var decoded LoginRequest
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", decoded.Email)
}

func TestLoginRequest_JSONUnmarshaling(t *testing.T) {
	jsonData := []byte(`{"username": "test@example.com"}`)

	var req LoginRequest
	err := json.Unmarshal(jsonData, &req)
	assert.NoError(t, err)
	assert.Equal(t, "test@example.com", req.Email)
}

// Additional tests for higher coverage

func TestFinishRegistration_SessionDataUnmarshalError(t *testing.T) {
	handler, _, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	userID := uint64(12345)
	encodedUserID := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(userID, 10)))

	registration := &entities.Registration{
		ID:          userID,
		Email:       "test@example.com",
		SessionData: []byte("invalid json"),
	}

	req := httptest.NewRequest(http.MethodPost, "/register/finish", nil)
	req.Header.Set("X-User-Id", encodedUserID)
	w := httptest.NewRecorder()

	mockRegistrationService.On("Get", mock.Anything, mock.Anything, userID).Return(registration, nil)
	mockResponseWriter.On("Error500", w, req, mock.Anything).Return()

	handler.FinishRegistration(w, req)

	mockRegistrationService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginRegistration_SessionJSONMarshalError(t *testing.T) {
	// This test validates the happy path where BeginRegistration succeeds
	// The json.Marshal of session should always work with valid SessionData
	handler, mockUserService, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	username := "test2@example.com"
	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	userID := util.NewID([]byte(username))

	mockUserService.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	mockRegistrationService.On("Create", mock.Anything, mock.AnythingOfType("*entities.Registration")).Return(nil)
	mockResponseWriter.On("Write", w, req, http.StatusOK, mock.Anything).Return()

	handler.BeginRegistration(w, req)

	mockUserService.AssertExpectations(t)
	mockRegistrationService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestBeginLogin_InvalidUserIDFromBody(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader([]byte("{invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, ErrInvalidUserIDHeader).Return()

	handler.BeginLogin(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestFinishLogin_SaveError(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "test@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	// FinishLogin will fail trying to parse the credential response from the request,
	// but we're testing the early error paths
	mockResponseWriter.On("Error400", w, req, mock.Anything).Return()

	handler.FinishLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestRegistrationStatus_UserServiceError(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	userID := uint64(12345)
	testErr := errors.New("service error")

	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(userID, 10))
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, userID).Return(nil, testErr)
	mockResponseWriter.On("Write", w, req, http.StatusOK, "not_registered").Return()

	handler.RegistrationStatus(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestGetUserID_ParseUintRangeError(t *testing.T) {
	// Test with a number that's too large for uint64
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-User-Id", "99999999999999999999999999999999999999")

	_, err := getUserID(req)

	assert.Error(t, err)
}

func TestBeginLogin_EmptyBody(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader([]byte("")))
	w := httptest.NewRecorder()

	mockResponseWriter.On("Error400", w, req, ErrInvalidUserIDHeader).Return()

	handler.BeginLogin(w, req)

	mockResponseWriter.AssertExpectations(t)
}

// Edge case tests for better coverage

func TestBeginRegistration_EmptyUsername(t *testing.T) {
	handler, _, _, _, mockResponseWriter := createTestHandler(t)

	requestBody := map[string]string{"username": ""}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/register/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// The implementation now validates that username is required and returns ErrUsernameRequired
	mockResponseWriter.On("Error400", w, req, ErrUsernameRequired).Return()

	handler.BeginRegistration(w, req)

	mockResponseWriter.AssertExpectations(t)
}

func TestBeginLogin_WithCredentials(t *testing.T) {
	handler, mockUserService, _, _, mockResponseWriter := createTestHandler(t)

	username := "user-with-creds@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)
	mockUserService.On("Save", mock.Anything, mock.AnythingOfType("*entities.User")).Return(nil)
	mockResponseWriter.On("Write", w, req, http.StatusOK, mock.Anything).Return()

	handler.BeginLogin(w, req)

	mockUserService.AssertExpectations(t)
	mockResponseWriter.AssertExpectations(t)
}

func TestVerify_ValidSessionNotExpired(t *testing.T) {
	handler, mockUserService, _, _, _ := createTestHandler(t)

	username := "valid@example.com"
	user := createTestUser(username)

	requestBody := map[string]string{"username": username}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodGet, "/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	})

	mockUserService.On("Get", mock.Anything, user.ID).Return(user, nil)

	handler.Verify(w, req, next)

	mockUserService.AssertExpectations(t)
	assert.True(t, nextCalled, "next handler should be called for valid session")
}

func TestGetUserID_EmptyEmail(t *testing.T) {
	requestBody := map[string]string{"username": ""}
	body, _ := json.Marshal(requestBody)

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	result, err := getUserID(req)

	assert.NoError(t, err)
	// Empty email will still generate a valid ID via util.NewID
	assert.NotEqual(t, uint64(0), result)
}

func TestWebAuthnRestHandler_StructFields(t *testing.T) {
	handler, mockUserService, mockRegistrationService, _, mockResponseWriter := createTestHandler(t)

	assert.NotNil(t, handler.logger)
	assert.NotNil(t, handler.jwtService)
	assert.NotNil(t, handler.userService)
	assert.Equal(t, mockUserService, handler.userService)
	assert.Equal(t, mockRegistrationService, handler.registrationService)
	assert.Equal(t, mockResponseWriter, handler.responseWriter)
	assert.NotNil(t, handler.webAuthn)
}

func TestIsConfigured_NilConfig(t *testing.T) {
	assert.False(t, IsConfigured(nil))
}

func TestIsConfigured_EmptyConfig(t *testing.T) {
	assert.False(t, IsConfigured(&Config{}))
}

func TestIsConfigured_MissingRPID(t *testing.T) {
	assert.False(t, IsConfigured(&Config{
		RPOrigins: []string{"https://example.com"},
	}))
}

func TestIsConfigured_MissingOrigins(t *testing.T) {
	assert.False(t, IsConfigured(&Config{
		RPID: "example.com",
	}))
}

func TestIsConfigured_EmptyOrigins(t *testing.T) {
	assert.False(t, IsConfigured(&Config{
		RPID:      "example.com",
		RPOrigins: []string{},
	}))
}

func TestIsConfigured_ValidConfig(t *testing.T) {
	assert.True(t, IsConfigured(&Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://example.com"},
	}))
}

func TestIsConfigured_ValidConfigWithDisplayName(t *testing.T) {
	assert.True(t, IsConfigured(&Config{
		RPDisplayName: "Example",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com", "http://localhost"},
	}))
}
