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

package invitation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newTestLogger creates a test logger with minimal output.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// newTestResponseWriter creates a real response writer for testing.
func newTestResponseWriter() response.HttpWriter {
	logger := newTestLogger()
	return response.NewResponseWriter(logger, nil)
}

// MockInvitationService is a mock implementation of InvitationServicer.
type MockInvitationService struct {
	mock.Mock
}

func (m *MockInvitationService) Create(ctx context.Context, tenantID, email, role string, invitedByID uint64, expiresIn time.Duration) (*entities.Invitation, error) {
	args := m.Called(ctx, tenantID, email, role, invitedByID, expiresIn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationService) Get(ctx context.Context, id uint64) (*entities.Invitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationService) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationService) ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}

func (m *MockInvitationService) Revoke(ctx context.Context, id uint64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockHttpWriter is a mock implementation of response.HttpWriter.
type MockHttpWriter struct {
	mock.Mock
}

func (m *MockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	m.Called(w, r, status, response)
}

func (m *MockHttpWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *MockHttpWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	m.Called(w, status, response)
}

func (m *MockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}

func (m *MockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}

func (m *MockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.Called(w, r, payload, err)
}

func (m *MockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

func (m *MockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.Called(w, r, err, payload)
}

func (m *MockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

// createTestInvitation creates a test invitation with specified parameters.
func createTestInvitation(id uint64, tenantID, email, role string, status entities.InvitationStatus) *entities.Invitation {
	now := time.Now().UTC()
	return &entities.Invitation{
		ID:          id,
		Token:       "test-token-" + email,
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		Status:      status,
		InvitedByID: 1,
		ExpiresAt:   now.Add(72 * time.Hour),
		CreatedAt:   now,
	}
}

// createExpiredInvitation creates an expired test invitation.
func createExpiredInvitation(id uint64, tenantID, email, role string) *entities.Invitation {
	past := time.Now().UTC().Add(-24 * time.Hour)
	return &entities.Invitation{
		ID:          id,
		Token:       "expired-token-" + email,
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		Status:      entities.InvitationStatusPending,
		InvitedByID: 1,
		ExpiresAt:   past,
		CreatedAt:   past.Add(-48 * time.Hour),
	}
}

// TestNewHandler_Success verifies successful handler creation.
func TestNewHandler_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	invHandler, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
		BaseURL:           "https://example.com",
	})

	require.NoError(t, err)
	require.NotNil(t, invHandler)

	// Verify handler is usable by calling a method
	// Type assertion to internal handler type for field verification
	h, ok := invHandler.(*handler)
	require.True(t, ok)
	assert.NotNil(t, h.logger)
	assert.NotNil(t, h.invitationService)
	assert.NotNil(t, h.responseWriter)
	assert.Equal(t, "https://example.com", h.baseURL)
}

// TestNewHandler_MissingLogger verifies error when logger is nil.
func TestNewHandler_MissingLogger(t *testing.T) {
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	invHandler, err := NewHandler(HandlerParams{
		Logger:            nil,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})

	require.Error(t, err)
	assert.Nil(t, invHandler)
	var serviceErr ErrServiceError
	assert.True(t, errors.As(err, &serviceErr))
}

// TestNewHandler_MissingInvitationService verifies error when service is nil.
func TestNewHandler_MissingInvitationService(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()

	invHandler, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: nil,
		ResponseWriter:    responseWriter,
	})

	require.Error(t, err)
	assert.Nil(t, invHandler)
	var serviceErr ErrServiceError
	assert.True(t, errors.As(err, &serviceErr))
}

// TestNewHandler_MissingResponseWriter verifies error when response writer is nil.
func TestNewHandler_MissingResponseWriter(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}

	invHandler, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    nil,
	})

	require.Error(t, err)
	assert.Nil(t, invHandler)
	var serviceErr ErrServiceError
	assert.True(t, errors.As(err, &serviceErr))
}

// TestHandler_Create_Success verifies successful invitation creation by tenant owner.
func TestHandler_Create_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
		BaseURL:           "https://example.com",
	})
	require.NoError(t, err)

	expectedInvitation := createTestInvitation(1, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), time.Duration(0)).Return(expectedInvitation, nil)

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)
	assert.Equal(t, http.StatusCreated, resp.Code)

	mockService.AssertExpectations(t)
}

// TestHandler_Create_MissingTenantContext verifies 401 when tenant context is missing.
func TestHandler_Create_MissingTenantContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_MissingUserContext verifies 401 when user ID is missing.
func TestHandler_Create_MissingUserContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	// Set tenant but no user ID (userID = 0)
	ctx := context.WithValue(req.Context(), tenant.TenantIDKey, "tenant-123")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_NotOwner verifies 403 when user is not tenant owner.
func TestHandler_Create_NotOwner(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error403", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notOwnerErr ErrNotTenantOwner
		return errors.As(err, &notOwnerErr)
	}), mock.Anything).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	// Set isOwner to false
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_InvalidBody verifies 400 when request body is malformed JSON.
func TestHandler_Create_InvalidBody(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var invalidBodyErr ErrInvalidRequestBody
		return errors.As(err, &invalidBodyErr)
	})).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader([]byte("invalid json{")))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_MissingEmail verifies 400 when email is missing.
func TestHandler_Create_MissingEmail(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var missingEmailErr ErrMissingEmail
		return errors.As(err, &missingEmailErr)
	})).Return()

	reqBody := CreateInvitationRequest{
		Email: "",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_InvalidEmail verifies 400 when email format is invalid.
func TestHandler_Create_InvalidEmail(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var invalidEmailErr ErrInvalidEmail
		return errors.As(err, &invalidEmailErr)
	})).Return()

	testCases := []string{
		"notanemail",
		"missing@domain",
		"@nodomain.com",
		"spaces in@email.com",
		"no spaces@email .com",
	}

	for _, email := range testCases {
		t.Run(email, func(t *testing.T) {
			reqBody := CreateInvitationRequest{
				Email: email,
				Role:  "member",
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
			ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			h.Create(w, req)
		})
	}

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_MissingRole verifies 400 when role is missing.
func TestHandler_Create_MissingRole(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var missingRoleErr ErrMissingRole
		return errors.As(err, &missingRoleErr)
	})).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_InvalidRole verifies 400 when role is not in ValidRoles.
func TestHandler_Create_InvalidRole(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var invalidRoleErr ErrInvalidRole
		return errors.As(err, &invalidRoleErr)
	})).Return()

	invalidRoles := []string{"superadmin", "guest", "owner", "root", "user"}

	for _, role := range invalidRoles {
		t.Run(role, func(t *testing.T) {
			reqBody := CreateInvitationRequest{
				Email: "user@example.com",
				Role:  role,
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
			ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			h.Create(w, req)
		})
	}

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Create")
}

// TestHandler_Create_ServiceError verifies 500 when service returns an error.
func TestHandler_Create_ServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	serviceError := errors.New("database connection failed")
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), time.Duration(0)).Return(nil, serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Create_DuplicateInvitation verifies 409 when duplicate invitation exists.
func TestHandler_Create_DuplicateInvitation(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
		BaseURL:           "https://example.com",
	})
	require.NoError(t, err)

	duplicateErr := ErrDuplicateInvitation{Email: "user@example.com"}
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), time.Duration(0)).Return(nil, duplicateErr)

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	mockService.AssertExpectations(t)
}

// TestHandler_Create_EmailAlreadyRegistered verifies 409 when email is already registered.
func TestHandler_Create_EmailAlreadyRegistered(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
		BaseURL:           "https://example.com",
	})
	require.NoError(t, err)

	registeredErr := ErrEmailAlreadyRegistered{Email: "user@example.com", TenantID: "tenant-123"}
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), time.Duration(0)).Return(nil, registeredErr)

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	mockService.AssertExpectations(t)
}

// TestHandler_Create_AllValidRoles verifies all valid roles are accepted.
func TestHandler_Create_AllValidRoles(t *testing.T) {
	validRoles := []string{"admin", "member", "viewer"}

	for _, role := range validRoles {
		t.Run(role, func(t *testing.T) {
			logger := newTestLogger()
			mockService := &MockInvitationService{}
			responseWriter := newTestResponseWriter()

			h, err := NewHandler(HandlerParams{
				Logger:            logger,
				InvitationService: mockService,
				ResponseWriter:    responseWriter,
				BaseURL:           "https://example.com",
			})
			require.NoError(t, err)

			expectedInvitation := createTestInvitation(1, "tenant-123", "user@example.com", role, entities.InvitationStatusPending)
			mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", role, uint64(100), time.Duration(0)).Return(expectedInvitation, nil)

			reqBody := CreateInvitationRequest{
				Email: "user@example.com",
				Role:  role,
			}
			body, _ := json.Marshal(reqBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
			ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			h.Create(w, req)

			assert.Equal(t, http.StatusCreated, w.Code)
			mockService.AssertExpectations(t)
		})
	}
}

// TestHandler_Create_WithExpiresIn verifies custom expiry duration is passed.
func TestHandler_Create_WithExpiresIn(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
		BaseURL:           "https://example.com",
	})
	require.NoError(t, err)

	expectedInvitation := createTestInvitation(1, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	customDuration := 24 * time.Hour
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), customDuration).Return(expectedInvitation, nil)

	reqBody := CreateInvitationRequest{
		Email:     "user@example.com",
		Role:      "member",
		ExpiresIn: customDuration,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockService.AssertExpectations(t)
}

// TestHandler_List_Success verifies successful listing of invitations.
func TestHandler_List_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	invitations := []*entities.Invitation{
		createTestInvitation(1, "tenant-123", "user1@example.com", "admin", entities.InvitationStatusPending),
		createTestInvitation(2, "tenant-123", "user2@example.com", "member", entities.InvitationStatusAccepted),
		createTestInvitation(3, "tenant-123", "user3@example.com", "viewer", entities.InvitationStatusRevoked),
	}
	mockService.On("ListByTenant", mock.Anything, "tenant-123").Return(invitations, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	mockService.AssertExpectations(t)
}

// TestHandler_List_MissingTenantContext verifies 401 when tenant context is missing.
func TestHandler_List_MissingTenantContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	w := httptest.NewRecorder()

	h.List(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "ListByTenant")
}

// TestHandler_List_ServiceError verifies 500 when service returns an error.
func TestHandler_List_ServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	serviceError := errors.New("database error")
	mockService.On("ListByTenant", mock.Anything, "tenant-123").Return(nil, serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.List(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_List_EmptyResult verifies successful response with empty list.
func TestHandler_List_EmptyResult(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	mockService.On("ListByTenant", mock.Anything, "tenant-123").Return([]*entities.Invitation{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.List(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_Success verifies successful token lookup.
func TestHandler_GetByToken_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	invitation := createTestInvitation(1, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("GetByToken", mock.Anything, "valid-token-abc").Return(invitation, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/valid-token-abc", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "valid-token-abc"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_MissingToken verifies 400 when token is missing from URL.
func TestHandler_GetByToken_MissingToken(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var missingTokenErr ErrMissingToken
		return errors.As(err, &missingTokenErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/", nil)
	req = mux.SetURLVars(req, map[string]string{"token": ""})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "GetByToken")
}

// TestHandler_GetByToken_NotFound verifies 404 when invitation is not found.
func TestHandler_GetByToken_NotFound(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockService.On("GetByToken", mock.Anything, "nonexistent-token").Return(nil, datastore.ErrRecordNotFound)
	mockWriter.On("Error404", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notFoundErr ErrInvitationNotFound
		return errors.As(err, &notFoundErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/nonexistent-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "nonexistent-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_Expired verifies 400 when invitation is expired.
func TestHandler_GetByToken_Expired(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	expiredInvitation := createExpiredInvitation(1, "tenant-123", "user@example.com", "member")
	mockService.On("GetByToken", mock.Anything, "expired-token").Return(expiredInvitation, nil)
	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var expiredErr ErrInvitationExpired
		return errors.As(err, &expiredErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/expired-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "expired-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_Revoked verifies 400 when invitation is revoked.
func TestHandler_GetByToken_Revoked(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	revokedInvitation := createTestInvitation(1, "tenant-123", "user@example.com", "member", entities.InvitationStatusRevoked)
	mockService.On("GetByToken", mock.Anything, "revoked-token").Return(revokedInvitation, nil)
	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var revokedErr ErrInvitationRevoked
		return errors.As(err, &revokedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/revoked-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "revoked-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_AlreadyAccepted verifies 400 when invitation is already accepted.
func TestHandler_GetByToken_AlreadyAccepted(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	acceptedInvitation := createTestInvitation(1, "tenant-123", "user@example.com", "member", entities.InvitationStatusAccepted)
	mockService.On("GetByToken", mock.Anything, "accepted-token").Return(acceptedInvitation, nil)
	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var acceptedErr ErrInvitationAlreadyAccepted
		return errors.As(err, &acceptedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/accepted-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "accepted-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_GetByToken_ServiceError verifies 500 on non-NotFound service error.
func TestHandler_GetByToken_ServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	serviceError := errors.New("database connection error")
	mockService.On("GetByToken", mock.Anything, "some-token").Return(nil, serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/some-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "some-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Get_Success verifies successful get by ID.
func TestHandler_Get_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	invitation := createTestInvitation(42, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("Get", mock.Anything, uint64(42)).Return(invitation, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Get(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	mockService.AssertExpectations(t)
}

// TestHandler_Get_MissingTenantContext verifies 401 when tenant context is missing.
func TestHandler_Get_MissingTenantContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	w := httptest.NewRecorder()

	h.Get(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
}

// TestHandler_Get_MissingID verifies 400 when ID is missing from URL.
func TestHandler_Get_MissingID(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var missingIDErr ErrMissingInvitationID
		return errors.As(err, &missingIDErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Get(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
}

// TestHandler_Get_InvalidID verifies 400 when ID format is invalid.
func TestHandler_Get_InvalidID(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var invalidIDErr ErrInvalidInvitationID
		return errors.As(err, &invalidIDErr)
	})).Return()

	invalidIDs := []string{"abc", "12.5", "-1", "999999999999999999999"}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/"+id, nil)
			req = mux.SetURLVars(req, map[string]string{"id": id})
			ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			h.Get(w, req)
		})
	}

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
}

// TestHandler_Get_NotFound verifies 404 when invitation is not found.
func TestHandler_Get_NotFound(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockService.On("Get", mock.Anything, uint64(999)).Return(nil, datastore.ErrRecordNotFound)
	mockWriter.On("Error404", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notFoundErr ErrInvitationNotFound
		return errors.As(err, &notFoundErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Get(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Get_ServiceError verifies 500 on service error.
func TestHandler_Get_ServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	serviceError := errors.New("database connection failed")
	mockService.On("Get", mock.Anything, uint64(42)).Return(nil, serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Get(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Get_WrongTenant verifies 404 when invitation belongs to different tenant.
func TestHandler_Get_WrongTenant(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	invitation := createTestInvitation(42, "tenant-456", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("Get", mock.Anything, uint64(42)).Return(invitation, nil)
	mockWriter.On("Error404", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notFoundErr ErrInvitationNotFound
		return errors.As(err, &notFoundErr)
	})).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Get(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Revoke_Success verifies successful invitation revocation by owner.
func TestHandler_Revoke_Success(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	invitation := createTestInvitation(42, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("Get", mock.Anything, uint64(42)).Return(invitation, nil)
	mockService.On("Revoke", mock.Anything, uint64(42)).Return(nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp restwire.WebServiceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.True(t, resp.Success)

	mockService.AssertExpectations(t)
}

// TestHandler_Revoke_NotOwner verifies 403 when user is not tenant owner.
func TestHandler_Revoke_NotOwner(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error403", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notOwnerErr ErrNotTenantOwner
		return errors.As(err, &notOwnerErr)
	}), mock.Anything).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, false)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_MissingID verifies 400 when ID is missing from URL.
func TestHandler_Revoke_MissingID(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var missingIDErr ErrMissingInvitationID
		return errors.As(err, &missingIDErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_InvalidID verifies 400 when ID format is invalid.
func TestHandler_Revoke_InvalidID(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error400", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var invalidIDErr ErrInvalidInvitationID
		return errors.As(err, &invalidIDErr)
	})).Return()

	invalidIDs := []string{"abc", "12.5", "-1", "999999999999999999999"}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/"+id, nil)
			req = mux.SetURLVars(req, map[string]string{"id": id})
			ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()

			h.Revoke(w, req)
		})
	}

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_NotFound verifies 404 when invitation is not found.
func TestHandler_Revoke_NotFound(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockService.On("Get", mock.Anything, uint64(999)).Return(nil, datastore.ErrRecordNotFound)
	mockWriter.On("Error404", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notFoundErr ErrInvitationNotFound
		return errors.As(err, &notFoundErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_WrongTenant verifies 404 when invitation belongs to different tenant (cross-tenant blocked).
func TestHandler_Revoke_WrongTenant(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	// Invitation belongs to tenant-456
	invitation := createTestInvitation(42, "tenant-456", "user@example.com", "member", entities.InvitationStatusPending)
	mockService.On("Get", mock.Anything, uint64(42)).Return(invitation, nil)
	mockWriter.On("Error404", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var notFoundErr ErrInvitationNotFound
		return errors.As(err, &notFoundErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	// User is from tenant-123, not tenant-456
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_MissingTenantContext verifies 401 when tenant context is missing.
func TestHandler_Revoke_MissingTenantContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_MissingUserContext verifies 401 when user context is missing.
func TestHandler_Revoke_MissingUserContext(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	mockWriter.On("Error401", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var unauthorizedErr ErrUnauthorized
		return errors.As(err, &unauthorizedErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	// Set tenant but no user ID
	ctx := context.WithValue(req.Context(), tenant.TenantIDKey, "tenant-123")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Get")
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_GetServiceError verifies 500 on service error during Get.
func TestHandler_Revoke_GetServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	serviceError := errors.New("database connection failed")
	mockService.On("Get", mock.Anything, uint64(42)).Return(nil, serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_RevokeServiceError verifies 500 on service error during Revoke.
func TestHandler_Revoke_RevokeServiceError(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	invitation := createTestInvitation(42, "tenant-123", "user@example.com", "member", entities.InvitationStatusPending)
	serviceError := errors.New("failed to update record")
	mockService.On("Get", mock.Anything, uint64(42)).Return(invitation, nil)
	mockService.On("Revoke", mock.Anything, uint64(42)).Return(serviceError)
	mockWriter.On("Error500", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		var svcErr ErrServiceError
		return errors.As(err, &svcErr)
	})).Return()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)
}

// TestHandler_Revoke_AlreadyRevoked verifies 409 when invitation is already revoked.
func TestHandler_Revoke_AlreadyRevoked(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	revokedInvitation := createTestInvitation(42, "tenant-123", "user@example.com", "member", entities.InvitationStatusRevoked)
	mockService.On("Get", mock.Anything, uint64(42)).Return(revokedInvitation, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Revoke")
}

// TestHandler_Revoke_AlreadyAccepted verifies 409 when invitation is already accepted.
func TestHandler_Revoke_AlreadyAccepted(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	responseWriter := newTestResponseWriter()

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    responseWriter,
	})
	require.NoError(t, err)

	acceptedInvitation := createTestInvitation(42, "tenant-123", "user@example.com", "member", entities.InvitationStatusAccepted)
	mockService.On("Get", mock.Anything, uint64(42)).Return(acceptedInvitation, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "42"})
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Revoke(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	mockService.AssertExpectations(t)
	mockService.AssertNotCalled(t, "Revoke")
}

// TestIsValidRole verifies role validation function.
func TestIsValidRole(t *testing.T) {
	validRoles := []string{"admin", "member", "viewer"}
	invalidRoles := []string{"superadmin", "guest", "owner", "root", "", "Admin", "MEMBER"}

	for _, role := range validRoles {
		t.Run("valid_"+role, func(t *testing.T) {
			assert.True(t, IsValidRole(role))
		})
	}

	for _, role := range invalidRoles {
		t.Run("invalid_"+role, func(t *testing.T) {
			assert.False(t, IsValidRole(role))
		})
	}
}

// TestToInvitationResponse verifies response conversion.
func TestToInvitationResponse(t *testing.T) {
	now := time.Now().UTC()
	inv := &entities.Invitation{
		ID:        123,
		Token:     "secret-token",
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: now.Add(72 * time.Hour),
		CreatedAt: now,
	}

	t.Run("with_token", func(t *testing.T) {
		resp := ToInvitationResponse(inv, true)
		assert.Equal(t, uint64(123), resp.ID)
		assert.Equal(t, "tenant-123", resp.TenantID)
		assert.Equal(t, "user@example.com", resp.Email)
		assert.Equal(t, "member", resp.Role)
		assert.Equal(t, "pending", resp.Status)
		assert.Equal(t, "secret-token", resp.Token)
		assert.Equal(t, inv.ExpiresAt, resp.ExpiresAt)
		assert.Equal(t, inv.CreatedAt, resp.CreatedAt)
	})

	t.Run("without_token", func(t *testing.T) {
		resp := ToInvitationResponse(inv, false)
		assert.Equal(t, uint64(123), resp.ID)
		assert.Equal(t, "user@example.com", resp.Email)
		assert.Equal(t, "member", resp.Role)
		assert.Equal(t, "pending", resp.Status)
		assert.Empty(t, resp.Token)
	})
}

// TestToInvitationResponseWithURL verifies response conversion with invite URL.
func TestToInvitationResponseWithURL(t *testing.T) {
	now := time.Now().UTC()
	inv := &entities.Invitation{
		ID:        123,
		Token:     "secret-token",
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: now.Add(72 * time.Hour),
		CreatedAt: now,
	}

	t.Run("with_token_and_url", func(t *testing.T) {
		resp := ToInvitationResponseWithURL(inv, true, "https://example.com")
		assert.Equal(t, "secret-token", resp.Token)
		assert.Equal(t, "https://example.com/invite/secret-token", resp.InviteURL)
	})

	t.Run("with_token_no_url", func(t *testing.T) {
		resp := ToInvitationResponseWithURL(inv, true, "")
		assert.Equal(t, "secret-token", resp.Token)
		assert.Empty(t, resp.InviteURL)
	})

	t.Run("without_token", func(t *testing.T) {
		resp := ToInvitationResponseWithURL(inv, false, "https://example.com")
		assert.Empty(t, resp.Token)
		assert.Empty(t, resp.InviteURL)
	})

	t.Run("url_with_trailing_slash", func(t *testing.T) {
		resp := ToInvitationResponseWithURL(inv, true, "https://example.com/")
		assert.Equal(t, "https://example.com/invite/secret-token", resp.InviteURL)
	})
}

// TestToInvitationListResponse verifies list response conversion.
func TestToInvitationListResponse(t *testing.T) {
	invitations := []*entities.Invitation{
		createTestInvitation(1, "tenant-123", "user1@example.com", "admin", entities.InvitationStatusPending),
		createTestInvitation(2, "tenant-123", "user2@example.com", "member", entities.InvitationStatusAccepted),
	}

	resp := ToInvitationListResponse(invitations, "https://example.com")
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Invitations, 2)
	assert.Equal(t, "user1@example.com", resp.Invitations[0].Email)
	assert.Equal(t, "tenant-123", resp.Invitations[0].TenantID)
	assert.Equal(t, "user2@example.com", resp.Invitations[1].Email)
	// Token should not be included in list response
	assert.Empty(t, resp.Invitations[0].Token)
	assert.Empty(t, resp.Invitations[1].Token)
}

// TestToInvitationListResponse_Empty verifies empty list handling.
func TestToInvitationListResponse_Empty(t *testing.T) {
	resp := ToInvitationListResponse([]*entities.Invitation{}, "https://example.com")
	assert.Equal(t, 0, resp.Total)
	assert.NotNil(t, resp.Invitations)
	assert.Len(t, resp.Invitations, 0)
}

// TestErrorMessages verifies error message formatting.
func TestErrorMessages(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "ErrInvalidRequestBody",
			err:      ErrInvalidRequestBody{Reason: "malformed JSON"},
			contains: "invalid request body",
		},
		{
			name:     "ErrMissingEmail",
			err:      ErrMissingEmail{},
			contains: "email is required",
		},
		{
			name:     "ErrInvalidEmail",
			err:      ErrInvalidEmail{Email: "bad@"},
			contains: "invalid email format",
		},
		{
			name:     "ErrMissingRole",
			err:      ErrMissingRole{},
			contains: "role is required",
		},
		{
			name:     "ErrInvalidRole",
			err:      ErrInvalidRole{Role: "superadmin"},
			contains: "invalid role",
		},
		{
			name:     "ErrMissingInvitationID",
			err:      ErrMissingInvitationID{},
			contains: "invitation id is required",
		},
		{
			name:     "ErrInvalidInvitationID",
			err:      ErrInvalidInvitationID{ID: "abc"},
			contains: "invalid invitation id",
		},
		{
			name:     "ErrMissingToken",
			err:      ErrMissingToken{},
			contains: "token is required",
		},
		{
			name:     "ErrInvitationNotFound",
			err:      ErrInvitationNotFound{ID: 123},
			contains: "not found",
		},
		{
			name:     "ErrInvitationExpired",
			err:      ErrInvitationExpired{Token: "abc"},
			contains: "expired",
		},
		{
			name:     "ErrInvitationAlreadyAccepted",
			err:      ErrInvitationAlreadyAccepted{Token: "abc"},
			contains: "already been accepted",
		},
		{
			name:     "ErrInvitationRevoked",
			err:      ErrInvitationRevoked{Token: "abc"},
			contains: "revoked",
		},
		{
			name:     "ErrNotTenantOwner",
			err:      ErrNotTenantOwner{},
			contains: "tenant owner",
		},
		{
			name:     "ErrUnauthorized",
			err:      ErrUnauthorized{Reason: "missing token"},
			contains: "unauthorized",
		},
		{
			name:     "ErrServiceError",
			err:      ErrServiceError{Operation: "create", Cause: errors.New("db error")},
			contains: "create failed",
		},
		{
			name:     "ErrMissingLogger",
			err:      ErrMissingLogger{},
			contains: "logger is required",
		},
		{
			name:     "ErrMissingInvitationService",
			err:      ErrMissingInvitationService{},
			contains: "invitation service is required",
		},
		{
			name:     "ErrMissingResponseWriter",
			err:      ErrMissingResponseWriter{},
			contains: "response writer is required",
		},
		{
			name:     "ErrDuplicateInvitation",
			err:      ErrDuplicateInvitation{Email: "test@example.com"},
			contains: "already exists",
		},
		{
			name:     "ErrEmailAlreadyRegistered",
			err:      ErrEmailAlreadyRegistered{Email: "test@example.com", TenantID: "tenant-1"},
			contains: "already registered",
		},
		{
			name:     "ErrInvitationAlreadyRevoked",
			err:      ErrInvitationAlreadyRevoked{ID: 123},
			contains: "already revoked",
		},
		{
			name:     "ErrInvitationNotFound_WithToken",
			err:      ErrInvitationNotFound{Token: "abc123"},
			contains: "not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, tc.err.Error(), tc.contains)
		})
	}
}

// TestErrServiceError_Unwrap verifies the Unwrap method for error unwrapping.
func TestErrServiceError_Unwrap(t *testing.T) {
	cause := errors.New("root cause error")
	svcErr := ErrServiceError{Operation: "test", Cause: cause}

	unwrapped := svcErr.Unwrap()
	assert.Equal(t, cause, unwrapped)

	// Test with errors.Is/As
	assert.True(t, errors.Is(svcErr, cause))
}

// TestHandler_Create_ResponseIncludesToken verifies token is included in create response.
func TestHandler_Create_ResponseIncludesToken(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
		BaseURL:           "https://example.com",
	})
	require.NoError(t, err)

	expectedInvitation := &entities.Invitation{
		ID:          1,
		Token:       "secret-secure-token",
		TenantID:    "tenant-123",
		Email:       "user@example.com",
		Role:        "member",
		Status:      entities.InvitationStatusPending,
		InvitedByID: 100,
		ExpiresAt:   time.Now().UTC().Add(72 * time.Hour),
		CreatedAt:   time.Now().UTC(),
	}
	mockService.On("Create", mock.Anything, "tenant-123", "user@example.com", "member", uint64(100), time.Duration(0)).Return(expectedInvitation, nil)

	var capturedPayload interface{}
	mockWriter.On("Success201", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedPayload = args.Get(2)
	}).Return()

	reqBody := CreateInvitationRequest{
		Email: "user@example.com",
		Role:  "member",
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewReader(body))
	ctx := tenant.SetTenantContext(req.Context(), "tenant-123", 100, true)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.Create(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)

	resp, ok := capturedPayload.(InvitationResponse)
	require.True(t, ok)
	assert.Equal(t, "secret-secure-token", resp.Token)
	assert.Equal(t, "https://example.com/invite/secret-secure-token", resp.InviteURL)
}

// TestHandler_GetByToken_ResponseExcludesToken verifies token is not included in GetByToken response.
func TestHandler_GetByToken_ResponseExcludesToken(t *testing.T) {
	logger := newTestLogger()
	mockService := &MockInvitationService{}
	mockWriter := &MockHttpWriter{}

	h, err := NewHandler(HandlerParams{
		Logger:            logger,
		InvitationService: mockService,
		ResponseWriter:    mockWriter,
	})
	require.NoError(t, err)

	invitation := &entities.Invitation{
		ID:        1,
		Token:     "secret-secure-token",
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(72 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	mockService.On("GetByToken", mock.Anything, "lookup-token").Return(invitation, nil)

	var capturedPayload interface{}
	mockWriter.On("Success200", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedPayload = args.Get(2)
	}).Return()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/token/lookup-token", nil)
	req = mux.SetURLVars(req, map[string]string{"token": "lookup-token"})
	w := httptest.NewRecorder()

	h.GetByToken(w, req)

	mockWriter.AssertExpectations(t)
	mockService.AssertExpectations(t)

	resp, ok := capturedPayload.(InvitationResponse)
	require.True(t, ok)
	assert.Empty(t, resp.Token) // Token should NOT be included
}

// TestBuildInviteURL verifies the invite URL building function.
func TestBuildInviteURL(t *testing.T) {
	testCases := []struct {
		name     string
		baseURL  string
		token    string
		expected string
	}{
		{
			name:     "normal_url",
			baseURL:  "https://example.com",
			token:    "abc123",
			expected: "https://example.com/invite/abc123",
		},
		{
			name:     "url_with_trailing_slash",
			baseURL:  "https://example.com/",
			token:    "abc123",
			expected: "https://example.com/invite/abc123",
		},
		{
			name:     "empty_base_url",
			baseURL:  "",
			token:    "abc123",
			expected: "",
		},
		{
			name:     "empty_token",
			baseURL:  "https://example.com",
			token:    "",
			expected: "",
		},
		{
			name:     "both_empty",
			baseURL:  "",
			token:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := buildInviteURL(tc.baseURL, tc.token)
			assert.Equal(t, tc.expected, result)
		})
	}
}
