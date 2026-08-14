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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mocks
// =============================================================================

type mockUserService struct{ mock.Mock }

func (m *mockUserService) Save(ctx context.Context, user *entities.User) error {
	return m.Called(ctx, user).Error(0)
}
func (m *mockUserService) Delete(ctx context.Context, userID uint64) error {
	return m.Called(ctx, userID).Error(0)
}
func (m *mockUserService) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}
func (m *mockUserService) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}
func (m *mockUserService) GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.User), args.Error(1)
}
func (m *mockUserService) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

type mockRegistrationService struct{ mock.Mock }

func (m *mockRegistrationService) Create(ctx context.Context, r *entities.Registration) error {
	return m.Called(ctx, r).Error(0)
}
func (m *mockRegistrationService) Delete(ctx context.Context, s service.Session, id uint64) error {
	return m.Called(ctx, s, id).Error(0)
}
func (m *mockRegistrationService) Get(ctx context.Context, s service.Session, id uint64) (*entities.Registration, error) {
	args := m.Called(ctx, s, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Registration), args.Error(1)
}

type mockResponseWriter struct{ mock.Mock }

func (m *mockResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.Called(w, r, status, resp)
}
func (m *mockResponseWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.Called(w, status, resp)
}
func (m *mockResponseWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.Called(w, status, resp)
}
func (m *mockResponseWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}
func (m *mockResponseWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.Called(w, r, payload)
}
func (m *mockResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.Called(w, r, payload, err)
}
func (m *mockResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}
func (m *mockResponseWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}
func (m *mockResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}
func (m *mockResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}
func (m *mockResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.Called(w, r, err, payload)
}
func (m *mockResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.Called(w, r, err)
}

// mockFIDO2Client implements the SDK FIDO2Client interface — the single
// canonical WebAuthn/FIDO2 ceremony surface the handler proxies to.
type mockFIDO2Client struct{ mock.Mock }

var _ quicbaassdk.FIDO2Client = (*mockFIDO2Client)(nil)

func (m *mockFIDO2Client) BeginRegistration(ctx context.Context, req *quicbaassdk.FIDO2BeginRegistrationRequest) (*quicbaassdk.FIDO2BeginRegistrationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*quicbaassdk.FIDO2BeginRegistrationResponse), args.Error(1)
}
func (m *mockFIDO2Client) FinishRegistration(ctx context.Context, req *quicbaassdk.FIDO2FinishRegistrationRequest) (*quicbaassdk.FIDO2FinishRegistrationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*quicbaassdk.FIDO2FinishRegistrationResponse), args.Error(1)
}
func (m *mockFIDO2Client) BeginAuthentication(ctx context.Context, req *quicbaassdk.FIDO2BeginAuthenticationRequest) (*quicbaassdk.FIDO2BeginAuthenticationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*quicbaassdk.FIDO2BeginAuthenticationResponse), args.Error(1)
}
func (m *mockFIDO2Client) FinishAuthentication(ctx context.Context, req *quicbaassdk.FIDO2FinishAuthenticationRequest) (*quicbaassdk.FIDO2FinishAuthenticationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*quicbaassdk.FIDO2FinishAuthenticationResponse), args.Error(1)
}

// =============================================================================
// Test helpers
// =============================================================================

type harness struct {
	handler *WebAuthnRestHandler
	users   *mockUserService
	regs    *mockRegistrationService
	writer  *mockResponseWriter
	sdk     *mockFIDO2Client
	logger  *logging.Logger
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)
	users := new(mockUserService)
	regs := new(mockRegistrationService)
	writer := new(mockResponseWriter)
	sdk := new(mockFIDO2Client)

	params := ServiceParams{
		Config: &Config{
			RPDisplayName: "Test RP",
			RPID:          "localhost",
			RPOrigins:     []string{"http://localhost"},
		},
		JWTService:          &jwt.Service{},
		Logger:              logger,
		RegistrationService: regs,
		ResponseWriter:      writer,
		UserService:         users,
		FIDO2Client:         sdk,
	}
	rh, err := NewHandler(params)
	require.NoError(t, err)
	require.NotNil(t, rh)
	return &harness{
		handler: rh.(*WebAuthnRestHandler),
		users:   users,
		regs:    regs,
		writer:  writer,
		sdk:     sdk,
		logger:  logger,
	}
}

// createTestHandler is a compatibility shim retained so that
// error_writers_test.go keeps testing the helper functions without
// duplicating the mock setup. The middle three return values are
// placeholders left over from the pre-SDK signature; new tests should
// use newHarness instead.
func createTestHandler(t *testing.T) (*WebAuthnRestHandler, *mockUserService, *mockRegistrationService, interface{}, *mockResponseWriter) {
	h := newHarness(t)
	return h.handler, h.users, h.regs, nil, h.writer
}

// =============================================================================
// NewHandler
// =============================================================================

func TestNewHandler_RequiresSDKClient(t *testing.T) {
	_, err := NewHandler(ServiceParams{
		Config:      &Config{RPID: "x", RPOrigins: []string{"https://x"}},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: nil,
	})
	assert.ErrorIs(t, err, ErrSDKClientRequired)
}

func TestNewHandler_RequiresValidConfig(t *testing.T) {
	sdk := new(mockFIDO2Client)
	_, err := NewHandler(ServiceParams{
		Config:      nil,
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)

	_, err = NewHandler(ServiceParams{
		Config:      &Config{RPID: ""},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)

	_, err = NewHandler(ServiceParams{
		Config:      &Config{RPID: "x", RPOrigins: nil},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

func TestNewHandler_Success(t *testing.T) {
	h := newHarness(t)
	require.NotNil(t, h.handler)
	assert.NotNil(t, h.handler.fido2Client)
}

// =============================================================================
// BeginRegistration
// =============================================================================

func TestBeginRegistration_Success(t *testing.T) {
	h := newHarness(t)

	username := "alice@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.sdk.On("BeginRegistration", mock.Anything, mock.AnythingOfType("*transport.BeginRegistrationRequest")).
		Return(&quicbaassdk.FIDO2BeginRegistrationResponse{SessionID: "sess", OptionsJSON: `{"challenge":"test"}`}, nil)
	h.regs.On("Create", mock.Anything, mock.AnythingOfType("*entities.Registration")).Return(nil)
	h.writer.On("Write", w, req, http.StatusOK, mock.Anything).Return()

	h.handler.BeginRegistration(w, req)

	h.users.AssertExpectations(t)
	h.sdk.AssertExpectations(t)
	h.regs.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestBeginRegistration_InvalidJSON(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, ErrInvalidRequestBody).Return()
	h.handler.BeginRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestBeginRegistration_MissingUsername(t *testing.T) {
	h := newHarness(t)
	body, _ := json.Marshal(map[string]string{"username": ""})
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, ErrUsernameRequired).Return()
	h.handler.BeginRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestBeginRegistration_UserAlreadyRegistered(t *testing.T) {
	h := newHarness(t)
	username := "dup@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, userID).Return(&entities.User{ID: userID, Email: username}, nil)
	h.writer.On("Write", w, req, http.StatusConflict, mock.MatchedBy(func(resp response.WebServiceResponse) bool {
		return resp.Code == http.StatusConflict && resp.Error == ErrUserAlreadyExists.Error() && !resp.Success
	})).Return()
	h.handler.BeginRegistration(w, req)
	h.users.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestBeginRegistration_SDKError(t *testing.T) {
	h := newHarness(t)
	username := "sdkerr@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sdkErr := errors.New("upstream failed")
	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.sdk.On("BeginRegistration", mock.Anything, mock.Anything).Return(nil, sdkErr)
	h.writer.On("Error500", w, req, sdkErr).Return()
	h.handler.BeginRegistration(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestBeginRegistration_RegistrationServiceError(t *testing.T) {
	h := newHarness(t)
	username := "regsave@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/registration/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	saveErr := errors.New("create failed")
	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.sdk.On("BeginRegistration", mock.Anything, mock.Anything).
		Return(&quicbaassdk.FIDO2BeginRegistrationResponse{SessionID: "sess", OptionsJSON: `{"challenge":"x"}`}, nil)
	h.regs.On("Create", mock.Anything, mock.Anything).Return(saveErr)
	h.writer.On("Error500", w, req, saveErr).Return()
	h.handler.BeginRegistration(w, req)
	h.regs.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// FinishRegistration
// =============================================================================

func TestFinishRegistration_MissingHeader(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, ErrInvalidUserIDHeader).Return()
	h.handler.FinishRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_BadBase64Header(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	req.Header.Set("X-User-Id", "not base64!!!")
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, mock.Anything).Return()
	h.handler.FinishRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_RegistrationLookupFails(t *testing.T) {
	h := newHarness(t)
	userID := uint64(424242)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(userID, 10)))
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	req.Header.Set("X-User-Id", encoded)
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.writer.On("Error404", w, req, datastore.ErrRecordNotFound).Return()
	h.handler.FinishRegistration(w, req)
	h.regs.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_InvalidBody(t *testing.T) {
	h := newHarness(t)
	userID := uint64(101)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(userID, 10)))
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader([]byte("nope")))
	req.Header.Set("X-User-Id", encoded)
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, userID).
		Return(&entities.Registration{ID: userID, Email: "x@example.com"}, nil)
	h.writer.On("Error400", w, req, ErrInvalidRequestBody).Return()
	h.handler.FinishRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_SDKError(t *testing.T) {
	h := newHarness(t)
	userID := uint64(202)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatUint(userID, 10)))
	body, _ := json.Marshal(quicbaassdk.FIDO2FinishRegistrationRequest{SessionID: "sess", AttestationJSON: `{"id":"x"}`})
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", encoded)
	w := httptest.NewRecorder()
	sdkErr := errors.New("attestation invalid")
	h.regs.On("Get", mock.Anything, mock.Anything, userID).
		Return(&entities.Registration{ID: userID, Email: "y@example.com"}, nil)
	h.sdk.On("FinishRegistration", mock.Anything, mock.Anything).Return(nil, sdkErr)
	h.writer.On("Error400", w, req, sdkErr).Return()
	h.handler.FinishRegistration(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// BeginLogin
// =============================================================================

func TestBeginLogin_Success(t *testing.T) {
	h := newHarness(t)
	username := "bob@example.com"
	user := entities.NewUser(username)
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("BeginAuthentication", mock.Anything, mock.AnythingOfType("*transport.BeginAuthenticationRequest")).
		Return(&quicbaassdk.FIDO2BeginAuthenticationResponse{SessionID: "sess", OptionsJSON: `{"challenge":"auth"}`}, nil)
	h.writer.On("Write", w, req, http.StatusOK, mock.Anything).Return()
	h.handler.BeginLogin(w, req)
	h.users.AssertExpectations(t)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
	assert.Equal(t, strconv.FormatUint(user.ID, 10), w.Header().Get("X-User-ID"))
}

func TestBeginLogin_UserNotFound(t *testing.T) {
	h := newHarness(t)
	username := "ghost@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.writer.On("Error400", w, req, ErrInvalidUserID).Return()
	h.handler.BeginLogin(w, req)
	h.users.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestBeginLogin_InvalidBody(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader([]byte("{")))
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, ErrInvalidUserIDHeader).Return()
	h.handler.BeginLogin(w, req)
	h.writer.AssertExpectations(t)
}

func TestBeginLogin_SDKError(t *testing.T) {
	h := newHarness(t)
	username := "fail@example.com"
	user := entities.NewUser(username)
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/login/begin", bytes.NewReader(body))
	w := httptest.NewRecorder()
	sdkErr := errors.New("upstream down")
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("BeginAuthentication", mock.Anything, mock.Anything).Return(nil, sdkErr)
	h.writer.On("Error500", w, req, sdkErr).Return()
	h.handler.BeginLogin(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// FinishLogin
// =============================================================================

func TestFinishLogin_Success_SDKToken(t *testing.T) {
	h := newHarness(t)
	username := "ok@example.com"
	user := entities.NewUser(username)
	body, _ := json.Marshal(quicbaassdk.FIDO2FinishAuthenticationRequest{SessionID: "sess", Username: username, AssertionJSON: `{"id":"x"}`})
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", mock.Anything, mock.Anything).
		Return(&quicbaassdk.FIDO2FinishAuthenticationResponse{Success: true, Token: "JWT.TOKEN"}, nil)
	h.writer.On("Success200", w, req, "JWT.TOKEN").Return()
	h.handler.FinishLogin(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestFinishLogin_UserNotFound(t *testing.T) {
	h := newHarness(t)
	username := "lost@example.com"
	userID := util.NewID([]byte(username))
	body, _ := json.Marshal(map[string]string{"username": username})
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.writer.On("Error404", w, req, datastore.ErrRecordNotFound).Return()
	h.handler.FinishLogin(w, req)
	h.users.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestFinishLogin_SDKError(t *testing.T) {
	h := newHarness(t)
	username := "deny@example.com"
	user := entities.NewUser(username)
	body, _ := json.Marshal(quicbaassdk.FIDO2FinishAuthenticationRequest{SessionID: "sess", AssertionJSON: `{"id":"x"}`})
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()
	sdkErr := errors.New("assertion bad")
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", mock.Anything, mock.Anything).Return(nil, sdkErr)
	h.writer.On("Error400", w, req, sdkErr).Return()
	h.handler.FinishLogin(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// RegistrationStatus
// =============================================================================

func TestRegistrationStatus_Registered(t *testing.T) {
	h := newHarness(t)
	user := entities.NewUser("yes@example.com")
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.writer.On("Write", w, req, http.StatusOK, "registered").Return()
	h.handler.RegistrationStatus(w, req)
	h.users.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestRegistrationStatus_NotRegistered_NoHeader(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/registration/status", bytes.NewReader([]byte("garbage")))
	w := httptest.NewRecorder()
	h.writer.On("Write", w, req, http.StatusOK, "not_registered").Return()
	h.handler.RegistrationStatus(w, req)
	h.writer.AssertExpectations(t)
}

func TestRegistrationStatus_NotRegistered_UserNotFound(t *testing.T) {
	h := newHarness(t)
	userID := uint64(99)
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", strconv.FormatUint(userID, 10))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
	h.writer.On("Write", w, req, http.StatusOK, "not_registered").Return()
	h.handler.RegistrationStatus(w, req)
	h.users.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestRegistrationStatus_ZeroUserID(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", "0")
	w := httptest.NewRecorder()
	h.writer.On("Write", w, req, http.StatusOK, "not_registered").Return()
	h.handler.RegistrationStatus(w, req)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// AuthMiddleware
// =============================================================================

func TestVerify_PassesThrough(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h.handler.Verify(w, req, next)
	assert.True(t, called)
}

func TestRefreshToken_Unsupported(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, ErrRefreshUnsupported).Return()
	h.handler.RefreshToken(w, req)
	h.writer.AssertExpectations(t)
}

// =============================================================================
// Helpers + config
// =============================================================================

func TestIsConfigured(t *testing.T) {
	assert.False(t, IsConfigured(nil))
	assert.False(t, IsConfigured(&Config{}))
	assert.False(t, IsConfigured(&Config{RPID: "x"}))
	assert.False(t, IsConfigured(&Config{RPOrigins: []string{"y"}}))
	assert.True(t, IsConfigured(&Config{RPID: "x", RPOrigins: []string{"y"}}))
}

func TestGetUserIDAndEmail_FromHeaderNumeric(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Id", "12345")
	id, email, err := getUserIDAndEmail(req)
	assert.NoError(t, err)
	assert.Equal(t, uint64(12345), id)
	assert.Empty(t, email)
}

func TestGetUserIDAndEmail_FromBody(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"username": "z@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	id, email, err := getUserIDAndEmail(req)
	assert.NoError(t, err)
	assert.Equal(t, util.NewID([]byte("z@example.com")), id)
	assert.Equal(t, "z@example.com", email)
}

func TestGetUserIDAndEmail_NoHeaderNoBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, _, err := getUserIDAndEmail(req)
	assert.ErrorIs(t, err, ErrInvalidUserIDHeader)
}

func TestGetUserIDAndEmail_ParseUintRangeError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Id", "99999999999999999999999999999999999999")
	_, _, err := getUserIDAndEmail(req)
	assert.Error(t, err)
}

func TestDecodeXUserIDHeader_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err := decodeXUserIDHeader(req)
	assert.ErrorIs(t, err, ErrInvalidUserIDHeader)
}

func TestDecodeXUserIDHeader_OK(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("4242"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-User-Id", encoded)
	id, err := decodeXUserIDHeader(req)
	assert.NoError(t, err)
	assert.Equal(t, uint64(4242), id)
}

func TestDecodeFinishRegistrationBody_Success(t *testing.T) {
	body, _ := json.Marshal(quicbaassdk.FIDO2FinishRegistrationRequest{
		SessionID:       "sess-1",
		AttestationJSON: `{"id":"abc"}`,
	})
	out, err := decodeFinishRegistrationBody(bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, "sess-1", out.SessionID)
	assert.Equal(t, `{"id":"abc"}`, out.AttestationJSON)
}

func TestDecodeFinishRegistrationBody_Invalid(t *testing.T) {
	_, err := decodeFinishRegistrationBody(bytes.NewReader([]byte("invalid")))
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

func TestDecodeFinishAuthenticationBody_Success(t *testing.T) {
	body, _ := json.Marshal(quicbaassdk.FIDO2FinishAuthenticationRequest{
		SessionID:     "sess-2",
		AssertionJSON: `{"id":"z"}`,
	})
	out, err := decodeFinishAuthenticationBody(bytes.NewReader(body), "user@y")
	require.NoError(t, err)
	assert.Equal(t, "sess-2", out.SessionID)
	assert.Equal(t, `{"id":"z"}`, out.AssertionJSON)
	assert.Equal(t, "user@y", out.Username)
}

func TestDecodeFinishAuthenticationBody_Invalid(t *testing.T) {
	_, err := decodeFinishAuthenticationBody(bytes.NewReader([]byte("nope")), "x")
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

func TestErrorConstants(t *testing.T) {
	assert.Equal(t, "webauthn: invalid organization id", ErrInvalidOrganizationID.Error())
	assert.Equal(t, "webauthn: user already registered", ErrUserAlreadyExists.Error())
	assert.Equal(t, "webauthn: invalid user id header", ErrInvalidUserIDHeader.Error())
	assert.Equal(t, "webauthn: invalid user", ErrInvalidUserID.Error())
	assert.Equal(t, "webauthn: SDK WebAuthn client is required", ErrSDKClientRequired.Error())
	assert.Equal(t, "webauthn: invalid relying-party configuration", ErrInvalidConfig.Error())
}

func TestLoginRequest_JSONRoundtrip(t *testing.T) {
	out, err := json.Marshal(LoginRequest{Email: "x@y.z"})
	require.NoError(t, err)
	assert.Contains(t, string(out), `"username":"x@y.z"`)

	var lr LoginRequest
	require.NoError(t, json.Unmarshal([]byte(`{"username":"foo@bar"}`), &lr))
	assert.Equal(t, "foo@bar", lr.Email)
}

// =============================================================================
// Invitation + tenant orchestration coverage
// =============================================================================

type mockInvitationService struct{ mock.Mock }

func (m *mockInvitationService) Create(ctx context.Context, req *service.CreateInvitationRequest) (*entities.Invitation, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}
func (m *mockInvitationService) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}
func (m *mockInvitationService) GetByID(ctx context.Context, id uint64) (*entities.Invitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}
func (m *mockInvitationService) Accept(ctx context.Context, token string, userID uint64) error {
	return m.Called(ctx, token, userID).Error(0)
}
func (m *mockInvitationService) Revoke(ctx context.Context, id, revokerID uint64) error {
	return m.Called(ctx, id, revokerID).Error(0)
}
func (m *mockInvitationService) ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}
func (m *mockInvitationService) ListPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}
func (m *mockInvitationService) CleanupExpired(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}
func (m *mockInvitationService) Delete(ctx context.Context, id uint64) error {
	return m.Called(ctx, id).Error(0)
}

// withInvitations rewires the harness with a mock invitation service.
func (h *harness) withInvitations(t *testing.T) *mockInvitationService {
	t.Helper()
	inv := new(mockInvitationService)
	h.handler.invitationService = inv
	return inv
}

func TestValidateInvitation_NoServiceConfigured(t *testing.T) {
	h := newHarness(t)
	// invitationService is nil by default
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	h.writer.On("Error500", w, r, ErrInvitationServiceNotConfigured).Return()
	ok := h.handler.validateInvitation(w, r, "tok", "x@y")
	assert.False(t, ok)
	h.writer.AssertExpectations(t)
}

func TestValidateInvitation_LookupError_NotFound(t *testing.T) {
	h := newHarness(t)
	inv := h.withInvitations(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	inv.On("GetByToken", mock.Anything, "tok").
		Return(nil, service.ErrInvitationNotFound{Token: "tok"})
	h.writer.On("Error404", w, r, mock.Anything).Return()
	assert.False(t, h.handler.validateInvitation(w, r, "tok", "x@y"))
	h.writer.AssertExpectations(t)
}

func TestValidateInvitation_EmailMismatch(t *testing.T) {
	h := newHarness(t)
	inv := h.withInvitations(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	inv.On("GetByToken", mock.Anything, "tok").Return(&entities.Invitation{
		Token: "tok", Email: "other@example.com", Status: entities.InvitationStatusPending,
		ExpiresAt: futureTime(),
	}, nil)
	h.writer.On("Error400", w, r, ErrInvitationEmailMismatch).Return()
	assert.False(t, h.handler.validateInvitation(w, r, "tok", "user@example.com"))
	h.writer.AssertExpectations(t)
}

func TestValidateInvitation_AcceptedStatus(t *testing.T) {
	h := newHarness(t)
	inv := h.withInvitations(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	inv.On("GetByToken", mock.Anything, "tok").Return(&entities.Invitation{
		Token: "tok", Email: "a@b", Status: entities.InvitationStatusAccepted,
		ExpiresAt: futureTime(),
	}, nil)
	h.writer.On("Error400", w, r, ErrInvitationAlreadyAccepted).Return()
	assert.False(t, h.handler.validateInvitation(w, r, "tok", "a@b"))
	h.writer.AssertExpectations(t)
}

func TestValidateInvitation_Expired(t *testing.T) {
	h := newHarness(t)
	inv := h.withInvitations(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	inv.On("GetByToken", mock.Anything, "tok").Return(&entities.Invitation{
		Token: "tok", Email: "a@b", Status: entities.InvitationStatusPending,
		ExpiresAt: pastTime(),
	}, nil)
	h.writer.On("Error400", w, r, ErrInvitationExpired).Return()
	assert.False(t, h.handler.validateInvitation(w, r, "tok", "a@b"))
	h.writer.AssertExpectations(t)
}

func TestValidateInvitation_Pending_OK(t *testing.T) {
	h := newHarness(t)
	inv := h.withInvitations(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/registration/begin", nil)
	inv.On("GetByToken", mock.Anything, "tok").Return(&entities.Invitation{
		Token: "tok", Email: "a@b", Status: entities.InvitationStatusPending,
		ExpiresAt: futureTime(),
	}, nil)
	assert.True(t, h.handler.validateInvitation(w, r, "tok", "a@b"))
	h.writer.AssertNotCalled(t, "Error400", mock.Anything, mock.Anything, mock.Anything)
}

// =============================================================================
// IssueToken fallback coverage
// =============================================================================

type mockTenantUserService struct{ mock.Mock }

func (m *mockTenantUserService) RegisterNewUser(ctx context.Context, user *entities.User) (*service.RegisterResult, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.RegisterResult), args.Error(1)
}
func (m *mockTenantUserService) RegisterInvitedUser(ctx context.Context, user *entities.User, token string) (*service.RegisterResult, error) {
	args := m.Called(ctx, user, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.RegisterResult), args.Error(1)
}
func (m *mockTenantUserService) GetUserTenant(ctx context.Context, userID uint64) (*tenantEntity, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tenantEntity), args.Error(1)
}
func (m *mockTenantUserService) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}
func (m *mockTenantUserService) TransferOwnership(ctx context.Context, currentOwnerID, newOwnerID uint64) error {
	return m.Called(ctx, currentOwnerID, newOwnerID).Error(0)
}
func (m *mockTenantUserService) IssueToken(ctx context.Context, user *entities.User) (string, error) {
	args := m.Called(ctx, user)
	return args.String(0), args.Error(1)
}
func (m *mockTenantUserService) SetIAMMirror(_ service.IAMUserMirror) {}

func TestOrchestrateTenant_NoTenantService_SavesDirectly(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	user := &entities.User{ID: 1, Email: "a@b"}
	h.users.On("Save", mock.Anything, user).Return(nil)
	id, err := h.handler.orchestrateTenant(req, user, "")
	assert.NoError(t, err)
	assert.Empty(t, id)
	h.users.AssertExpectations(t)
}

func TestOrchestrateTenant_NewUser_TenantCreated(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	user := &entities.User{ID: 1, Email: "a@b"}
	tus.On("RegisterNewUser", mock.Anything, user).Return(&service.RegisterResult{
		User:   &entities.User{ID: 1, Email: "a@b", TenantID: "T-1"},
		Tenant: &tenantEntity{ID: "T-1"},
	}, nil)
	id, err := h.handler.orchestrateTenant(req, user, "")
	require.NoError(t, err)
	assert.Equal(t, "T-1", id)
	tus.AssertExpectations(t)
}

func TestOrchestrateTenant_InvitedUser_JoinsTenant(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	user := &entities.User{ID: 1, Email: "a@b"}
	tus.On("RegisterInvitedUser", mock.Anything, user, "tok").Return(&service.RegisterResult{
		User:   &entities.User{ID: 1, Email: "a@b", TenantID: "T-2"},
		Tenant: &tenantEntity{ID: "T-2"},
	}, nil)
	id, err := h.handler.orchestrateTenant(req, user, "tok")
	require.NoError(t, err)
	assert.Equal(t, "T-2", id)
	tus.AssertExpectations(t)
}

func TestOrchestrateTenant_NewUser_PropagatesError(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	user := &entities.User{ID: 1, Email: "a@b"}
	wantErr := service.ErrTenantCreationFailed{Cause: errors.New("boom")}
	tus.On("RegisterNewUser", mock.Anything, user).Return(nil, wantErr)
	_, err := h.handler.orchestrateTenant(req, user, "")
	assert.Error(t, err)
	tus.AssertExpectations(t)
}

func TestIssueToken_PrefersTenantUserService(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	user := &entities.User{ID: 1, Email: "a@b"}
	tus.On("IssueToken", mock.Anything, user).Return("tenant-token", nil)
	out, err := h.handler.issueToken(req, user)
	require.NoError(t, err)
	assert.Equal(t, "tenant-token", out)
}

func TestResolveTenantID_NilResult(t *testing.T) {
	user := &entities.User{}
	assert.Empty(t, resolveTenantID(user, nil))
}

func TestResolveTenantID_PopulatesUser(t *testing.T) {
	user := &entities.User{}
	updated := &entities.User{ID: 7, Email: "z@y", TenantID: "T-7"}
	out := resolveTenantID(user, &service.RegisterResult{User: updated, Tenant: &tenantEntity{ID: "T-7"}})
	assert.Equal(t, "T-7", out)
	assert.Equal(t, uint64(7), user.ID)
	assert.Equal(t, "T-7", user.TenantID)
}

// =============================================================================
// time helpers + type aliases
// =============================================================================

// futureTime returns a time 1 hour ahead so IsExpired returns false.
func futureTime() time.Time { return time.Now().UTC().Add(1 * time.Hour) }

// pastTime returns a time 1 hour ago so IsExpired returns true.
func pastTime() time.Time { return time.Now().UTC().Add(-1 * time.Hour) }

// tenantEntity is a local alias so the mock signatures remain readable
// without importing the heavyweight tenant package transitively.
type tenantEntity = tenant.TenantEntity
