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
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
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

// testTenantID is the ceremony tenant every harness handler is scoped to.
const testTenantID = "tenant-system-test"

// withTestTenant matches a context carrying the harness ceremony tenant —
// the regression assertion for the "tenant is required" failure: every SDK
// ceremony call must be tenant-scoped.
var withTestTenant = mock.MatchedBy(func(ctx context.Context) bool {
	return sdktransport.TenantFromContext(ctx) == testTenantID
})

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
		TenantID:            testTenantID,
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
		TenantID:    testTenantID,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)

	_, err = NewHandler(ServiceParams{
		Config:      &Config{RPID: ""},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
		TenantID:    testTenantID,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)

	_, err = NewHandler(ServiceParams{
		Config:      &Config{RPID: "x", RPOrigins: nil},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
		TenantID:    testTenantID,
	})
	assert.ErrorIs(t, err, ErrInvalidConfig)
}

// TestNewHandler_RequiresTenantID verifies the handler fails closed at
// construction when no ceremony tenant is supplied: the SDK FIDO2 service
// rejects unscoped calls, so an unscoped handler could never complete a
// ceremony.
func TestNewHandler_RequiresTenantID(t *testing.T) {
	sdk := new(mockFIDO2Client)
	_, err := NewHandler(ServiceParams{
		Config:      &Config{RPID: "x", RPOrigins: []string{"https://x"}},
		Logger:      logging.NewLogger(slog.LevelDebug, os.Stderr),
		FIDO2Client: sdk,
	})
	assert.ErrorIs(t, err, ErrTenantIDRequired)
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
	h.sdk.On("BeginRegistration", withTestTenant, mock.AnythingOfType("*transport.BeginRegistrationRequest")).
		Return(&quicbaassdk.FIDO2BeginRegistrationResponse{
			SessionID:   "sess",
			OptionsJSON: `{"publicKey":{"rp":{"id":"localhost"},"user":{"id":"c2RrLWhhbmRsZQ","name":"alice@example.com"},"challenge":"test"}}`,
		}, nil)
	// The pending registration is keyed by the digest of the SDK user
	// handle — the one identifier the browser echoes back — and carries
	// NO ceremony state: the SDK session ID rides the begin payload.
	handleDigest := util.NewID([]byte("sdk-handle"))
	h.regs.On("Create", mock.Anything, mock.MatchedBy(func(reg *entities.Registration) bool {
		return len(reg.SessionData) == 0 && reg.Email == "alice@example.com" &&
			reg.ID == handleDigest
	})).Return(nil)
	// The browser receives the PARSED options with the SDK user handle
	// untouched (the SDK validates it as the assertion userHandle at
	// login).
	h.writer.On("Write", w, req, http.StatusOK, mock.MatchedBy(func(v interface{}) bool {
		options, ok := v.(map[string]interface{})
		if !ok {
			return false
		}
		publicKey, ok := options["publicKey"].(map[string]interface{})
		if !ok {
			return false
		}
		encoded, _ := publicKey["user"].(map[string]interface{})["id"].(string)
		return encoded == base64.RawURLEncoding.EncodeToString([]byte("sdk-handle"))
	})).Return()

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
		Return(&quicbaassdk.FIDO2BeginRegistrationResponse{SessionID: "sess", OptionsJSON: `{"publicKey":{"rp":{"id":"x"},"user":{"id":"aGFuZGxl"},"challenge":"x"}}`}, nil)
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
	handle := []byte("sdk-handle-lookup-fails")
	recordID := util.NewID(handle)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).Return(nil, datastore.ErrRecordNotFound)
	h.writer.On("Error404", w, req, datastore.ErrRecordNotFound).Return()
	h.handler.FinishRegistration(w, req)
	h.regs.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_InvalidBody(t *testing.T) {
	h := newHarness(t)
	handle := []byte("sdk-handle-invalid-body")
	recordID := util.NewID(handle)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader([]byte("nope")))
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).
		Return(&entities.Registration{ID: recordID, Email: "x@example.com"}, nil)
	h.writer.On("Error400", w, req, ErrInvalidRequestBody).Return()
	h.handler.FinishRegistration(w, req)
	h.writer.AssertExpectations(t)
}

func TestFinishRegistration_SDKError(t *testing.T) {
	h := newHarness(t)
	handle := []byte("sdk-handle-sdk-error")
	recordID := util.NewID(handle)
	// The browser posts the RAW attestation JSON; the persisted ceremony
	// session correlates it with the SDK.
	body := []byte(`{"id":"cred-x","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	sdkErr := errors.New("attestation invalid")
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).
		Return(&entities.Registration{ID: recordID, Email: "y@example.com"}, nil)
	h.sdk.On("FinishRegistration", withTestTenant, mock.MatchedBy(func(req *quicbaassdk.FIDO2FinishRegistrationRequest) bool {
		return req.SessionID == "sess" && req.AttestationJSON == string(body)
	})).Return(nil, sdkErr)
	h.writer.On("Error400", w, req, sdkErr).Return()
	h.handler.FinishRegistration(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// finishRegistrationRejection exercises the fail-closed guard: an
// error-free SDK response that does not affirm Success must never
// create a user or issue a token.
func finishRegistrationRejection(t *testing.T, resp *quicbaassdk.FIDO2FinishRegistrationResponse) {
	h := newHarness(t)
	handle := []byte("sdk-handle-rejected")
	recordID := util.NewID(handle)
	body := []byte(`{"id":"cred-r","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).
		Return(&entities.Registration{ID: recordID, Email: "r@example.com"}, nil)
	h.sdk.On("FinishRegistration", withTestTenant, mock.Anything).Return(resp, nil)
	h.writer.On("Error400", w, req, ErrAuthenticationFailed).Return()
	h.handler.FinishRegistration(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
	h.users.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
}

func TestFinishRegistration_SuccessFalse_FailsClosed(t *testing.T) {
	finishRegistrationRejection(t, &quicbaassdk.FIDO2FinishRegistrationResponse{Success: false, CredentialID: "cred-r"})
}

func TestFinishRegistration_NilResponse_FailsClosed(t *testing.T) {
	finishRegistrationRejection(t, nil)
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
	h.sdk.On("BeginAuthentication", withTestTenant, mock.AnythingOfType("*transport.BeginAuthenticationRequest")).
		Return(&quicbaassdk.FIDO2BeginAuthenticationResponse{SessionID: "sess", OptionsJSON: `{"publicKey":{"challenge":"auth"}}`}, nil)
	// The parsed object carries publicKey, the user_id the /auth/login
	// page reads from the body, and the SDK session_id the browser
	// echoes back on finish via the X-Session-Id header.
	h.writer.On("Write", w, req, http.StatusOK, mock.MatchedBy(func(v interface{}) bool {
		options, ok := v.(map[string]interface{})
		return ok && options["publicKey"] != nil &&
			options["user_id"] == strconv.FormatUint(user.ID, 10) &&
			options["session_id"] == "sess"
	})).Return()
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

func TestFinishLogin_Success_IssuesPlatformToken(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	username := "ok@example.com"
	user := entities.NewUser(username)
	body := []byte(`{"id":"cred-9","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", withTestTenant, mock.MatchedBy(func(req *quicbaassdk.FIDO2FinishAuthenticationRequest) bool {
		return req.SessionID == "sess" && req.Username == username && req.AssertionJSON == string(body)
	})).Return(&quicbaassdk.FIDO2FinishAuthenticationResponse{Success: true, Token: "sdk-opaque-token"}, nil)
	// The SDK token is never surfaced; the platform issues its own JWT.
	tus.On("IssueToken", mock.Anything, user).Return("platform-jwt", nil)
	h.writer.On("Success200", w, req, "platform-jwt").Return()
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
	body := []byte(`{"id":"cred-bad","type":"public-key"}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	sdkErr := errors.New("assertion bad")
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", mock.Anything, mock.Anything).Return(nil, sdkErr)
	h.writer.On("Error400", w, req, sdkErr).Return()
	h.handler.FinishLogin(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
}

// finishLoginRejection exercises the fail-closed guard: an error-free
// SDK response that does not affirm Success must never issue a JWT.
func finishLoginRejection(t *testing.T, resp *quicbaassdk.FIDO2FinishAuthenticationResponse) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	username := "reject@example.com"
	user := entities.NewUser(username)
	body := []byte(`{"id":"cred-r","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", withTestTenant, mock.Anything).Return(resp, nil)
	h.writer.On("Error400", w, req, ErrAuthenticationFailed).Return()
	h.handler.FinishLogin(w, req)
	h.sdk.AssertExpectations(t)
	h.writer.AssertExpectations(t)
	tus.AssertNotCalled(t, "IssueToken", mock.Anything, mock.Anything)
}

// TestFinishLogin_MissingSessionHeader proves a finish without the
// X-Session-Id ceremony header fails closed before the SDK is called.
func TestFinishLogin_MissingSessionHeader(t *testing.T) {
	h := newHarness(t)
	username := "nosess@example.com"
	user := entities.NewUser(username)
	body := []byte(`{"id":"cred-n","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.writer.On("Error400", w, req, ErrCeremonySessionMissing).Return()
	h.handler.FinishLogin(w, req)
	h.sdk.AssertNotCalled(t, "FinishAuthentication", mock.Anything, mock.Anything)
	h.writer.AssertExpectations(t)
}

// TestFinishRegistration_MissingSessionHeader proves the same guard on
// the registration finish path.
func TestFinishRegistration_MissingSessionHeader(t *testing.T) {
	h := newHarness(t)
	handle := []byte("sdk-handle-no-session")
	recordID := util.NewID(handle)
	body := []byte(`{"id":"cred-n","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).
		Return(&entities.Registration{ID: recordID, Email: "n@example.com"}, nil)
	h.writer.On("Error400", w, req, ErrCeremonySessionMissing).Return()
	h.handler.FinishRegistration(w, req)
	h.sdk.AssertNotCalled(t, "FinishRegistration", mock.Anything, mock.Anything)
	h.writer.AssertExpectations(t)
}

func TestFinishLogin_SuccessFalse_FailsClosed(t *testing.T) {
	finishLoginRejection(t, &quicbaassdk.FIDO2FinishAuthenticationResponse{Success: false})
}

func TestFinishLogin_NilResponse_FailsClosed(t *testing.T) {
	finishLoginRejection(t, nil)
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

func TestDecodeFinishRegistrationBody_Invalid(t *testing.T) {
	_, err := decodeFinishRegistrationBody(bytes.NewReader([]byte("invalid")), "sess")
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

// TestDecodeFinishRegistrationBody_BrowserShape proves the raw WebAuthn
// attestation JSON a browser posts (navigator.credentials.create() output,
// no session-model wrapper) is accepted and correlated with the ceremony
// session persisted at begin time.
func TestDecodeFinishRegistrationBody_BrowserShape(t *testing.T) {
	raw := `{"id":"cred-1","rawId":"cred-1","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}`
	out, err := decodeFinishRegistrationBody(bytes.NewReader([]byte(raw)), "sess-from-begin")
	require.NoError(t, err)
	assert.Equal(t, "sess-from-begin", out.SessionID)
	assert.JSONEq(t, raw, out.AttestationJSON)
}

// TestDecodeFinishRegistrationBody_BrowserShapeNoSession fails closed when
// the browser shape arrives but no ceremony session was persisted: the
// ceremony cannot be correlated, so the client must restart it.
func TestDecodeFinishRegistrationBody_BrowserShapeNoSession(t *testing.T) {
	raw := `{"id":"cred-1","type":"public-key"}`
	_, err := decodeFinishRegistrationBody(bytes.NewReader([]byte(raw)), "")
	assert.ErrorIs(t, err, ErrCeremonySessionMissing)
}

func TestDecodeFinishAuthenticationBody_Invalid(t *testing.T) {
	_, err := decodeFinishAuthenticationBody(bytes.NewReader([]byte("nope")), "x", "sess")
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

// TestDecodeFinishAuthenticationBody_BrowserShape proves the raw WebAuthn
// assertion JSON a browser posts is accepted, stamped with the username,
// and correlated with the persisted ceremony session.
func TestDecodeFinishAuthenticationBody_BrowserShape(t *testing.T) {
	raw := `{"id":"cred-9","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`
	out, err := decodeFinishAuthenticationBody(bytes.NewReader([]byte(raw)), "user@y", "sess-login")
	require.NoError(t, err)
	assert.Equal(t, "sess-login", out.SessionID)
	assert.Equal(t, "user@y", out.Username)
	assert.JSONEq(t, raw, out.AssertionJSON)
}

// TestDecodeFinishAuthenticationBody_BrowserShapeNoSession fails closed
// when no login ceremony session was persisted for the user.
func TestDecodeFinishAuthenticationBody_BrowserShapeNoSession(t *testing.T) {
	_, err := decodeFinishAuthenticationBody(bytes.NewReader([]byte(`{"id":"x"}`)), "u", "")
	assert.ErrorIs(t, err, ErrCeremonySessionMissing)
}

// TestParseCreationOptions proves the SDK options are returned as a
// parsed object with the SDK's user handle left UNTOUCHED (the
// authenticator stores it and the SDK validates it at login), and that the
// decoded handle bytes are returned for the handler to derive the
// registration correlation key.
func TestParseCreationOptions(t *testing.T) {
	optionsJSON := `{"publicKey":{"rp":{"id":"cp.trusted-platform.io","name":"TP"},"user":{"id":"c2RrLW9wYXF1ZS1oYW5kbGU","name":"jeremy","displayName":"jeremy"},"challenge":"abc"}}`
	out, handle, err := parseCreationOptions(optionsJSON)
	require.NoError(t, err)
	publicKey := out["publicKey"].(map[string]interface{})
	user := publicKey["user"].(map[string]interface{})
	assert.Equal(t, "c2RrLW9wYXF1ZS1oYW5kbGU", user["id"], "the SDK user handle must not be rewritten")
	assert.Equal(t, []byte("sdk-opaque-handle"), handle)
	assert.Equal(t, "cp.trusted-platform.io", publicKey["rp"].(map[string]interface{})["id"])
}

// TestParseCreationOptions_Malformed rejects options without the expected
// publicKey/user structure or an undecodable handle.
func TestParseCreationOptions_Malformed(t *testing.T) {
	_, _, err := parseCreationOptions(`{"nope":true}`)
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
	_, _, err = parseCreationOptions(`not-json`)
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
	_, _, err = parseCreationOptions(`{"publicKey":{"user":{"id":""}}}`)
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

// TestRegistrationKeyFromHeader resolves both accepted header shapes: the
// legacy base64url decimal platform id, and the browser-echoed SDK user
// handle whose digest keys the pending registration.
func TestRegistrationKeyFromHeader(t *testing.T) {
	// Browser shape: opaque handle -> digest.
	handle := []byte("sdk-opaque-handle")
	req2 := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	req2.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	id2, err := registrationKeyFromHeader(req2)
	require.NoError(t, err)
	assert.Equal(t, util.NewID(handle), id2)

	// Missing / undecodable headers fail.
	req3 := httptest.NewRequest(http.MethodPost, "/registration/finish", nil)
	_, err = registrationKeyFromHeader(req3)
	assert.ErrorIs(t, err, ErrInvalidUserIDHeader)
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

// TestReadCredentialBody_Boundaries pins the size cap on the
// unauthenticated finish endpoints: a body at the limit passes, one
// byte over fails closed with the typed error.
func TestReadCredentialBody_Boundaries(t *testing.T) {
	pad := bytes.Repeat([]byte(" "), maxCredentialBodyBytes-2)
	atLimit := append([]byte("{}"), pad...)
	require.Len(t, atLimit, maxCredentialBodyBytes)
	raw, err := readCredentialBody(bytes.NewReader(atLimit))
	require.NoError(t, err)
	assert.Len(t, raw, maxCredentialBodyBytes)

	over := append(atLimit, ' ')
	_, err = readCredentialBody(bytes.NewReader(over))
	assert.ErrorIs(t, err, ErrRequestBodyTooLarge)

	_, err = readCredentialBody(bytes.NewReader([]byte("not-json")))
	assert.ErrorIs(t, err, ErrInvalidRequestBody)
}

// TestIsNotFoundError_AllShapes pins the classifier across the three
// not-found error families the platform stores speak.
func TestIsNotFoundError_AllShapes(t *testing.T) {
	assert.True(t, isNotFoundError(datastore.ErrRecordNotFound))
	assert.True(t, isNotFoundError(kvstore.ErrNotFound{EntityType: "user", ID: 1}))
	assert.True(t, isNotFoundError(kvstore.ErrNotFoundByIndex{EntityType: "user", IndexField: "Email", Value: "x"}))
	assert.False(t, isNotFoundError(errors.New("kv backend unavailable")))
	assert.False(t, isNotFoundError(nil))
}

// TestFinishLogin_TenantIssuerError proves a tenant-token failure after
// a successful ceremony fails closed with a 500 — never an unscoped JWT.
func TestFinishLogin_TenantIssuerError(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	username := "tenantfail@example.com"
	user := entities.NewUser(username)
	body := []byte(`{"id":"cred-t","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	issueErr := errors.New("tenant claims unavailable")
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", withTestTenant, mock.Anything).
		Return(&quicbaassdk.FIDO2FinishAuthenticationResponse{Success: true}, nil)
	tus.On("IssueToken", mock.Anything, user).Return("", issueErr)
	h.writer.On("Error500", w, req, issueErr).Return()
	h.handler.FinishLogin(w, req)
	h.writer.AssertExpectations(t)
	h.writer.AssertNotCalled(t, "Success200", mock.Anything, mock.Anything, mock.Anything)
}

// TestFinishLogin_TenantIssuerEmptyToken proves an empty tenant token is
// a typed 500, never a silent downgrade to the unscoped JWT service.
func TestFinishLogin_TenantIssuerEmptyToken(t *testing.T) {
	h := newHarness(t)
	tus := new(mockTenantUserService)
	h.handler.tenantUserService = tus
	username := "emptytoken@example.com"
	user := entities.NewUser(username)
	body := []byte(`{"id":"cred-e","type":"public-key","response":{"clientDataJSON":"e30","authenticatorData":"e30","signature":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/login/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", strconv.FormatUint(user.ID, 10))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.users.On("Get", mock.Anything, user.ID).Return(user, nil)
	h.sdk.On("FinishAuthentication", withTestTenant, mock.Anything).
		Return(&quicbaassdk.FIDO2FinishAuthenticationResponse{Success: true}, nil)
	tus.On("IssueToken", mock.Anything, user).Return("", nil)
	h.writer.On("Error500", w, req, ErrEmptyTenantToken).Return()
	h.handler.FinishLogin(w, req)
	h.writer.AssertExpectations(t)
	h.writer.AssertNotCalled(t, "Success200", mock.Anything, mock.Anything, mock.Anything)
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
