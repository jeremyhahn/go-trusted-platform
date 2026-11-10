package webauthn

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// finishAfterAttestation builds a FinishRegistration request whose
// registration record resolves and whose attestation the SDK accepts, so
// each case exercises only what happens after a verified credential.
func finishAfterAttestation(t *testing.T, email, invitationToken string) (*harness, *httptest.ResponseRecorder, *http.Request, uint64) {
	t.Helper()
	h := newHarness(t)
	handle := []byte("sdk-handle-964-" + email)
	recordID := util.NewID(handle)
	body := []byte(`{"id":"cred-964","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"e30"}}`)
	req := httptest.NewRequest(http.MethodPost, "/registration/finish", bytes.NewReader(body))
	req.Header.Set("X-User-Id", base64.RawURLEncoding.EncodeToString(handle))
	req.Header.Set("X-Session-Id", "sess")
	w := httptest.NewRecorder()
	h.regs.On("Get", mock.Anything, mock.Anything, recordID).
		Return(&entities.Registration{ID: recordID, Email: email, InvitationToken: invitationToken}, nil)
	h.sdk.On("FinishRegistration", withTestTenant, mock.Anything).
		Return(&quicbaassdk.FIDO2FinishRegistrationResponse{Success: true, CredentialID: "cred-964"}, nil)
	return h, w, req, recordID
}

// TestFinishRegistration_AfterAttestation covers every outcome once the
// SDK has verified the credential: user lookup, tenant orchestration,
// pending-record cleanup and token issuance each fail closed with the
// status their error class maps to, and an existing user is reused.
func TestFinishRegistration_AfterAttestation(t *testing.T) {
	storeErr := errors.New("user store unavailable")
	deleteErr := errors.New("registration delete failed")
	issueErr := errors.New("token signer unavailable")
	invitationErr := service.ErrInvitationNotFound{Token: "inv-964"}

	tests := []struct {
		name            string
		invitationToken string
		arrange         func(h *harness, w *httptest.ResponseRecorder, req *http.Request, recordID uint64, userID uint64)
		verify          func(t *testing.T, h *harness)
	}{
		{
			name: "user lookup error is a 500 and no tenant is created",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, _ uint64, userID uint64) {
				h.users.On("Get", mock.Anything, userID).Return(nil, storeErr)
				h.writer.On("Error500", w, req, storeErr).Return()
			},
			verify: func(t *testing.T, h *harness) {
				h.tenants.AssertNotCalled(t, "RegisterNewUser", mock.Anything, mock.Anything)
			},
		},
		{
			name: "existing user is reused for tenant orchestration and the token",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, recordID uint64, userID uint64) {
				existing := &entities.User{ID: userID, Email: "existing@example.com", TenantID: "workspace-2"}
				h.users.On("Get", mock.Anything, userID).Return(existing, nil)
				h.tenants.On("RegisterNewUser", mock.Anything, mock.MatchedBy(func(u *entities.User) bool {
					return u == existing
				})).Return(&service.RegisterResult{Tenant: &tenantEntity{ID: "workspace-2"}}, nil)
				h.regs.On("Delete", mock.Anything, mock.Anything, recordID).Return(nil)
				h.tenants.On("IssueToken", mock.Anything, existing).Return("existing-token", nil)
				h.writer.On("Success200", w, req, FinishRegistrationResponse{Token: "existing-token", TenantID: "workspace-2"}).Return()
			},
		},
		{
			name:            "invitation not found is a 404 and the pending record is kept",
			invitationToken: "inv-964",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, _ uint64, userID uint64) {
				h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
				h.tenants.On("RegisterInvitedUser", mock.Anything, mock.Anything, "inv-964").Return(nil, invitationErr)
				h.writer.On("Error404", w, req, invitationErr).Return()
			},
			verify: func(t *testing.T, h *harness) {
				h.regs.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			name: "pending record delete error is a 500 and no token is issued",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, recordID uint64, userID uint64) {
				h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
				h.tenants.On("RegisterNewUser", mock.Anything, mock.Anything).
					Return(&service.RegisterResult{User: &entities.User{ID: userID, TenantID: "workspace-1"}, Tenant: &tenantEntity{ID: "workspace-1"}}, nil)
				h.regs.On("Delete", mock.Anything, mock.Anything, recordID).Return(deleteErr)
				h.writer.On("Error500", w, req, deleteErr).Return()
			},
			verify: func(t *testing.T, h *harness) {
				h.tenants.AssertNotCalled(t, "IssueToken", mock.Anything, mock.Anything)
			},
		},
		{
			name: "token issuance error is a 500",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, recordID uint64, userID uint64) {
				h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
				h.tenants.On("RegisterNewUser", mock.Anything, mock.Anything).
					Return(&service.RegisterResult{User: &entities.User{ID: userID, TenantID: "workspace-1"}, Tenant: &tenantEntity{ID: "workspace-1"}}, nil)
				h.regs.On("Delete", mock.Anything, mock.Anything, recordID).Return(nil)
				h.tenants.On("IssueToken", mock.Anything, mock.Anything).Return("", issueErr)
				h.writer.On("Error500", w, req, issueErr).Return()
			},
		},
		{
			name: "empty token is refused with ErrEmptyTenantToken",
			arrange: func(h *harness, w *httptest.ResponseRecorder, req *http.Request, recordID uint64, userID uint64) {
				h.users.On("Get", mock.Anything, userID).Return(nil, datastore.ErrRecordNotFound)
				h.tenants.On("RegisterNewUser", mock.Anything, mock.Anything).
					Return(&service.RegisterResult{User: &entities.User{ID: userID, TenantID: "workspace-1"}, Tenant: &tenantEntity{ID: "workspace-1"}}, nil)
				h.regs.On("Delete", mock.Anything, mock.Anything, recordID).Return(nil)
				h.tenants.On("IssueToken", mock.Anything, mock.Anything).Return("", nil)
				h.writer.On("Error500", w, req, ErrEmptyTenantToken).Return()
			},
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			email := "user" + strconv.Itoa(i) + "@example.com"
			h, w, req, recordID := finishAfterAttestation(t, email, tc.invitationToken)
			tc.arrange(h, w, req, recordID, util.NewID([]byte(email)))
			h.handler.FinishRegistration(w, req)
			h.users.AssertExpectations(t)
			h.tenants.AssertExpectations(t)
			h.regs.AssertExpectations(t)
			h.writer.AssertExpectations(t)
			if tc.verify != nil {
				tc.verify(t, h)
			}
		})
	}
}

// TestRegistrationStatus_OutOfRangeHeader_BadRequest: a numeric header
// that overflows uint64 is a malformed request, not "not_registered".
func TestRegistrationStatus_OutOfRangeHeader_BadRequest(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/registration/status", nil)
	req.Header.Set("X-User-Id", "99999999999999999999999")
	w := httptest.NewRecorder()
	h.writer.On("Error400", w, req, mock.MatchedBy(func(err error) bool {
		return errors.Is(err, strconv.ErrRange)
	})).Return()
	h.handler.RegistrationStatus(w, req)
	h.writer.AssertExpectations(t)
	h.users.AssertNotCalled(t, "Get", mock.Anything, mock.Anything)
}

// TestDecodeXUserIDHeader_Malformed: a header that is not base64url, or
// that decodes to a non-numeric value, is rejected with no user ID.
func TestDecodeXUserIDHeader_Malformed(t *testing.T) {
	tests := []struct {
		name   string
		header string
		target error
	}{
		{name: "not base64url", header: "!!!not-base64!!!"},
		{name: "decodes to non-numeric", header: base64.RawURLEncoding.EncodeToString([]byte("abc")), target: strconv.ErrSyntax},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-User-Id", tc.header)
			id, err := decodeXUserIDHeader(req)
			require.Error(t, err)
			assert.Zero(t, id)
			if tc.target != nil {
				assert.ErrorIs(t, err, tc.target)
			}
			assert.NotErrorIs(t, err, ErrInvalidUserIDHeader)
		})
	}
}
