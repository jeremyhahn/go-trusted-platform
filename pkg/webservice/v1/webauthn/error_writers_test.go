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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestWriteInvitationError_NotFound(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	invErr := service.ErrInvitationNotFound{Token: "abc"}
	mockWriter.On("Error404", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationNotFound)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, invErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationError_Expired(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	invErr := service.ErrInvitationExpired{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationExpired)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, invErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationError_AlreadyAccepted(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	invErr := service.ErrInvitationAlreadyAccepted{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationAlreadyAccepted)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, invErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationError_Revoked(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	invErr := service.ErrInvitationRevoked{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationRevoked)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, invErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationError_InvalidInvitation(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	invErr := service.ErrInvalidInvitation{Reason: "bad"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvalidInvitation)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, invErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationError_DefaultFallback(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	genericErr := service.ErrTokenIssueFailed{Cause: assert.AnError}
	mockWriter.On("Error500", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrTokenIssueFailed)
		return ok
	})).Once()

	handler.writeInvitationError(w, r, genericErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationStatusError_Accepted(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	mockWriter.On("Error400", w, r, ErrInvitationAlreadyAccepted).Once()

	handler.writeInvitationStatusError(w, r, entities.InvitationStatusAccepted)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationStatusError_Revoked(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	mockWriter.On("Error400", w, r, ErrInvitationRevoked).Once()

	handler.writeInvitationStatusError(w, r, entities.InvitationStatusRevoked)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationStatusError_Expired(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	mockWriter.On("Error400", w, r, ErrInvitationExpired).Once()

	handler.writeInvitationStatusError(w, r, entities.InvitationStatusExpired)
	mockWriter.AssertExpectations(t)
}

func TestWriteInvitationStatusError_DefaultFallback(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/test", nil)

	mockWriter.On("Error400", w, r, ErrInvalidInvitationStatus).Once()

	handler.writeInvitationStatusError(w, r, entities.InvitationStatusPending)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_UserAlreadyExists(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrUserAlreadyExists{Email: "test@example.com"}
	mockWriter.On("Write", w, r, http.StatusConflict, mock.AnythingOfType("response.WebServiceResponse")).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_InvitationNotFound(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrInvitationNotFound{Token: "abc"}
	mockWriter.On("Error404", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationNotFound)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_InvitationExpired(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrInvitationExpired{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationExpired)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_InvitationAlreadyAccepted(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrInvitationAlreadyAccepted{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationAlreadyAccepted)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_InvitationRevoked(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrInvitationRevoked{Token: "abc"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvitationRevoked)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_InvalidInvitation(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrInvalidInvitation{Reason: "bad"}
	mockWriter.On("Error400", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrInvalidInvitation)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_TenantCreationFailed(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrTenantCreationFailed{Cause: assert.AnError}
	mockWriter.On("Error500", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrTenantCreationFailed)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_UserSaveFailed(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	regErr := service.ErrUserSaveFailed{Cause: assert.AnError}
	mockWriter.On("Error500", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrUserSaveFailed)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, regErr)
	mockWriter.AssertExpectations(t)
}

func TestWriteRegistrationError_DefaultFallback(t *testing.T) {
	handler, _, _, _, mockWriter := createTestHandler(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/test", nil)

	genericErr := service.ErrTokenIssueFailed{Cause: assert.AnError}
	mockWriter.On("Error500", w, r, mock.MatchedBy(func(err error) bool {
		_, ok := err.(service.ErrTokenIssueFailed)
		return ok
	})).Once()

	handler.writeRegistrationError(w, r, genericErr)
	mockWriter.AssertExpectations(t)
}
