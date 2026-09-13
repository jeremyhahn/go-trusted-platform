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
	"crypto"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssueSessionProjectsTheBackboneIdentity pins which claims a
// backbone-issued session carries, because every one of them is read
// somewhere downstream: the seam republishes subject, tenant and roles to
// the RBAC guards, and the console refuses to consider itself signed in
// without a subject and an email.
func TestIssueSessionProjectsTheBackboneIdentity(t *testing.T) {
	handler := newHandlerForLoginTest(t)

	bearer, expiresAt, err := handler.jwtService.IssueSession(&quicbaas.Identity{
		Subject:  "operator@platform",
		TenantID: "tenant-a",
		Roles:    []string{"admin", "operator"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, bearer)
	expected := time.Now().Add(
		time.Minute * time.Duration(handler.jwtService.params.Expiration))
	assert.WithinDuration(t, expected, expiresAt, time.Minute,
		"the credential expires on the service's configured schedule")

	token, err := handler.jwtService.ParseTokenString(bearer)
	require.NoError(t, err, "the credential must verify against this service's own key")
	require.NoError(t, handler.jwtService.Verify(token),
		"the credential must pass the same validation a protected route runs")

	claims, ok := token.Claims.(*TokenClaims)
	require.True(t, ok)
	assert.Equal(t, "operator@platform", claims.Subject)
	assert.Equal(t, "operator@platform", claims.UserIDStr)
	assert.Equal(t, "operator@platform", claims.Email)
	assert.Equal(t, "tenant-a", claims.TenantID)
	assert.Equal(t, []string{"admin", "operator"}, claims.Roles)
	// "uid" keys the PLATFORM user store and the backbone's subject keys a
	// different one, so it is deliberately left unset rather than filled
	// with an identifier from the wrong namespace.
	assert.Zero(t, claims.UserID)
}

// TestIssueSessionRefusesAnIncompleteIdentity covers the inputs that would
// produce a credential with an undefined principal or an undefined blast
// radius. Each must fail issuance rather than mint something weaker.
func TestIssueSessionRefusesAnIncompleteIdentity(t *testing.T) {
	handler := newHandlerForLoginTest(t)

	for name, testCase := range map[string]struct {
		identity *quicbaas.Identity
		want     error
	}{
		"no identity": {identity: nil, want: ErrIdentityRequired},
		"no subject": {
			identity: &quicbaas.Identity{TenantID: "tenant-a"},
			want:     ErrIdentitySubjectRequired,
		},
		"no tenant": {
			identity: &quicbaas.Identity{Subject: "operator@platform"},
			want:     ErrIdentityTenantRequired,
		},
	} {
		t.Run(name, func(t *testing.T) {
			bearer, expiresAt, err := handler.jwtService.IssueSession(testCase.identity)
			assert.ErrorIs(t, err, testCase.want)
			assert.Empty(t, bearer, "no credential may escape a refused issuance")
			assert.True(t, expiresAt.IsZero())
		})
	}
}

// TestIssueSessionOnANilServiceRefuses covers the zero value: a service
// that was never constructed has no signer, and must say so rather than
// panic inside the driver's finish path.
func TestIssueSessionOnANilServiceRefuses(t *testing.T) {
	var service *Service

	_, _, err := service.IssueSession(&quicbaas.Identity{
		Subject: "operator@platform", TenantID: "tenant-a",
	})
	assert.ErrorIs(t, err, ErrIdentityRequired)
}

// TestIssuedSessionIsRejectedByAForeignSigner is the control that makes
// the acceptance tests mean something: the credential verifies because
// THIS service signed it, not because the seam accepts anything.
func TestIssuedSessionIsRejectedByAForeignSigner(t *testing.T) {
	issuing := newHandlerForLoginTest(t)
	verifying := newHandlerForLoginTest(t)

	bearer, _, err := issuing.jwtService.IssueSession(&quicbaas.Identity{
		Subject: "operator@platform", TenantID: "tenant-a",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/users", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()

	reached := false
	verifying.Verify(w, req, func(http.ResponseWriter, *http.Request) { reached = true })

	assert.False(t, reached, "a credential from another signer must not be accepted")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// failingSigner is a crypto.Signer that refuses to sign, which is how a
// platform whose key material has become unreachable behaves mid-request.
type failingSigner struct {
	public crypto.PublicKey
}

func (s failingSigner) Public() crypto.PublicKey { return s.public }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

// TestIssueSessionSurfacesASigningFailure covers the other half of the
// issuance contract: the identity is complete and the ceremony succeeded,
// but the platform cannot sign. Nothing may be returned as a credential,
// and the error must reach the driver, which reports it as a platform
// fault rather than a rejected login.
func TestIssueSessionSurfacesASigningFailure(t *testing.T) {
	working := newHandlerForLoginTest(t).jwtService
	broken := &Service{
		params:        working.params,
		signingMethod: working.signingMethod,
		signer:        failingSigner{public: working.signer.Public()},
	}

	bearer, expiresAt, err := broken.IssueSession(&quicbaas.Identity{
		Subject: "operator@platform", TenantID: "tenant-a",
	})
	require.Error(t, err)
	assert.Empty(t, bearer)
	assert.True(t, expiresAt.IsZero())
}
