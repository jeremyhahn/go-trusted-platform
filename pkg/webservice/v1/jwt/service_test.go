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
	"crypto/x509"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
)

func TestGenerateToken(t *testing.T) {

	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Generate the key using the full XKMS (which has GenerateKey)
	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)
	assert.NotNil(t, service)

	user := entities.NewUser("root@localhost")
	token, err := service.GenerateToken(user)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	fmt.Println(token)
}

func TestNewService(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Generate the key
	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	// Test successful service creation
	service, err := NewService(params)
	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.NotNil(t, service.signer)
	assert.NotNil(t, service.signingMethod)
}

func TestNewService_SignerError(t *testing.T) {
	params := testServiceParams()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Don't generate key - should cause signer error
	service, err := NewService(params)
	assert.NotNil(t, err)
	assert.Nil(t, service)
}

// TestNewService_SigningMethodError tests the NewService function when
// NewSigningMethodSigner fails due to unsupported algorithm configuration.
// This covers the error path at service.go:78-80.
func TestNewService_SigningMethodError(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Generate a valid key first
	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	// Modify KeyAttrs to have an unsupported/invalid signature algorithm
	// combination that will cause NewSigningMethodSigner to fail
	params.KeyAttrs.SignatureAlgorithm = x509.SignatureAlgorithm(999) // Invalid algorithm
	params.KeyAttrs.KeyAlgorithm = x509.PublicKeyAlgorithm(999)       // Invalid key algorithm

	// This should fail at NewSigningMethodSigner due to unsupported algorithm
	service, err := NewService(params)
	assert.NotNil(t, err)
	assert.Nil(t, service)
}

// TestNewService_UnsupportedAlgorithm tests NewService with an unsupported
// public key algorithm to trigger the signing method error path.
func TestNewService_UnsupportedAlgorithm(t *testing.T) {
	ks := createXKMS()
	defer ks.Close()

	// Create params with unsupported algorithm that will fail signing method creation
	keyAttrs := &xkmssdk.KeyAttributes{
		CN:                 "unsupported-test",
		Debug:              true,
		Hash:               crypto.SHA256,
		KeyAlgorithm:       x509.DSA, // DSA is not supported for JWT signing
		KeyType:            xkmssdk.KeyTypeTLS,
		SignatureAlgorithm: x509.DSAWithSHA256,
		StoreType:          xkmssdk.StoreSoftware,
	}

	params := ServiceParams{
		Audience:   "localhost",
		Issuer:     "localhost",
		Expiration: 3600,
		KeyAttrs:   keyAttrs,
		XKMS:       ks,
	}

	// This should fail because DSA is not a supported JWT signing algorithm
	service, err := NewService(params)
	assert.NotNil(t, err)
	assert.Nil(t, service)
}

func TestParseToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Create a request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	// Parse the token
	token, claims, err := service.ParseToken(w, req)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	assert.NotNil(t, claims)
	assert.True(t, token.Valid)
	assert.Equal(t, uint64(12345), claims.UserID)
}

func TestParseToken_MissingAuthHeader(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Create a request without Authorization header
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Parse the token
	token, claims, err := service.ParseToken(w, req)
	assert.Equal(t, ErrAuthorizationHeaderRequired, err)
	assert.Nil(t, token)
	assert.Nil(t, claims)
}

func TestParseToken_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Create a request with invalid token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()

	// Parse the token
	token, claims, err := service.ParseToken(w, req)
	assert.NotNil(t, err)
	assert.Nil(t, token)
	assert.Nil(t, claims)
}

func TestParseTokenString(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 67890
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Parse the token string
	token, err := service.ParseTokenString(tokenString)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(*TokenClaims)
	assert.True(t, ok)
	assert.Equal(t, uint64(67890), claims.UserID)
}

func TestParseTokenString_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Parse invalid token string
	token, err := service.ParseTokenString("invalid.token.string")
	assert.NotNil(t, err)
	assert.Nil(t, token)
}

func TestKeyFunc(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// KeyFunc should return the public key
	key, err := service.KeyFunc(nil)
	assert.Nil(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, service.signer.Public(), key)
}

func TestPublicKey(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// PublicKey should return the signer's public key
	pubKey := service.PublicKey()
	assert.NotNil(t, pubKey)
	assert.Equal(t, service.signer.Public(), pubKey)
}

func TestServiceVerify(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Parse and verify the token
	token, err := service.ParseTokenString(tokenString)
	assert.Nil(t, err)

	err = service.Verify(token)
	assert.Nil(t, err)
}

func TestServiceVerify_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Parse the token
	token, err := service.ParseTokenString(tokenString)
	assert.Nil(t, err)

	// Manually mark token as invalid
	token.Valid = false

	err = service.Verify(token)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestServiceVerify_WrongAudience(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	params.Audience = "localhost"

	_, err := ks.GenerateKey(params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Parse the token
	token, err := service.ParseTokenString(tokenString)
	assert.Nil(t, err)

	// Change service audience to make validation fail
	service.params.Audience = "wrongaudience"

	err = service.Verify(token)
	assert.NotNil(t, err)
}

// TestServiceErrors tests the error sentinel values are properly defined.
func TestServiceErrors(t *testing.T) {
	assert.NotNil(t, ErrAuthorizationHeaderRequired)
	assert.NotNil(t, ErrInvalidToken)
	assert.NotNil(t, ErrInvalidUserClaim)
	assert.NotNil(t, ErrInvalidEmailClaim)

	assert.Equal(t, "jwt/service: authorization header required", ErrAuthorizationHeaderRequired.Error())
	assert.Equal(t, "jwt/service: invalid token", ErrInvalidToken.Error())
	assert.Equal(t, "jwt/service: invalid user id claim", ErrInvalidUserClaim.Error())
	assert.Equal(t, "jwt/service: invalid email claim", ErrInvalidEmailClaim.Error())
}

// TestServiceParams_Validation tests the ServiceParams structure.
func TestServiceParams_Validation(t *testing.T) {
	params := ServiceParams{
		Audience:   "test-audience",
		Expiration: 3600,
		Issuer:     "test-issuer",
	}

	assert.Equal(t, "test-audience", params.Audience)
	assert.Equal(t, 3600, params.Expiration)
	assert.Equal(t, "test-issuer", params.Issuer)
}

// TestTokenClaims_WebAuthn tests the TokenClaims with WebAuthn session data.
func TestTokenClaims_WebAuthn(t *testing.T) {
	claims := &TokenClaims{
		Organizations:  []uint64{1, 2},
		Services:       []uint64{3, 4},
		UserID:         100,
		WebAuthnClaims: nil, // WebAuthn claims can be nil
	}

	assert.Nil(t, claims.WebAuthnClaims)
	assert.Equal(t, uint64(100), claims.UserID)
	assert.Equal(t, []uint64{1, 2}, claims.Organizations)
	assert.Equal(t, []uint64{3, 4}, claims.Services)
}
