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
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {

	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Generate the key using the full XKMS (which has GenerateKey)
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	// Test successful service creation
	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.NotNil(t, service.signer)
	assert.NotNil(t, service.signingMethod)
}

func TestNewService_SignerError(t *testing.T) {
	params := testServiceParams()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	// Don't generate key - should cause signer error
	service, err := NewService(context.Background(), params)
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
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	// Modify KeyAttrs to have an unsupported/invalid signature algorithm
	// combination that will cause NewSigningMethodSigner to fail
	params.KeyAttrs.SignatureAlgorithm = x509.SignatureAlgorithm(999) // Invalid algorithm
	params.KeyAttrs.KeyAlgorithm = x509.PublicKeyAlgorithm(999)       // Invalid key algorithm

	// This should fail at NewSigningMethodSigner due to unsupported algorithm
	service, err := NewService(context.Background(), params)
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
	service, err := NewService(context.Background(), params)
	assert.NotNil(t, err)
	assert.Nil(t, service)
}

func TestParseToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)

	// Generate a valid token
	user := entities.NewUser("test@localhost")
	user.ID = 12345
	tokenString, err := service.GenerateToken(user)
	assert.Nil(t, err)

	// Create a request with the token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	// Parse the token
	token, claims, err := service.ParseToken(req)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	assert.NotNil(t, claims)
	assert.True(t, token.Valid)
	userID, err := claims.PlatformUserID()
	assert.NoError(t, err)
	assert.Equal(t, uint64(12345), userID)
}

func TestParseToken_MissingAuthHeader(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)

	// Create a request without Authorization header
	req := httptest.NewRequest("GET", "/test", nil)

	// Parse the token
	token, claims, err := service.ParseToken(req)
	assert.Equal(t, ErrAuthorizationHeaderRequired, err)
	assert.Nil(t, token)
	assert.Nil(t, claims)
}

func TestVerifyTokenClaims_ReturnsVerifiedPrincipal(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)
	service, err := NewService(context.Background(), params)
	require.NoError(t, err)

	user := entities.NewUser("test@localhost")
	user.ID = 12345
	user.TenantID = "acme"
	user.Roles = []*entities.Role{{Name: "operator"}}
	tokenString, err := service.GenerateToken(user)
	require.NoError(t, err)

	claims, err := service.VerifyTokenClaims("Bearer " + tokenString)
	require.NoError(t, err)
	assert.Equal(t, "12345", claims.UserIDStr)
	assert.Equal(t, "acme", claims.TenantID)
	assert.Equal(t, []string{"operator"}, claims.Roles)
}

func TestVerifyTokenClaims_RejectsInvalidTokens(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)
	service, err := NewService(context.Background(), params)
	require.NoError(t, err)

	for name, token := range map[string]string{
		"empty":        "",
		"bearer only":  "Bearer ",
		"not a jwt":    "not-a-jwt",
		"wrong format": "a.b.c",
	} {
		t.Run(name, func(t *testing.T) {
			claims, err := service.VerifyTokenClaims(token)
			assert.Error(t, err)
			assert.Nil(t, claims)
		})
	}

	var nilService *Service
	_, err = nilService.VerifyTokenClaims("x")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestParseToken_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)

	// Create a request with invalid token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	// Parse the token
	token, claims, err := service.ParseToken(req)
	assert.NotNil(t, err)
	assert.Nil(t, token)
	assert.Nil(t, claims)
}

func TestParseTokenString(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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
	userID, err := claims.PlatformUserID()
	assert.NoError(t, err)
	assert.Equal(t, uint64(67890), userID)
}

// newTestService returns a Service signing with a freshly generated key.
func newTestService(t *testing.T) *Service {
	t.Helper()
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)
	service, err := NewService(context.Background(), params)
	require.NoError(t, err)
	return service
}

// hostileUser returns a user whose store key is above 2^53, the largest
// integer a float64 holds exactly. User ids are xxhash64 (util.NewID), so
// almost every real id is in this range; a small id would hide a float64
// round-trip (#642).
func hostileUser(t *testing.T) *entities.User {
	t.Helper()
	user := entities.NewUser("issue-642@hostile.example")
	require.Greater(t, user.ID, uint64(1)<<53)
	require.NotEqual(t, user.ID, uint64(float64(user.ID)),
		"the id must change under a float64 round-trip to be hostile")
	return user
}

// A consumer that decodes the claims without a schema (golang-jwt's
// MapClaims, the web console's JSON.parse) turns every JSON number into a
// float64. The platform user id must therefore travel as a decimal string,
// or such a consumer reads a different user (#642).
func TestGenerateToken_HostileUserIDSurvivesASchemalessDecode(t *testing.T) {
	service := newTestService(t)
	user := hostileUser(t)

	tokenString, err := service.GenerateToken(user)
	require.NoError(t, err)

	token, err := jwt.Parse(tokenString, service.KeyFunc)
	require.NoError(t, err)
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	want := strconv.FormatUint(user.ID, 10)
	for _, name := range []string{"uid", "user_id", "sub"} {
		got, ok := mapClaims[name].(string)
		require.Truef(t, ok, "%q claim is %T %v, want the decimal string %s",
			name, mapClaims[name], mapClaims[name], want)
		assert.Equal(t, want, got, name)
	}
}

// The server's own reader: the real issuer, then the real parser, must
// hand back exactly the id that was issued.
func TestParseToken_HostileUserIDRoundTrips(t *testing.T) {
	service := newTestService(t)
	user := hostileUser(t)

	tokenString, err := service.GenerateToken(user)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	_, claims, err := service.ParseToken(req)
	require.NoError(t, err)
	userID, err := claims.PlatformUserID()
	require.NoError(t, err)
	assert.Equal(t, user.ID, userID)
	assert.Equal(t, strconv.FormatUint(user.ID, 10), claims.UserIDStr)
}

func TestPlatformUserID_RejectsAMissingOrMalformedClaim(t *testing.T) {
	for name, uid := range map[string]string{
		"missing":       "",
		"not a number":  "operator@platform",
		"negative":      "-1",
		"float":         "6.339618737788534e+18",
		"above uint64":  "18446744073709551616",
		"leading space": " 42",
	} {
		t.Run(name, func(t *testing.T) {
			claims := &TokenClaims{UID: uid}
			id, err := claims.PlatformUserID()
			assert.ErrorIs(t, err, ErrInvalidUserClaim)
			assert.Zero(t, id)
		})
	}
}

func TestParseTokenString_InvalidToken(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)

	// Parse invalid token string
	token, err := service.ParseTokenString("invalid.token.string")
	assert.NotNil(t, err)
	assert.Nil(t, token)
}

func TestKeyFunc(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
	assert.Nil(t, err)

	// PublicKey should return the signer's public key
	pubKey := service.PublicKey()
	assert.NotNil(t, pubKey)
	assert.Equal(t, service.signer.Public(), pubKey)
}

func TestServiceVerify(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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

	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	assert.Nil(t, err)

	service, err := NewService(context.Background(), params)
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

// TestRequestToken covers the two carriers the platform's two first-class
// clients use, their precedence, and the short-header case that used to
// panic on a slice out of range.
func TestRequestToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		cookies map[string]string
		want    string
	}{
		{"bearer header", "Bearer abc", nil, "abc"},
		{"bearer header with padding", "Bearer   abc  ", nil, "abc"},
		{"a bare token is NOT accepted", "abc", nil, ""},
		{"header shorter than the prefix", "x", nil, ""},
		{"wrong scheme", "Basic abc", nil, ""},
		{"lowercase scheme is not the scheme", "bearer abc", nil, ""},
		{"a bare header falls through to the cookie", "abc",
			map[string]string{"jwt": "cookie-token"}, "cookie-token"},
		{"bearer with nothing after it", "Bearer ", nil, ""},
		{"empty header", "", nil, ""},
		{"jwt cookie", "", map[string]string{"jwt": "cookie-token"}, "cookie-token"},
		{"token cookie", "", map[string]string{"token": "alt-token"}, "alt-token"},
		{"jwt cookie wins over token cookie", "",
			map[string]string{"token": "alt", "jwt": "primary"}, "primary"},
		{"header wins over cookie", "Bearer header-token",
			map[string]string{"jwt": "cookie-token"}, "header-token"},
		{"empty cookie value is ignored", "",
			map[string]string{"jwt": "", "token": "alt"}, "alt"},
		{"nothing at all", "", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/x", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			for name, value := range tt.cookies {
				req.AddCookie(&http.Cookie{Name: name, Value: value})
			}
			assert.Equal(t, tt.want, requestToken(req))
		})
	}
}

// TestParseToken_AcceptsTheConsoleCookie is the console's path end to end:
// the SDK client sends credentials, not an Authorization header.
func TestParseToken_AcceptsTheConsoleCookie(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	service, err := NewService(context.Background(), params)
	require.NoError(t, err)

	user := entities.NewUser("admin")
	user.TenantID = "system"
	tokenString, err := service.GenerateToken(user)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "jwt", Value: tokenString})

	token, claims, err := service.ParseToken(req)
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "system", claims.TenantID)
}

func TestParseToken_NoCredential(t *testing.T) {
	params, ks := testServiceParamsWithXKMS()
	params.KeyAttrs.KeyType = xkmssdk.KeyTypeTLS
	_, err := ks.GenerateKey(context.Background(), params.KeyAttrs)
	require.NoError(t, err)

	service, err := NewService(context.Background(), params)
	require.NoError(t, err)

	_, _, err = service.ParseToken(
		httptest.NewRequest("GET", "/protected", nil))
	assert.ErrorIs(t, err, ErrAuthorizationHeaderRequired)
}
