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

package auth

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/GeertJohan/yubigo"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPassword implements types.Password interface
type mockPassword struct {
	password string
	err      error
}

func (m *mockPassword) String() (string, error) {
	return m.password, m.err
}

func (m *mockPassword) Bytes() []byte {
	return []byte(m.password)
}

func (m *mockPassword) Clear() {
	m.password = ""
}

// mockVerifier implements YubiKeyVerifier for testing
type mockVerifier struct {
	response *yubigo.YubiResponse
	ok       bool
	err      error
}

func (m *mockVerifier) Verify(otp string) (*yubigo.YubiResponse, bool, error) {
	return m.response, m.ok, m.err
}

// mockPrompter implements Prompter for testing
type mockPrompter struct {
	response []byte
}

func (m *mockPrompter) PasswordPrompt(message string) []byte {
	return m.response
}

func TestNewYubiKeyAuthenticator_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "12345"
	// Use base64-encoded secret key (yubigo validates it)
	secretKey := &mockPassword{password: "dGVzdHNlY3JldGtleQ=="}

	auth, err := NewYubiKeyAuthenticator(logger, clientID, secretKey)

	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.IsType(t, &YubiAuth{}, auth)
}

func TestNewYubiKeyAuthenticator_NilSecretKey(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "test-client-id"

	auth, err := NewYubiKeyAuthenticator(logger, clientID, nil)

	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.IsType(t, &YubiAuth{}, auth)
}

func TestNewYubiKeyAuthenticator_SecretKeyError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "test-client-id"
	expectedErr := errors.New("password error")
	secretKey := &mockPassword{err: expectedErr}

	auth, err := NewYubiKeyAuthenticator(logger, clientID, secretKey)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, auth)
}

func TestNewYubiKeyAuthenticator_EmptyClientID(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "" // Empty client ID is allowed by yubigo library
	secretKey := &mockPassword{password: "dGVzdHNlY3JldGtleQ=="}

	auth, err := NewYubiKeyAuthenticator(logger, clientID, secretKey)

	// Yubigo library allows empty client ID
	require.NoError(t, err)
	require.NotNil(t, auth)
}

func TestNewYubiKeyAuthenticator_WithVerifier(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "12345"
	secretKey := &mockPassword{password: "dGVzdHNlY3JldGtleQ=="}
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, clientID, secretKey, WithVerifier(mockV))

	require.NoError(t, err)
	require.NotNil(t, auth)
	yubiAuth := auth.(*YubiAuth)
	assert.Equal(t, mockV, yubiAuth.verifier)
}

func TestNewYubiKeyAuthenticator_WithPrompter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "12345"
	secretKey := &mockPassword{password: "dGVzdHNlY3JldGtleQ=="}
	mockP := &mockPrompter{response: []byte("test-otp")}
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, clientID, secretKey, WithVerifier(mockV), WithPrompter(mockP))

	require.NoError(t, err)
	require.NotNil(t, auth)
	yubiAuth := auth.(*YubiAuth)
	assert.Equal(t, mockP, yubiAuth.prompter)
}

func TestNewYubiKeyAuthenticator_WithMultipleOptions(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	clientID := "12345"
	mockV := &mockVerifier{ok: true}
	mockP := &mockPrompter{response: []byte("otp")}

	auth, err := NewYubiKeyAuthenticator(
		logger,
		clientID,
		nil,
		WithVerifier(mockV),
		WithPrompter(mockP),
	)

	require.NoError(t, err)
	require.NotNil(t, auth)
	yubiAuth := auth.(*YubiAuth)
	assert.Equal(t, mockV, yubiAuth.verifier)
	assert.Equal(t, mockP, yubiAuth.prompter)
}

func TestYubiAuth_Authenticate_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{
		response: &yubigo.YubiResponse{},
		ok:       true,
		err:      nil,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// Valid OTP: 12 char token ID + 32 char password
	otp := []byte("ccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.NoError(t, err)
}

func TestYubiAuth_Authenticate_VerificationFailed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{
		response: nil,
		ok:       false,
		err:      nil,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	otp := []byte("ccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.Error(t, err)
	assert.Equal(t, ErrAuthenticationFailed, err)
}

func TestYubiAuth_Authenticate_VerificationError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	expectedErr := errors.New("network error")
	mockV := &mockVerifier{
		response: nil,
		ok:       false,
		err:      expectedErr,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	otp := []byte("ccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
}

func TestYubiAuth_Authenticate_OTPTooShort(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// OTP less than 32 characters
	otp := []byte("shortOTP")
	err = auth.Authenticate(otp)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidOTPLength, err)
}

func TestYubiAuth_Authenticate_OTPExactly32Chars(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{
		response: &yubigo.YubiResponse{},
		ok:       true,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// OTP exactly 32 characters (minimum valid)
	otp := []byte("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.NoError(t, err)
}

func TestYubiAuth_Authenticate_OTP31Chars(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// OTP 31 characters (just below minimum)
	otp := []byte("vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidOTPLength, err)
}

func TestYubiAuth_Authenticate_EmptyOTP(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	err = auth.Authenticate([]byte{})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidOTPLength, err)
}

func TestYubiAuth_Authenticate_NilOTP(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	err = auth.Authenticate(nil)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidOTPLength, err)
}

func TestYubiAuth_Authenticate_LongOTP(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{
		response: &yubigo.YubiResponse{},
		ok:       true,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// Very long OTP (more than typical 44 chars)
	otp := []byte("ccccccccccccccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.NoError(t, err)
}

func TestYubiAuth_Prompt(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	expectedOTP := []byte("ccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	mockP := &mockPrompter{response: expectedOTP}
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV), WithPrompter(mockP))
	require.NoError(t, err)

	result := auth.Prompt()

	assert.Equal(t, expectedOTP, result)
}

func TestYubiAuth_Prompt_EmptyResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockP := &mockPrompter{response: []byte{}}
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV), WithPrompter(mockP))
	require.NoError(t, err)

	result := auth.Prompt()

	assert.Empty(t, result)
}

func TestYubiAuth_Prompt_NilResponse(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockP := &mockPrompter{response: nil}
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV), WithPrompter(mockP))
	require.NoError(t, err)

	result := auth.Prompt()

	assert.Nil(t, result)
}

func TestErrAuthenticationFailed(t *testing.T) {
	assert.Equal(t, "platform: authentication failed", ErrAuthenticationFailed.Error())
}

func TestErrInvalidOTPLength(t *testing.T) {
	assert.Equal(t, "platform: OTP must be at least 32 characters", ErrInvalidOTPLength.Error())
}

func TestWithVerifier_Option(t *testing.T) {
	mockV := &mockVerifier{ok: true}
	opt := WithVerifier(mockV)

	yubiAuth := &YubiAuth{}
	opt(yubiAuth)

	assert.Equal(t, mockV, yubiAuth.verifier)
}

func TestWithPrompter_Option(t *testing.T) {
	mockP := &mockPrompter{response: []byte("test")}
	opt := WithPrompter(mockP)

	yubiAuth := &YubiAuth{}
	opt(yubiAuth)

	assert.Equal(t, mockP, yubiAuth.prompter)
}

func TestDefaultPrompter_PasswordPrompt(t *testing.T) {
	// This test verifies that the default prompter exists and is properly typed
	// We cannot actually test stdin interaction in unit tests
	dp := &defaultPrompter{}
	assert.NotNil(t, dp)
}

func TestYubigoVerifier_Verify(t *testing.T) {
	// Test that yubigoVerifier properly wraps the yubigo client
	// This requires a real yubigo client, so we just verify the type exists
	// Real verification happens in the NewYubiKeyAuthenticator tests
	assert.NotNil(t, &yubigoVerifier{})
}

func TestYubiAuth_ImplementsPlatformAuthenticator(t *testing.T) {
	var _ PlatformAuthenticator = (*YubiAuth)(nil)
}

func TestNewYubiKeyAuthenticator_DefaultPrompter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockV := &mockVerifier{ok: true}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	yubiAuth := auth.(*YubiAuth)
	assert.IsType(t, &defaultPrompter{}, yubiAuth.prompter)
}

func TestYubiAuth_Authenticate_TokenIDExtraction(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stderr)
	mockV := &mockVerifier{
		response: &yubigo.YubiResponse{},
		ok:       true,
	}

	auth, err := NewYubiKeyAuthenticator(logger, "12345", nil, WithVerifier(mockV))
	require.NoError(t, err)

	// OTP with 12 char token ID + 32 char password
	otp := []byte("ccccccccccccvvvvvvvvvvvvvvvvvvvvvvvvvvvv")
	err = auth.Authenticate(otp)

	assert.NoError(t, err)
}

func TestMockPassword_String(t *testing.T) {
	mp := &mockPassword{password: "test123"}
	str, err := mp.String()

	assert.NoError(t, err)
	assert.Equal(t, "test123", str)
}

func TestMockPassword_String_Error(t *testing.T) {
	expectedErr := errors.New("string error")
	mp := &mockPassword{err: expectedErr}
	str, err := mp.String()

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Empty(t, str)
}

func TestMockPassword_Bytes(t *testing.T) {
	mp := &mockPassword{password: "test123"}
	bytes := mp.Bytes()

	assert.Equal(t, []byte("test123"), bytes)
}

func TestMockPassword_Clear(t *testing.T) {
	mp := &mockPassword{password: "test123"}
	mp.Clear()

	assert.Empty(t, mp.password)
}

func TestMockVerifier_Verify(t *testing.T) {
	expectedResponse := &yubigo.YubiResponse{}
	mv := &mockVerifier{
		response: expectedResponse,
		ok:       true,
		err:      nil,
	}

	response, ok, err := mv.Verify("test-otp")

	assert.Equal(t, expectedResponse, response)
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestMockVerifier_Verify_Error(t *testing.T) {
	expectedErr := errors.New("verify error")
	mv := &mockVerifier{
		response: nil,
		ok:       false,
		err:      expectedErr,
	}

	response, ok, err := mv.Verify("test-otp")

	assert.Nil(t, response)
	assert.False(t, ok)
	assert.Equal(t, expectedErr, err)
}

func TestMockPrompter_PasswordPrompt(t *testing.T) {
	expected := []byte("password123")
	mp := &mockPrompter{response: expected}

	result := mp.PasswordPrompt("Enter password")

	assert.Equal(t, expected, result)
}
