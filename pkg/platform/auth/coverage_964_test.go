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
	"io"
	"testing"

	"github.com/GeertJohan/yubigo"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cov964PasswordReadErr is the error the fake terminal returns.
type cov964PasswordReadErr struct{}

func (cov964PasswordReadErr) Error() string { return "cov964: terminal read failed" }

// cov964PasswordReader behaves like a terminal read: it returns the bytes
// typed for the descriptor it is given, or its error.
type cov964PasswordReader struct {
	password []byte
	err      error
	gotFd    int
}

func (r *cov964PasswordReader) ReadPassword(fd int) ([]byte, error) {
	r.gotFd = fd
	if r.err != nil {
		return nil, r.err
	}
	return r.password, nil
}

// cov964Password is an xkmssdk.Password whose String() returns a fixed value.
type cov964Password struct {
	value string
}

func (p *cov964Password) String() (string, error) { return p.value, nil }
func (p *cov964Password) Bytes() []byte           { return []byte(p.value) }
func (p *cov964Password) Clear()                  { p.value = "" }

func TestCov964_DefaultPrompter_PasswordPrompt_ReturnsReaderBytes(t *testing.T) {
	const stdinFd = 7
	otp := []byte("cccccccccccbnrgbibkcfjulbgrbtdhjhtjtjnrtvlbe")
	reader := &cov964PasswordReader{password: otp}
	p := &defaultPrompter{prompter: prompt.NewPrompter(
		prompt.WithPasswordReader(reader),
		prompt.WithWriter(io.Discard),
		prompt.WithStdinFd(stdinFd),
	)}

	got, err := p.PasswordPrompt("YubiKey OTP")

	require.NoError(t, err)
	assert.Equal(t, otp, got)
	assert.Equal(t, stdinFd, reader.gotFd)
}

func TestCov964_DefaultPrompter_PasswordPrompt_ReturnsReaderError(t *testing.T) {
	reader := &cov964PasswordReader{err: cov964PasswordReadErr{}}
	p := &defaultPrompter{prompter: prompt.NewPrompter(
		prompt.WithPasswordReader(reader),
		prompt.WithWriter(io.Discard),
	)}

	got, err := p.PasswordPrompt("YubiKey OTP")

	require.Error(t, err)
	assert.Nil(t, got)
	var readErr *prompt.PasswordReadError
	assert.True(t, errors.As(err, &readErr))
	assert.True(t, errors.Is(err, cov964PasswordReadErr{}))
}

func TestCov964_YubigoVerifier_Verify_RejectsMalformedOTP(t *testing.T) {
	client, err := yubigo.NewYubiAuth("12345", "dGVzdHNlY3JldGtleQ==")
	require.NoError(t, err)
	v := &yubigoVerifier{client: client}

	tests := []struct {
		name string
		otp  string
	}{
		{name: "shorter than 32 characters", otp: "cccccccbnrgb"},
		{name: "outside the modhex alphabet", otp: "cccccccccccbnrgbibkcfjulbgrbtdhjhtjtjnrtvlbz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, ok, err := v.Verify(tt.otp)

			assert.Error(t, err)
			assert.False(t, ok)
			assert.Nil(t, resp)
		})
	}
}

func TestCov964_NewYubiKeyAuthenticator_InvalidBase64Secret(t *testing.T) {
	authenticator, err := NewYubiKeyAuthenticator(nil, "12345", &cov964Password{value: "!!not-base64!!"})

	require.Error(t, err)
	assert.Nil(t, authenticator)
}

func TestCov964_NewYubiKeyAuthenticator_ValidSecretBuildsYubigoVerifier(t *testing.T) {
	authenticator, err := NewYubiKeyAuthenticator(nil, "12345", &cov964Password{value: "dGVzdHNlY3JldGtleQ=="})

	require.NoError(t, err)
	yubiAuth, ok := authenticator.(*YubiAuth)
	require.True(t, ok)
	verifier, ok := yubiAuth.verifier.(*yubigoVerifier)
	require.True(t, ok)
	assert.NotNil(t, verifier.client)
	assert.IsType(t, &defaultPrompter{}, yubiAuth.prompter)
}
