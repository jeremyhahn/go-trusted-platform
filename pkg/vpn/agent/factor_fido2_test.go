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

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// fakeAuthenticator stands in for the SDK's FIDO2 handler: it answers the
// request options with a PublicKeyCredential document whose clientDataJSON
// carries the options' challenge, as a CTAP2 authenticator's would.
type fakeAuthenticator struct {
	options   fido2RequestOptions
	origin    string
	answer    []byte
	assertErr error
	closeErr  error
	closed    bool
}

func (a *fakeAuthenticator) AssertWithOptionsAndOrigin(_ context.Context, optionsJSON []byte, origin string) ([]byte, error) {
	a.origin = origin
	if err := json.Unmarshal(optionsJSON, &a.options); err != nil {
		return nil, err
	}
	if a.assertErr != nil || a.answer != nil {
		return a.answer, a.assertErr
	}
	credentialID := "ZGlzY292ZXJhYmxl"
	if len(a.options.AllowCredentials) > 0 {
		credentialID = a.options.AllowCredentials[0].ID
	}
	clientData, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": a.options.Challenge,
		"origin":    origin,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":    credentialID,
		"rawId": credentialID,
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": "YXV0aERhdGE",
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"signature":         "c2lnbmF0dXJl",
		},
	})
}

func (a *fakeAuthenticator) Close() error {
	a.closed = true
	return a.closeErr
}

func fakeFIDO2Signer(t *testing.T, opts FIDO2SignerOptions, authenticator *fakeAuthenticator) *FIDO2Signer {
	t.Helper()
	s, err := NewFIDO2Signer(opts)
	require.NoError(t, err)
	s.open = func() (fido2Assertor, error) { return authenticator, nil }
	return s
}

// noAuthenticators is a host with no FIDO2 authenticator attached.
type noAuthenticators struct{}

func (noAuthenticators) Enumerate(uint16, uint16) ([]fido2.HIDDevice, error) { return nil, nil }

func (noAuthenticators) Open(string) (fido2.HIDDevice, error) { return nil, &errFake{"open"} }

// verifiedChallenge reads a fido2 factor as the gateway receives it and
// returns the challenge its clientDataJSON was signed over, checking the
// fields a WebAuthn verifier checks before the signature.
func verifiedChallenge(t *testing.T, wire *gwvpn.PersonFactorWire, rpID string) []byte {
	t.Helper()
	body, err := json.Marshal(wire)
	require.NoError(t, err)
	var received gwvpn.PersonFactorWire
	require.NoError(t, json.Unmarshal(body, &received))
	factor := received.PersonFactor()
	require.Equal(t, gwvpn.PersonFactorFIDO2, factor.Kind)

	var credential struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON string `json:"clientDataJSON"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(factor.Assertion, &credential))
	require.Equal(t, factor.CredentialID, credential.ID, "the factor names the credential that asserted")
	require.Equal(t, "public-key", credential.Type)
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(credential.Response.ClientDataJSON)
	require.NoError(t, err)
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	require.NoError(t, json.Unmarshal(clientDataJSON, &clientData))
	require.Equal(t, "webauthn.get", clientData.Type)
	require.Equal(t, "https://"+rpID, clientData.Origin)
	challenge, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	require.NoError(t, err)
	return challenge
}

func TestFIDO2Signer_AssertsOverTheSessionNonce(t *testing.T) {
	authenticator := &fakeAuthenticator{}
	s := fakeFIDO2Signer(t, FIDO2SignerOptions{RPID: "auth.example.com", CredentialID: "Y3JlZC0x"}, authenticator)
	nonce := []byte("session-nonce-\x00\xff")

	factor, err := s.Sign(context.Background(), gwvpn.PersonFactorFIDO2, nonce)

	require.NoError(t, err)
	assert.Equal(t, "Y3JlZC0x", factor.CredentialID)
	assert.Equal(t, nonce, verifiedChallenge(t, gwvpn.PersonFactorToWire(factor), "auth.example.com"),
		"the assertion is bound to the gateway's nonce")
	assert.Equal(t, "auth.example.com", authenticator.options.RPID)
	assert.Equal(t, "https://auth.example.com", authenticator.origin, "the RP's same-origin default")
	assert.Equal(t, []fido2CredentialDesc{{Type: "public-key", ID: "Y3JlZC0x"}}, authenticator.options.AllowCredentials)
	assert.Equal(t, "discouraged", authenticator.options.UserVerification, "a touch, not a PIN")
	assert.True(t, authenticator.closed)
}

func TestFIDO2Signer_WithoutACredentialIDTheAuthenticatorPicks(t *testing.T) {
	authenticator := &fakeAuthenticator{}
	s := fakeFIDO2Signer(t, FIDO2SignerOptions{RPID: "auth.example.com"}, authenticator)

	factor, err := s.Sign(context.Background(), gwvpn.PersonFactorFIDO2, []byte("nonce-1"))

	require.NoError(t, err)
	assert.Empty(t, authenticator.options.AllowCredentials)
	assert.Equal(t, "ZGlzY292ZXJhYmxl", factor.CredentialID, "the discoverable credential that asserted")
}

func TestFIDO2Signer_NoAuthenticatorIsErrAuthenticator(t *testing.T) {
	s, err := newFIDO2Signer(FIDO2SignerOptions{RPID: "auth.example.com"}, noAuthenticators{})
	require.NoError(t, err)

	_, err = s.Sign(context.Background(), gwvpn.PersonFactorFIDO2, []byte("nonce-1"))

	var authErr *ErrAuthenticator
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, gwvpn.PersonFactorFIDO2, authErr.Factor)
	assert.ErrorContains(t, err, "no FIDO2 device found", "the SDK accepted the request options and looked for a device")
}

func TestFIDO2Signer_RefusesAnotherFactor(t *testing.T) {
	authenticator := &fakeAuthenticator{}
	s := fakeFIDO2Signer(t, FIDO2SignerOptions{RPID: "auth.example.com"}, authenticator)

	_, err := s.Sign(context.Background(), gwvpn.PersonFactorPIV, []byte("nonce-1"))

	var unsupported *ErrFactorUnsupported
	require.ErrorAs(t, err, &unsupported)
	assert.Equal(t, gwvpn.PersonFactorPIV, unsupported.Factor)
	assert.False(t, authenticator.closed, "the authenticator is never opened")
}

func TestFIDO2Signer_AuthenticatorFailures(t *testing.T) {
	tests := []struct {
		name          string
		authenticator *fakeAuthenticator
		want          any
	}{
		{"no touch", &fakeAuthenticator{assertErr: &errFake{"touch"}}, new(*ErrAuthenticator)},
		{"not json", &fakeAuthenticator{answer: []byte("not json")}, new(*ErrInvalidAssertion)},
		{"no credential id", &fakeAuthenticator{answer: []byte(`{"type":"public-key"}`)}, new(*ErrInvalidAssertion)},
		{"close fails", &fakeAuthenticator{closeErr: &errFake{"close"}}, new(*ErrAuthenticator)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeFIDO2Signer(t, FIDO2SignerOptions{RPID: "auth.example.com"}, tt.authenticator)

			_, err := s.Sign(context.Background(), gwvpn.PersonFactorFIDO2, []byte("nonce-1"))

			require.ErrorAs(t, err, tt.want)
			assert.True(t, tt.authenticator.closed)
		})
	}
}

func TestFIDO2Signer_OpenFailureIsErrAuthenticator(t *testing.T) {
	s := fakeFIDO2Signer(t, FIDO2SignerOptions{RPID: "auth.example.com"}, nil)
	s.open = func() (fido2Assertor, error) { return nil, &errFake{"open"} }

	_, err := s.Sign(context.Background(), gwvpn.PersonFactorFIDO2, []byte("nonce-1"))

	var authErr *ErrAuthenticator
	require.ErrorAs(t, err, &authErr)
	var cause *errFake
	assert.True(t, errors.As(err, &cause))
}

func TestNewFIDO2Signer_RejectsBadOptions(t *testing.T) {
	tests := []struct {
		name  string
		opts  FIDO2SignerOptions
		field string
	}{
		{"no rp id", FIDO2SignerOptions{CredentialID: "Y3JlZC0x"}, "fido2 rp id"},
		{"padded credential id", FIDO2SignerOptions{RPID: "auth.example.com", CredentialID: "Y3JlZA=="}, "fido2 credential id"},
		{"not base64url", FIDO2SignerOptions{RPID: "auth.example.com", CredentialID: "cred/1+"}, "fido2 credential id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFIDO2Signer(tt.opts)

			var invalid *ErrInvalidOptions
			require.ErrorAs(t, err, &invalid)
			assert.Equal(t, tt.field, invalid.Field)
		})
	}
}
