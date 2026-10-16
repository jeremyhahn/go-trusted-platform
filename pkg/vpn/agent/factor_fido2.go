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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/fido2"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// FIDO2SignerOptions select the credential a FIDO2 signer asserts with.
type FIDO2SignerOptions struct {
	// RPID is the WebAuthn relying party the person's credential is
	// registered under. Required.
	RPID string
	// CredentialID is the credential to assert with, unpadded base64url.
	// Empty lets the authenticator pick a discoverable credential for RPID.
	CredentialID string
}

// fido2Assertor is the SDK's FIDO2 handler as the signer uses it.
type fido2Assertor interface {
	AssertWithOptions(ctx context.Context, optionsJSON []byte) ([]byte, error)
	Close() error
}

// FIDO2Signer is the FactorSigner for the fido2 person factor: a WebAuthn
// assertion over the gateway's session nonce, made by a FIDO2 authenticator
// attached to this host through the SDK's fido2 handler. It asks for user
// presence (a touch), not user verification, so no PIN is sent.
type FIDO2Signer struct {
	rpID         string
	credentialID []byte
	open         func() (fido2Assertor, error)
}

// NewFIDO2Signer returns a signer over the first FIDO2 authenticator attached
// to this host.
func NewFIDO2Signer(opts FIDO2SignerOptions) (*FIDO2Signer, error) {
	return newFIDO2Signer(opts, fido2.NewDefaultEnumerator())
}

func newFIDO2Signer(opts FIDO2SignerOptions, devices fido2.HIDDeviceEnumerator) (*FIDO2Signer, error) {
	if opts.RPID == "" {
		return nil, &ErrInvalidOptions{Field: "fido2 rp id", Reason: "required"}
	}
	var credentialID []byte
	if opts.CredentialID != "" {
		id, err := base64.RawURLEncoding.DecodeString(opts.CredentialID)
		if err != nil {
			return nil, &ErrInvalidOptions{Field: "fido2 credential id", Reason: "want unpadded base64url: " + err.Error()}
		}
		credentialID = id
	}
	open := func() (fido2Assertor, error) {
		cfg := fido2.DefaultConfig
		cfg.RelyingPartyID = opts.RPID
		handler, err := fido2.NewHandler(&cfg, devices)
		if err != nil {
			return nil, err
		}
		return handler, nil
	}
	return &FIDO2Signer{rpID: opts.RPID, credentialID: credentialID, open: open}, nil
}

// fido2RequestOptions are the WebAuthn PublicKeyCredentialRequestOptions the
// SDK handler asserts over; the challenge is the session nonce.
type fido2RequestOptions struct {
	Challenge        string                `json:"challenge"`
	RPID             string                `json:"rpId"`
	AllowCredentials []fido2CredentialDesc `json:"allowCredentials,omitempty"`
	UserVerification string                `json:"userVerification"`
}

type fido2CredentialDesc struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Sign asserts over nonce. The factor's Assertion is the WebAuthn
// PublicKeyCredential document (id, rawId, type and the response's
// authenticatorData, clientDataJSON, signature and userHandle), and its
// CredentialID the credential that asserted.
func (s *FIDO2Signer) Sign(ctx context.Context, kind gwvpn.PersonFactorKind, nonce []byte) (_ *gwvpn.PersonFactor, err error) {
	if kind != gwvpn.PersonFactorFIDO2 {
		return nil, &ErrFactorUnsupported{Factor: kind}
	}
	options := fido2RequestOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(nonce),
		RPID:             s.rpID,
		UserVerification: "discouraged",
	}
	if s.credentialID != nil {
		options.AllowCredentials = []fido2CredentialDesc{{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(s.credentialID)}}
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, &ErrInvalidAssertion{Factor: kind, Reason: "encode the request options: " + err.Error()}
	}
	authenticator, err := s.open()
	if err != nil {
		return nil, &ErrAuthenticator{Factor: kind, Cause: err}
	}
	defer func() {
		if closeErr := authenticator.Close(); closeErr != nil {
			err = errors.Join(err, &ErrAuthenticator{Factor: kind, Cause: closeErr})
		}
	}()
	assertion, err := authenticator.AssertWithOptions(ctx, optionsJSON)
	if err != nil {
		return nil, &ErrAuthenticator{Factor: kind, Cause: err}
	}
	var credential struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(assertion, &credential); err != nil {
		return nil, &ErrInvalidAssertion{Factor: kind, Reason: err.Error()}
	}
	if credential.ID == "" {
		return nil, &ErrInvalidAssertion{Factor: kind, Reason: "no credential id"}
	}
	return &gwvpn.PersonFactor{Kind: kind, CredentialID: credential.ID, Assertion: assertion}, nil
}
