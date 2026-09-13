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

package login

import (
	"encoding/json"
	"io"
	"net/http"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// SessionIDHeader carries the ceremony session the backbone issued at
// begin time. The client echoes it on finish so the platform persists no
// ceremony state of its own.
const SessionIDHeader = "X-Session-Id"

// challengeOptionsKey is the challenge-metadata key under which the
// backbone returns the PublicKeyCredentialRequestOptions JSON. It is the
// contract of go-xkms's WebAuthn factor challenger, which builds the
// assertion ceremony and marshals its options there.
const challengeOptionsKey = "options"

// maxProofBytes caps a finish request body. A WebAuthn assertion runs a
// few hundred bytes and an attestation with a full x5c chain a few KB;
// 64KB leaves ample headroom while keeping an unauthenticated endpoint
// from buffering an attacker-sized body.
const maxProofBytes = 64 * 1024

// FIDO2Binder binds the browser's WebAuthn assertion ceremony to the
// unified backbone.
//
// The ceremony is USERNAMELESS. An empty hint drives the backbone's
// discoverable-credential flow, and the lookup key is the credential id
// the authenticator returns in the assertion — the same base64url
// encoding the registration write-through enrolled the factor under. No
// email is collected, no directory is searched, and nothing depends on
// the caller knowing who they are before the authenticator says so. That
// is what makes a public email domain a non-problem: the platform never
// resolves an identity from one.
type FIDO2Binder struct {
	// tenantID scopes the ceremony. A WebAuthn assertion is only valid
	// against the relying party of the tenant that owns the credential,
	// so the backbone requires it and refuses to guess.
	tenantID string
}

// NewFIDO2Binder constructs the WebAuthn binder for a ceremony tenant.
func NewFIDO2Binder(tenantID string) (*FIDO2Binder, error) {
	if tenantID == "" {
		return nil, &DriverConfigError{Field: "FIDO2Binder tenant"}
	}
	return &FIDO2Binder{tenantID: tenantID}, nil
}

// Type returns the FIDO2 factor type.
func (b *FIDO2Binder) Type() quicbaas.FactorType {
	return quicbaas.FactorTypeFIDO2
}

// Begin opens a discoverable-credential assertion ceremony on the
// binder's tenant. Hint is deliberately left empty: see the type comment.
func (b *FIDO2Binder) Begin(r *http.Request) (quicbaas.BeginLoginRequest, error) {
	return quicbaas.BeginLoginRequest{
		Type:     quicbaas.FactorTypeFIDO2,
		TenantID: b.tenantID,
	}, nil
}

// Challenge projects the backbone's challenge onto the object the browser
// passes to navigator.credentials.get(), with the ceremony session added
// so the client can echo it back on finish.
//
// The options arrive as marshaled JSON and are unmarshaled here rather
// than forwarded as a string, so the browser receives publicKey at the
// top level instead of a stringified envelope.
func (b *FIDO2Binder) Challenge(begin *quicbaas.BeginLoginResponse) (any, error) {
	if begin == nil {
		return nil, &MissingChallengeError{Field: "response"}
	}
	optionsJSON := begin.ChallengeMetadata[challengeOptionsKey]
	if optionsJSON == "" {
		return nil, &MissingChallengeError{Field: challengeOptionsKey}
	}
	var options map[string]any
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return nil, &MissingChallengeError{Field: challengeOptionsKey}
	}
	if begin.SessionID == "" {
		return nil, &MissingChallengeError{Field: "sessionID"}
	}
	options["session_id"] = begin.SessionID
	return options, nil
}

// Finish reads the browser's PublicKeyCredential assertion and builds the
// ceremony's finish request.
//
// The credential id becomes the lookup key: the backbone resolves the
// principal from it and only then verifies the assertion's signature, RP
// id/origin and sign counter. The raw assertion rides in Signature, which
// is where the WebAuthn factor verifier reads it from when the metadata
// does not carry it.
//
// The backbone merges its own begin-time metadata into the verify
// challenge, so the relying party's session id needs no echoing here —
// only the ceremony session does.
func (b *FIDO2Binder) Finish(r *http.Request, _ string) (quicbaas.FinishLoginRequest, error) {
	sessionID := r.Header.Get(SessionIDHeader)
	if sessionID == "" {
		return quicbaas.FinishLoginRequest{}, &MissingSessionError{}
	}
	assertion, err := readProof(r.Body)
	if err != nil {
		return quicbaas.FinishLoginRequest{}, err
	}
	credentialID, err := credentialIDFromAssertion(assertion)
	if err != nil {
		return quicbaas.FinishLoginRequest{}, err
	}
	return quicbaas.FinishLoginRequest{
		SessionID: sessionID,
		Type:      quicbaas.FactorTypeFIDO2,
		LookupKey: []byte(credentialID),
		Signature: assertion,
	}, nil
}

// readProof buffers at most maxProofBytes of valid JSON from an
// unauthenticated finish request.
func readProof(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, &InvalidProofError{Reason: "empty body"}
	}
	raw, err := io.ReadAll(io.LimitReader(body, maxProofBytes+1))
	if err != nil {
		return nil, &InvalidProofError{Reason: "unreadable body"}
	}
	if len(raw) > maxProofBytes {
		return nil, &InvalidProofError{Reason: "body exceeds the proof size limit"}
	}
	if !json.Valid(raw) {
		return nil, &InvalidProofError{Reason: "body is not valid JSON"}
	}
	return raw, nil
}

// credentialIDFromAssertion extracts the base64url credential id the
// authenticator returned. WebAuthn puts it in the credential's "id"
// member, and the registration write-through enrolled the factor under
// exactly that encoding, so the two sides cannot drift.
func credentialIDFromAssertion(assertion []byte) (string, error) {
	var credential struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(assertion, &credential); err != nil {
		return "", &InvalidProofError{Reason: "assertion is not a WebAuthn credential"}
	}
	if credential.ID == "" {
		return "", &InvalidProofError{Reason: "assertion carries no credential id"}
	}
	return credential.ID, nil
}
