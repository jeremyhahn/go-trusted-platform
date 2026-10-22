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

//go:build integration

package helpers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// WebAuthn constants the software authenticator encodes (W3C WebAuthn
// Level 3 §6.1 authenticator data, §6.5.4 attestation object; RFC 9053
// §2.1 and RFC 9052 §7 for the COSE key).
const (
	// coseAlgES256 is ECDSA w/ SHA-256 (RFC 9053 §2.1).
	coseAlgES256 = -7
	// coseKeyTypeEC2 and coseCurveP256 are the RFC 9053 §7.1 values.
	coseKeyTypeEC2 = 2
	coseCurveP256  = 1

	// Authenticator data flags (WebAuthn §6.1): user present, user
	// verified, attested credential data included.
	authDataFlagUP = 0x01
	authDataFlagUV = 0x04
	authDataFlagAT = 0x40

	// credentialIDLength is the size of the random credential id.
	credentialIDLength = 32
)

// ErrCreationOptionsInvalid reports PublicKeyCredentialCreationOptions the
// software authenticator cannot answer.
type ErrCreationOptionsInvalid struct {
	Reason string
}

// Error implements the error interface.
func (e ErrCreationOptionsInvalid) Error() string {
	return "webauthn authenticator: creation options invalid: " + e.Reason
}

// ErrAuthenticatorKey reports that the authenticator could not create its
// credential key pair.
type ErrAuthenticatorKey struct {
	Cause error
}

// Error implements the error interface.
func (e ErrAuthenticatorKey) Error() string {
	return "webauthn authenticator: credential key: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrAuthenticatorKey) Unwrap() error { return e.Cause }

// ErrRegistrationEncoding reports that the registration response could not
// be encoded.
type ErrRegistrationEncoding struct {
	Cause error
}

// Error implements the error interface.
func (e ErrRegistrationEncoding) Error() string {
	return "webauthn authenticator: encode registration: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrRegistrationEncoding) Unwrap() error { return e.Cause }

// creationOptions is the part of the server's CredentialCreation object
// (publicKey at the top level, session_id beside it) the authenticator and
// the claim flow read.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		PubKeyCredParams []struct {
			Type string `json:"type"`
			Alg  int    `json:"alg"`
		} `json:"pubKeyCredParams"`
	} `json:"publicKey"`
	SessionID string `json:"session_id"`
}

// softwareAuthenticator is the harness's test-side WebAuthn authenticator.
// It holds a real ES256 key pair and answers a registration with "none"
// attestation (WebAuthn §8.7): the relying party verifies the ceremony —
// challenge, origin, RP id hash, flags and the credential public key —
// exactly as it does for a hardware authenticator, and records the key.
// Nothing about the server's verification is bypassed; the authenticator
// only declines to attest its own make and model.
//
// It lives here because the quicbaas SDK re-exports the CTAP2 HID
// transport (sdk/go/xkms/fido2) but no software authenticator, and the
// harness may import nothing outside quicbaas/sdk/go.
type softwareAuthenticator struct {
	key          *ecdsa.PrivateKey
	credentialID []byte
}

// newSoftwareAuthenticator creates an authenticator with a fresh P-256 key
// and a random credential id.
func newSoftwareAuthenticator() (*softwareAuthenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, ErrAuthenticatorKey{Cause: err}
	}
	credentialID := make([]byte, credentialIDLength)
	if _, err := rand.Read(credentialID); err != nil {
		return nil, ErrAuthenticatorKey{Cause: err}
	}
	return &softwareAuthenticator{key: key, credentialID: credentialID}, nil
}

// attestationResponse is the PublicKeyCredential JSON a browser posts to
// finish a registration (WebAuthn §5.1, toJSON form): every binary field
// base64url without padding.
type attestationResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	} `json:"response"`
	ClientExtensionResults struct{} `json:"clientExtensionResults"`
}

// clientData is the CollectedClientData a browser signs over (WebAuthn
// §5.8.1).
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// register answers options for origin and returns the registration JSON
// the relying party's finish endpoint takes. The challenge is echoed as
// the server issued it, base64url, because that is the string the relying
// party compares against.
func (a *softwareAuthenticator) register(options creationOptions, origin string) ([]byte, error) {
	if options.PublicKey.Challenge == "" {
		return nil, ErrCreationOptionsInvalid{Reason: "no challenge"}
	}
	if !offersES256(options) {
		return nil, ErrCreationOptionsInvalid{Reason: "ES256 (alg -7) is not among pubKeyCredParams"}
	}
	rpID, err := relyingPartyID(options, origin)
	if err != nil {
		return nil, err
	}

	clientDataJSON, err := json.Marshal(clientData{
		Type:      "webauthn.create",
		Challenge: options.PublicKey.Challenge,
		Origin:    origin,
	})
	if err != nil {
		return nil, ErrRegistrationEncoding{Cause: err}
	}
	authData, err := a.authenticatorData(rpID)
	if err != nil {
		return nil, err
	}

	attestation, err := cborEncode(attestationObject{
		Fmt:      "none",
		AttStmt:  map[string]any{},
		AuthData: authData,
	})
	if err != nil {
		return nil, err
	}

	encode := base64.RawURLEncoding.EncodeToString
	var response attestationResponse
	response.ID = encode(a.credentialID)
	response.RawID = response.ID
	response.Type = "public-key"
	response.Response.ClientDataJSON = encode(clientDataJSON)
	response.Response.AttestationObject = encode(attestation)
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, ErrRegistrationEncoding{Cause: err}
	}
	return encoded, nil
}

// authenticatorData lays out the registration authenticator data
// (WebAuthn §6.1): rpIdHash, flags, a zero signature counter, then the
// attested credential data (§6.5.1) with an all-zero AAGUID, as "none"
// attestation carries.
func (a *softwareAuthenticator) authenticatorData(rpID string) ([]byte, error) {
	coseKey, err := a.coseKey()
	if err != nil {
		return nil, err
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	data := make([]byte, 0, 37+16+2+len(a.credentialID)+len(coseKey))
	data = append(data, rpIDHash[:]...)
	data = append(data, authDataFlagUP|authDataFlagUV|authDataFlagAT)
	data = binary.BigEndian.AppendUint32(data, 0)
	data = append(data, make([]byte, 16)...)
	data = binary.BigEndian.AppendUint16(data, uint16(len(a.credentialID)))
	data = append(data, a.credentialID...)
	return append(data, coseKey...), nil
}

// coseKey encodes the credential public key as a COSE_Key (RFC 9052 §7,
// EC2 parameters RFC 9053 §7.1.1), map keys in CTAP2 canonical order.
func (a *softwareAuthenticator) coseKey() ([]byte, error) {
	// Bytes is the uncompressed point 0x04 || X || Y (SEC 1 §2.3.3).
	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		return nil, ErrAuthenticatorKey{Cause: err}
	}
	coordinateLen := (len(point) - 1) / 2
	x := point[1 : 1+coordinateLen]
	y := point[1+coordinateLen:]
	return cborEncode(map[int]any{
		1:  coseKeyTypeEC2,
		3:  coseAlgES256,
		-1: coseCurveP256,
		-2: x,
		-3: y,
	})
}

// offersES256 reports whether the relying party accepts ES256. An empty
// list means the client default, which includes it (WebAuthn §5.4).
func offersES256(options creationOptions) bool {
	params := options.PublicKey.PubKeyCredParams
	if len(params) == 0 {
		return true
	}
	for _, param := range params {
		if param.Type == "public-key" && param.Alg == coseAlgES256 {
			return true
		}
	}
	return false
}

// relyingPartyID is the RP id the options name or, when they name none,
// the origin's host (WebAuthn §5.4.2).
func relyingPartyID(options creationOptions, origin string) (string, error) {
	if options.PublicKey.RP.ID != "" {
		return options.PublicKey.RP.ID, nil
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return "", ErrCreationOptionsInvalid{Reason: "no rp.id and origin " + origin + " names no host"}
	}
	return parsed.Hostname(), nil
}

// attestationObject is the registration's attestation object (WebAuthn
// §6.5.4) in "none" format: an empty statement over the authenticator
// data.
type attestationObject struct {
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
	AuthData []byte         `cbor:"authData"`
}

// ctap2Encoding is the CTAP2 canonical CBOR encoding (CTAP 2.1 §8, RFC
// 8949 §4.2.3 length-first key order), the form authenticators emit.
var ctap2Encoding = sync.OnceValues(func() (cbor.EncMode, error) {
	return cbor.CTAP2EncOptions().EncMode()
})

// cborEncode encodes v in the CTAP2 canonical form.
func cborEncode(v any) ([]byte, error) {
	mode, err := ctap2Encoding()
	if err != nil {
		return nil, ErrRegistrationEncoding{Cause: err}
	}
	encoded, err := mode.Marshal(v)
	if err != nil {
		return nil, ErrRegistrationEncoding{Cause: err}
	}
	return encoded, nil
}
