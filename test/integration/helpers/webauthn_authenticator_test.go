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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

// TestCBOREncoderMatchesRFC8949Vectors checks the encoder against the
// RFC 8949 Appendix A examples it can produce.
func TestCBOREncoderMatchesRFC8949Vectors(t *testing.T) {
	cases := []struct {
		name    string
		encoded []byte
		want    string
	}{
		{"0", cborInt(0), "00"},
		{"23", cborInt(23), "17"},
		{"24", cborInt(24), "1818"},
		{"100", cborInt(100), "1864"},
		{"1000", cborInt(1000), "1903e8"},
		{"1000000", cborInt(1000000), "1a000f4240"},
		{"1000000000000", cborInt(1000000000000), "1b000000e8d4a51000"},
		{"-1", cborInt(-1), "20"},
		{"-100", cborInt(-100), "3863"},
		{"-1000", cborInt(-1000), "3903e7"},
		{"h''", cborBytes(nil), "40"},
		{"h'01020304'", cborBytes([]byte{1, 2, 3, 4}), "4401020304"},
		{`""`, cborText(""), "60"},
		{`"IETF"`, cborText("IETF"), "6449455446"},
		{"{}", cborMap(), "a0"},
		{"{1: 2, 3: 4}", cborMap(cborInt(1), cborInt(2), cborInt(3), cborInt(4)), "a201020304"},
	}
	for _, tc := range cases {
		if got := hex.EncodeToString(tc.encoded); got != tc.want {
			t.Errorf("%s: encoded %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestSoftwareAuthenticatorRegistersWithNoneAttestation decodes a
// registration and checks what the relying party verifies: the client
// data, the RP id hash, the flags, the credential id and the COSE key.
func TestSoftwareAuthenticatorRegistersWithNoneAttestation(t *testing.T) {
	authenticator, err := newSoftwareAuthenticator()
	if err != nil {
		t.Fatalf("newSoftwareAuthenticator: %v", err)
	}
	options := testCreationOptions("Y2hhbGxlbmdl", "localhost")
	raw, err := authenticator.register(options, "https://localhost:8443")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	var response attestationResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	wantID := base64.RawURLEncoding.EncodeToString(authenticator.credentialID)
	if response.ID != wantID || response.RawID != wantID || response.Type != "public-key" {
		t.Errorf("id %q rawId %q type %q, want %q %q public-key", response.ID, response.RawID, response.Type, wantID, wantID)
	}

	clientDataJSON := decodeBase64URL(t, response.Response.ClientDataJSON)
	var data clientData
	if err := json.Unmarshal(clientDataJSON, &data); err != nil {
		t.Fatalf("decode client data: %v", err)
	}
	if data.Type != "webauthn.create" || data.Challenge != "Y2hhbGxlbmdl" || data.Origin != "https://localhost:8443" {
		t.Errorf("client data = %+v", data)
	}

	attestationObject := decodeBase64URL(t, response.Response.AttestationObject)
	authData, err := authenticator.authenticatorData("localhost")
	if err != nil {
		t.Fatalf("authenticatorData: %v", err)
	}
	wantObject := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(authData),
	)
	if !bytes.Equal(attestationObject, wantObject) {
		t.Errorf("attestation object is not the none-format map over the authenticator data")
	}

	rpIDHash := sha256.Sum256([]byte("localhost"))
	if !bytes.Equal(authData[:32], rpIDHash[:]) {
		t.Errorf("rpIdHash is not SHA-256(\"localhost\")")
	}
	if flags := authData[32]; flags != authDataFlagUP|authDataFlagUV|authDataFlagAT {
		t.Errorf("flags = %#x, want UP|UV|AT", flags)
	}
	if counter := binary.BigEndian.Uint32(authData[33:37]); counter != 0 {
		t.Errorf("signCount = %d, want 0", counter)
	}
	if !bytes.Equal(authData[37:53], make([]byte, 16)) {
		t.Errorf("AAGUID is not all zero")
	}
	idLen := int(binary.BigEndian.Uint16(authData[53:55]))
	if idLen != credentialIDLength || !bytes.Equal(authData[55:55+idLen], authenticator.credentialID) {
		t.Errorf("credential id in authenticator data does not match")
	}

	point, err := authenticator.key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	wantKey := cborMap(
		cborInt(1), cborInt(2),
		cborInt(3), cborInt(-7),
		cborInt(-1), cborInt(1),
		cborInt(-2), cborBytes(point[1:33]),
		cborInt(-3), cborBytes(point[33:65]),
	)
	if !bytes.Equal(authData[55+idLen:], wantKey) {
		t.Errorf("COSE key is not the EC2 P-256 ES256 key of the credential")
	}
}

// TestSoftwareAuthenticatorDefaultsRPIDToOriginHost covers options that
// name no RP id.
func TestSoftwareAuthenticatorDefaultsRPIDToOriginHost(t *testing.T) {
	options := testCreationOptions("Y2hhbGxlbmdl", "")
	rpID, err := relyingPartyID(options, "https://platform.example.internal:8443")
	if err != nil {
		t.Fatalf("relyingPartyID: %v", err)
	}
	if rpID != "platform.example.internal" {
		t.Errorf("rpID = %q, want the origin host", rpID)
	}
}

// TestSoftwareAuthenticatorRejectsUnanswerableOptions covers options the
// authenticator must refuse rather than answer wrongly.
func TestSoftwareAuthenticatorRejectsUnanswerableOptions(t *testing.T) {
	authenticator, err := newSoftwareAuthenticator()
	if err != nil {
		t.Fatalf("newSoftwareAuthenticator: %v", err)
	}
	rs256Only := testCreationOptions("Y2hhbGxlbmdl", "localhost")
	rs256Only.PublicKey.PubKeyCredParams[0].Alg = -257

	cases := []struct {
		name    string
		options creationOptions
		origin  string
	}{
		{"no challenge", testCreationOptions("", "localhost"), "https://localhost:8443"},
		{"no ES256", rs256Only, "https://localhost:8443"},
		{"no RP id and no origin host", testCreationOptions("Y2hhbGxlbmdl", ""), "not-a-url"},
	}
	for _, tc := range cases {
		_, err := authenticator.register(tc.options, tc.origin)
		var invalid ErrCreationOptionsInvalid
		if !errors.As(err, &invalid) {
			t.Errorf("%s: err = %v, want ErrCreationOptionsInvalid", tc.name, err)
		}
	}
}

// testCreationOptions builds options offering ES256.
func testCreationOptions(challenge, rpID string) creationOptions {
	var options creationOptions
	options.PublicKey.Challenge = challenge
	options.PublicKey.RP.ID = rpID
	options.PublicKey.PubKeyCredParams = []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	}{{Type: "public-key", Alg: coseAlgES256}}
	options.SessionID = "session-1"
	return options
}

// decodeBase64URL decodes unpadded base64url or fails the test.
func decodeBase64URL(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode base64url %q: %v", encoded, err)
	}
	return decoded
}
