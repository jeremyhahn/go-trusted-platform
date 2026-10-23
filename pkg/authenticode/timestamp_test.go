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

package authenticode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
)

// newTestSigner returns a signer with a fresh key that countersigns at
// tsaURL, or does not countersign when tsaURL is empty.
func newTestSigner(t *testing.T, tsaURL string) Authenticode {
	t.Helper()
	key, cert := generateTestKey(t)
	signer, err := NewSigner(context.Background(), &SignerOptions{
		KeyStore:      &mockBackend{privateKey: key},
		KeyAttributes: &xkmssdk.KeyAttributes{CN: "test"},
		Certificate:   cert,
		TimestampURL:  tsaURL,
		Logger:        logging.DefaultLogger(),
	})
	require.NoError(t, err)
	return signer
}

// signWithTimestamp signs a minimal PE with a TSA answering as opts says.
func signWithTimestamp(t *testing.T, opts authenticodetest.TSAOptions) ([]byte, Authenticode, error) {
	t.Helper()
	tsa := authenticodetest.NewTSA(t, opts)
	signer := newTestSigner(t, tsa.URL)
	var signed bytes.Buffer
	err := signer.Sign(bytes.NewReader(authenticodetest.MinimalPE(authenticodetest.MachineAMD64)), &signed)
	return signed.Bytes(), signer, err
}

// A signature countersigned by a TSA is embedded whole and verifies; before
// the fix the signer embedded a nil signature whenever TimestampURL was set.
func TestSignWithTimestampVerifies(t *testing.T) {
	signed, signer, err := signWithTimestamp(t, authenticodetest.TSAOptions{})
	require.NoError(t, err)
	require.NoError(t, signer.Verify(bytes.NewReader(signed)))
}

// embeddedSignerInfo returns the Authenticode signerInfo embedded in signed.
func embeddedSignerInfo(t *testing.T, signer Authenticode, signed []byte) signerInfo {
	t.Helper()
	pe, err := parsePE(signed)
	require.NoError(t, err)
	signature, err := signer.(*Signer).extractSignature(pe)
	require.NoError(t, err)
	var ci contentInfo
	_, err = asn1.Unmarshal(signature, &ci)
	require.NoError(t, err)
	var sd signedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	require.NoError(t, err)
	require.Len(t, sd.SignerInfos, 1)
	return sd.SignerInfos[0]
}

// The token is carried as the SPC RFC 3161 unauthenticated attribute.
func TestSignWithTimestampEmbedsToken(t *testing.T) {
	signed, signer, err := signWithTimestamp(t, authenticodetest.TSAOptions{})
	require.NoError(t, err)

	si := embeddedSignerInfo(t, signer, signed)
	require.Len(t, si.UnauthenticatedAttributes, 1)
	require.True(t, si.UnauthenticatedAttributes[0].Type.Equal(oidSPCRFC3161Timestamp))
}

// A configured TSA that cannot stamp fails signing, and nothing is written.
func TestSignWithTimestampFailures(t *testing.T) {
	tests := []struct {
		name string
		opts authenticodetest.TSAOptions
	}{
		{"refused", authenticodetest.TSAOptions{Status: 2}},
		{"http error", authenticodetest.TSAOptions{HTTPStatus: http.StatusInternalServerError}},
		{"wrong imprint", authenticodetest.TSAOptions{AlterImprint: true}},
		{"wrong nonce", authenticodetest.TSAOptions{AlterNonce: true}},
		{"no time-stamping EKU", authenticodetest.TSAOptions{OmitTimeStampingEKU: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, _, err := signWithTimestamp(t, tt.opts)
			var tsErr *TimestampError
			require.ErrorAs(t, err, &tsErr)
			require.Empty(t, signed)
		})
	}
}

func TestSignWithUnreachableTimestampAuthority(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	signer := newTestSigner(t, server.URL)

	var signed bytes.Buffer
	err := signer.Sign(bytes.NewReader(authenticodetest.MinimalPE(authenticodetest.MachineAMD64)), &signed)
	var tsErr *TimestampError
	require.ErrorAs(t, err, &tsErr)
	require.Equal(t, server.URL, tsErr.URL)
	require.Zero(t, signed.Len())
}

// Verify checks the embedded token: an altered imprint no longer matches the
// signature it claims to stamp.
func TestVerifyRejectsTamperedTimestamp(t *testing.T) {
	signed, signer, err := signWithTimestamp(t, authenticodetest.TSAOptions{})
	require.NoError(t, err)

	si := embeddedSignerInfo(t, signer, signed)
	imprint := sha256.Sum256(si.EncryptedDigest)
	at := bytes.Index(signed, imprint[:])
	require.GreaterOrEqual(t, at, 0)
	signed[at] ^= 0xff

	err = signer.Verify(bytes.NewReader(signed))
	require.ErrorContains(t, err, "time-stamp imprint does not match the signature")
}
