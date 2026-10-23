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

//go:build codec_msgpack

package quic

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// csrMockCA certifies CSRs for real, so a test can check whose key the
// certificate holds.
type csrMockCA struct {
	*mockCA
	signer *issuancetest.CA
}

func (m *csrMockCA) SignCSR(ctx context.Context, csrPEM []byte, opts *xkmsca.SignOptions) (*x509.Certificate, error) {
	return m.signer.SignCSR(ctx, csrPEM, opts)
}

func issue(t *testing.T, handler *CAHandler, issueReq *CAIssueRequest) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(issueReq)
	require.NoError(t, err)
	return handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpCAIssue, Payload: payload})
}

func signCSR(t *testing.T, handler *CAHandler, signReq *CASignCSRRequest) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(signReq)
	require.NoError(t, err)
	return handler.SignCSR(scopedCtx("ca:sign-csr"), payload)
}

// scopedCtx is the context of a caller whose platform token grants scopes.
func scopedCtx(scopes ...string) context.Context {
	return ContextWithToken(peerCtx(scopes...), "platform-token")
}

// peerCtx is what the peer authenticator leaves for a client certificate
// presented with no token: an AuthorizedContext and no token.
func peerCtx(scopes ...string) context.Context {
	return ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Subject: "u", Scopes: scopes})
}

// The handler itself refuses a caller whose token does not grant
// ca:sign-csr, or who was authenticated without a platform token, so a
// dispatcher on the legacy path cannot let one through.
func TestCAHandler_SignCSR_NeedsCASignCSR(t *testing.T) {
	key := issuancetest.RSAKey(t)
	payload := encode(t, &CASignCSRRequest{CsrPem: string(issuancetest.CSR(t, key, "rpi/fleet"))})
	cases := []struct {
		name   string
		ctx    context.Context
		status byte
	}{
		{"no platform token", context.Background(), quicwire.StatusPermissionDenied},
		{"ca:write", scopedCtx("ca:write"), quicwire.StatusPermissionDenied},
		{"operator certificate, no token", peerCtx("*:*"), quicwire.StatusPermissionDenied},
		{"empty token", ContextWithToken(peerCtx("ca:sign-csr"), ""), quicwire.StatusPermissionDenied},
		{"ca:sign-csr", scopedCtx("ca:sign-csr"), quicwire.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{mockCA: newMockCA(), signer: issuancetest.NewCA(t)}
			handler := NewCAHandler(logging.DefaultLogger(), ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

			resp := handler.SignCSR(tc.ctx, payload)
			assert.Equal(t, tc.status, resp.Status, string(resp.Payload))
			assert.Equal(t, tc.status == quicwire.StatusOK, ca.signer.Opts != nil, "reached the CA")
		})
	}
}

func TestCAHandler_SignCSR_CertifiesTheKMSKeyForCodeSigning(t *testing.T) {
	ca := &csrMockCA{mockCA: newMockCA(), signer: issuancetest.NewCA(t)}
	key := issuancetest.RSAKey(t)
	handler := NewCAHandler(logging.DefaultLogger(), ca, nil).WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))

	resp := signCSR(t, handler, &CASignCSRRequest{
		CsrPem:    string(issuancetest.CSR(t, key, "rpi/fleet")),
		ValidDays: 30,
	})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))

	var issued CAIssueResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &issued))
	block, _ := pem.Decode([]byte(issued.Certificate.Pem))
	require.NotNil(t, block, "no certificate PEM in the response")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the certificate does not certify the CSR's key")
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, cert.ExtKeyUsage)
	assert.Equal(t, 30, ca.signer.Opts.ValidityDays)
}

func TestCAHandler_SignCSR_Errors(t *testing.T) {
	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	cases := []struct {
		name    string
		payload []byte
		kms     *issuancetest.KMS
		caErr   error
		status  byte
		reached bool
	}{
		{"undecodable payload", []byte{0xc1}, issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), nil, quicwire.StatusInvalidRequest, false},
		{"malformed CSR", encode(t, &CASignCSRRequest{CsrPem: "not a csr"}), issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), nil, quicwire.StatusInvalidArgument, false},
		{"names no KMS key", encode(t, &CASignCSRRequest{CsrPem: csr}), issuancetest.NewKMS(t, "rpi/other", &key.PublicKey), nil, quicwire.StatusInvalidArgument, false},
		{"another key", encode(t, &CASignCSRRequest{CsrPem: csr}), issuancetest.NewKMS(t, "rpi/fleet", &issuancetest.RSAKey(t).PublicKey), nil, quicwire.StatusInvalidArgument, false},
		{"no KMS", encode(t, &CASignCSRRequest{CsrPem: csr}), nil, nil, quicwire.StatusInternalError, false},
		{"CA failure", encode(t, &CASignCSRRequest{CsrPem: csr}), issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey), errors.New("sealed"), quicwire.StatusInternalError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := &csrMockCA{mockCA: newMockCA(), signer: issuancetest.NewCA(t)}
			ca.signer.Err = tc.caErr
			handler := NewCAHandler(logging.DefaultLogger(), ca, nil)
			if tc.kms != nil {
				handler.WithKMS(tc.kms)
			}
			resp := handler.SignCSR(scopedCtx("ca:sign-csr"), tc.payload)
			assert.Equal(t, tc.status, resp.Status, string(resp.Payload))
			assert.Equal(t, tc.reached, ca.signer.Opts != nil, "reached the CA")
		})
	}
}

func TestCAHandler_SignCSR_WithoutACA(t *testing.T) {
	resp := NewCAHandler(logging.DefaultLogger(), nil, nil).SignCSR(scopedCtx("ca:sign-csr"), nil)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// A CSR is no longer something OpCAIssue takes: an issue request that
// carries one is an ordinary request without a common name.
func TestCAHandler_HandleIssue_IgnoresACSR(t *testing.T) {
	ca := &csrMockCA{mockCA: newMockCA(), signer: issuancetest.NewCA(t)}
	payload, err := quicwire.EncodePayload(map[string]string{"csr_pem": string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet"))})
	require.NoError(t, err)

	resp := NewCAHandler(logging.DefaultLogger(), ca, nil).HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpCAIssue, Payload: payload})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	assert.Nil(t, ca.signer.Opts, "an issue request reached SignCSR")
}

func encode(t *testing.T, v interface{}) []byte {
	t.Helper()
	payload, err := quicwire.EncodePayload(v)
	require.NoError(t, err)
	return payload
}

// "kms" names no key store; it used to fall back to a new software key.
func TestCAHandler_HandleIssue_UnknownStoreType(t *testing.T) {
	handler := NewCAHandler(logging.DefaultLogger(), newMockCA(), nil)

	resp := issue(t, handler, &CAIssueRequest{
		Subject:   &Subject{CommonName: "rpi/fleet"},
		StoreType: "kms",
	})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
	assert.Contains(t, string(resp.Payload), `unknown key store type "kms"`)
}
