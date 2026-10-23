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

package daemon

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// scopedTokenValidator accepts every token and grants it scopes.
type scopedTokenValidator struct {
	scopes []string
}

func (v scopedTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

func (v scopedTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "u", Scopes: v.scopes}, nil
}

// newSignCSRQUICHandler builds a daemon QUIC handler whose tokens carry
// scopes, and whose CA certifies CSRs for the KMS key "rpi/fleet".
func newSignCSRQUICHandler(t *testing.T, scopes ...string) (*QUICServiceHandler, *csrMockCA, []byte) {
	t.Helper()
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: scopes}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	handler.SetKMSService(newMockKMSService())

	ca := &csrMockCA{signer: issuancetest.NewCA(t)}
	key := issuancetest.RSAKey(t)
	handler.SetCAHandler(quic.NewCAHandler(logging.DefaultLogger(), ca, nil).
		WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)))
	return handler, ca, issuancetest.CSR(t, key, "rpi/fleet")
}

func signCSRRequest(t *testing.T, csr []byte) *quicwire.Request {
	t.Helper()
	req := kmsExtendedRequest(t, quicwire.OpKMSExtendedCategory, quicwire.KMSSubSignCSR,
		&quic.CASignCSRRequest{CsrPem: string(csr)})
	req.Token = "tok"
	return req
}

// Signing a CSR certifies a key for code signing, so it needs ca:sign-csr;
// ca:write, which issues ordinary certificates, is refused before the CA
// sees the request.
func TestQUICSignCSR_NeedsItsOwnScope(t *testing.T) {
	cases := []struct {
		scopes []string
		status byte
	}{
		{[]string{"ca:write"}, quicwire.StatusPermissionDenied},
		{[]string{"ca:read", "ca:write", "ca:delete", "kms:write"}, quicwire.StatusPermissionDenied},
		{[]string{"*:write"}, quicwire.StatusPermissionDenied},
		{[]string{"ca:sign-csr"}, quicwire.StatusOK},
		{[]string{"ca:*"}, quicwire.StatusOK},
	}
	for _, tc := range cases {
		handler, ca, csr := newSignCSRQUICHandler(t, tc.scopes...)

		resp := handler.HandleRequest(context.Background(), signCSRRequest(t, csr))
		assert.Equal(t, tc.status, resp.Status, "%v: %s", tc.scopes, resp.Payload)
		assert.Equal(t, tc.status == quicwire.StatusOK, ca.signer.Opts != nil, "%v reached the CA", tc.scopes)
	}
}

func TestQUICSignCSR_WithoutACAHandler(t *testing.T) {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetKMSService(newMockKMSService())

	resp := handler.HandleRequest(context.Background(), signCSRRequest(t, nil))
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// The daemon answers SignCSR with CAIssueResponse — unix-second times, string
// enums, no Status — so the SDK must translate it into IssueCertificateResponse.
// The SDK module cannot import the daemon, so the round trip is proven here:
// the SDK QUIC client against the daemon's own QUIC server.
func TestQUICSignCSR_DecodesTheDaemonsReply(t *testing.T) {
	handler, _, csr := newSignCSRQUICHandler(t, "ca:sign-csr")
	client := serveQUICCA(t, testutil.GenerateTestTLSBundle(t), handler)

	reply, err := client.SignCSR(context.Background(), &platformv1.SignCSRRequest{CsrPem: string(csr), ValidDays: 30})
	require.NoError(t, err)

	assert.True(t, reply.GetStatus().GetSuccess(), "status = %v", reply.GetStatus())
	assert.NotNil(t, reply.GetTimestamp(), "timestamp")
	got := reply.GetCertificate()
	block, _ := pem.Decode(got.GetPem())
	require.NotNil(t, block, "certificate PEM %q does not decode", got.GetPem())
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	csrBlock, _ := pem.Decode(csr)
	require.NotNil(t, csrBlock)
	request, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(t, err)

	assert.Equal(t, request.PublicKey, cert.PublicKey, "the certificate certifies the CSR's key")
	assert.Equal(t, "rpi/fleet", got.GetSubject().GetCommonName())
	assert.Equal(t, hex.EncodeToString(cert.SerialNumber.Bytes()), got.GetSerial())
	assert.Equal(t, cert.NotBefore.Unix(), got.GetNotBefore().GetSeconds())
	assert.Equal(t, cert.NotAfter.Unix(), got.GetNotAfter().GetSeconds())
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, got.GetStatus())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, got.GetKeyAlgorithm())
}
