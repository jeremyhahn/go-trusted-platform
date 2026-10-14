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

package rest

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// adminToken is the bearer every signCSRRouter request carries.
const adminToken = "admin"

func postJSON(t *testing.T, router *mux.Router, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return postJSONAs(t, router, path, adminToken, body)
}

// postJSONAs posts body with token as the bearer; an empty token sends no
// Authorization header.
func postJSONAs(t *testing.T, router *mux.Router, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	var err error
	if msg, ok := body.(proto.Message); ok {
		data, err = protojson.Marshal(msg)
	} else {
		data, err = json.Marshal(body)
	}
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// scopedAuthorizer grants each token the scopes listed for it and refuses
// any other token. It records the scope it was asked for.
type scopedAuthorizer struct {
	scopes   map[string][]string
	asked    string
	askedHTU string
}

func (a *scopedAuthorizer) AuthorizeToken(_ context.Context, token, requiredPerm, _, _, htu string) (*platformtoken.AuthorizedContext, error) {
	a.asked, a.askedHTU = requiredPerm, htu
	scopes, ok := a.scopes[token]
	if !ok {
		return nil, errors.New("token invalid")
	}
	return &platformtoken.AuthorizedContext{Subject: token, Scopes: scopes}, nil
}

// signCSRRouter routes to CA handlers whose KMS holds "rpi/fleet" as key,
// and whose platform tokens grant adminToken ca:sign-csr.
func signCSRRouter(ca CAServiceInterface, kms issuance.KMS) *mux.Router {
	return signCSRRouterWith(ca, kms, &scopedAuthorizer{scopes: map[string][]string{adminToken: {issuance.SignCSRScope}}})
}

func signCSRRouterWith(ca CAServiceInterface, kms issuance.KMS, tokens TokenAuthorizer) *mux.Router {
	router := mux.NewRouter()
	NewCAHandlers(ca, slog.Default(), nil).WithKMS(kms).WithTokenAuthorizer(tokens).RegisterRoutes(router)
	return router
}

// Signing a CSR certifies a key for code signing, so it needs a platform
// token granting ca:sign-csr; ca:write, which issues ordinary certificates,
// is refused before the CA sees the request.
func TestCAHandlers_SignCSR_NeedsItsOwnScope(t *testing.T) {
	key := issuancetest.RSAKey(t)
	csr := &platformv1.SignCSRRequest{CsrPem: string(issuancetest.CSR(t, key, "rpi/fleet"))}
	cases := []struct {
		name  string
		token string
		code  int
	}{
		{"no bearer token", "", http.StatusUnauthorized},
		{"token the validator refuses", "forged", http.StatusForbidden},
		{"ca:write only", "writer", http.StatusForbidden},
		{"every other ca scope", "operator", http.StatusForbidden},
		{"*:write", "wildcard-action", http.StatusForbidden},
		{"ca:sign-csr", "signer", http.StatusCreated},
		{"ca:*", "ca-admin", http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMockCAService()
			ca.csrCA = issuancetest.NewCA(t)
			tokens := &scopedAuthorizer{scopes: map[string][]string{
				"writer":          {"ca:write"},
				"operator":        {"ca:read", "ca:write", "ca:delete", "kms:write"},
				"wildcard-action": {"*:write"},
				"signer":          {issuance.SignCSRScope},
				"ca-admin":        {"ca:*"},
			}}

			rr := postJSONAs(t, signCSRRouterWith(ca, fleetKMS(t, key), tokens), "/api/v1/ca/sign-csr", tc.token, csr)
			assert.Equal(t, tc.code, rr.Code, rr.Body.String())
			assert.Equal(t, tc.code == http.StatusCreated, ca.csrCA.Opts != nil, "reached the CA")
		})
	}
}

func TestCAHandlers_SignCSR_AsksForTheSignCSRScope(t *testing.T) {
	key := issuancetest.RSAKey(t)
	tokens := &scopedAuthorizer{scopes: map[string][]string{adminToken: {issuance.SignCSRScope}}}
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)

	rr := postJSON(t, signCSRRouterWith(ca, fleetKMS(t, key), tokens), "/api/v1/ca/sign-csr",
		&platformv1.SignCSRRequest{CsrPem: string(issuancetest.CSR(t, key, "rpi/fleet"))})
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Equal(t, "ca:sign-csr", tokens.asked)
	assert.Equal(t, "http://example.com/api/v1/ca/sign-csr", tokens.askedHTU)
}

// Without a platform-token validator nobody can hold ca:sign-csr, so the
// endpoint refuses every request rather than falling open.
func TestCAHandlers_SignCSR_WithoutATokenAuthorizer(t *testing.T) {
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)

	rr := postJSON(t, signCSRRouterWith(ca, fleetKMS(t, key), nil), "/api/v1/ca/sign-csr",
		&platformv1.SignCSRRequest{CsrPem: string(issuancetest.CSR(t, key, "rpi/fleet"))})
	assert.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "requires ca:sign-csr: no platform-token validator is configured")
	assert.Nil(t, ca.csrCA.Opts, "reached the CA")
}

func fleetKMS(t *testing.T, key *rsa.PrivateKey) issuance.KMS {
	t.Helper()
	return issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)
}

func TestCAHandlers_SignCSR_CertifiesTheKMSKeyForCodeSigning(t *testing.T) {
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)
	key := issuancetest.RSAKey(t)

	rr := postJSON(t, signCSRRouter(ca, fleetKMS(t, key)), "/api/v1/ca/sign-csr", &platformv1.SignCSRRequest{
		CsrPem:    string(issuancetest.CSR(t, key, "rpi/fleet")),
		ValidDays: 30,
	})
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())

	resp := &platformv1.IssueCertificateResponse{}
	require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), resp))
	block, _ := pem.Decode(resp.GetCertificate().GetPem())
	require.NotNil(t, block, "no certificate PEM in the response")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the certificate does not certify the CSR's key")
	assert.Equal(t, 30, ca.csrCA.Opts.ValidityDays)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, ca.csrCA.Opts.ExtKeyUsage)
}

// sdkCAClient connects the SDK's REST transport to router, served over TLS
// as platformd serves it, with adminToken as the bearer.
func sdkCAClient(t *testing.T, router *mux.Router) platformv1.CAServiceClient {
	t.Helper()
	// sdkrest.Connect probes /health/live before handing the adapter out.
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	srv := httptest.NewTLSServer(router)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())

	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(srv.URL),
		platform.WithTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}),
		platform.WithBearerToken(adminToken),
	))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return platformv1.NewCAServiceClient(adapter.Connection())
}

// The SDK decodes the certificate the daemon's sign-csr handler writes into
// the gRPC reply, as every other transport returns it.
func TestCAHandlers_SignCSR_DecodesThroughTheSDK(t *testing.T) {
	key := issuancetest.RSAKey(t)
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)
	client := sdkCAClient(t, signCSRRouter(ca, fleetKMS(t, key)))

	resp, err := client.SignCSR(context.Background(), &platformv1.SignCSRRequest{
		CsrPem:    string(issuancetest.CSR(t, key, "rpi/fleet")),
		ValidDays: 30,
	})
	require.NoError(t, err)

	assert.True(t, resp.GetStatus().GetSuccess())
	assert.NotNil(t, resp.GetTimestamp())
	got := resp.GetCertificate()
	require.NotNil(t, got)
	block, _ := pem.Decode(got.GetPem())
	require.NotNil(t, block, "no certificate PEM in the reply")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the certificate does not certify the CSR's key")
	assert.Equal(t, "rpi/fleet", got.GetSubject().GetCommonName())
	assert.Equal(t, hex.EncodeToString(cert.SerialNumber.Bytes()), got.GetSerial())
	assert.Equal(t, cert.NotBefore.Unix(), got.GetNotBefore().AsTime().Unix())
	assert.Equal(t, cert.NotAfter.Unix(), got.GetNotAfter().AsTime().Unix())
	assert.Equal(t, platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID, got.GetStatus())
	assert.Equal(t, platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, got.GetKeyAlgorithm())
	assert.Equal(t, []string{"CODE_SIGNING"}, got.GetExtKeyUsage())
}

// A sign-csr refusal reaches the SDK caller as the gRPC status the other
// transports return, not as a decoding failure.
func TestCAHandlers_SignCSR_SDKSeesTheRefusal(t *testing.T) {
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)
	client := sdkCAClient(t, signCSRRouterWith(ca, fleetKMS(t, issuancetest.RSAKey(t)),
		&scopedAuthorizer{scopes: map[string][]string{adminToken: {"ca:write"}}}))

	_, err := client.SignCSR(context.Background(), &platformv1.SignCSRRequest{
		CsrPem: string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet")),
	})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
	assert.Nil(t, ca.csrCA.Opts, "reached the CA")
}

func TestCAHandlers_SignCSR_Errors(t *testing.T) {
	key := issuancetest.RSAKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	other := string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet"))
	unknown := string(issuancetest.CSR(t, key, "rpi/unknown"))
	cases := []struct {
		name    string
		body    any
		noKMS   bool
		caErr   error
		code    int
		reached bool
	}{
		{"body is not JSON", "{", false, nil, http.StatusBadRequest, false},
		{"malformed CSR", &platformv1.SignCSRRequest{CsrPem: "not a csr"}, false, nil, http.StatusBadRequest, false},
		{"names no KMS key", &platformv1.SignCSRRequest{CsrPem: unknown}, false, nil, http.StatusBadRequest, false},
		{"key is not the KMS key", &platformv1.SignCSRRequest{CsrPem: other}, false, nil, http.StatusBadRequest, false},
		{"no KMS", &platformv1.SignCSRRequest{CsrPem: csr}, true, nil, http.StatusInternalServerError, false},
		{"CA failure", &platformv1.SignCSRRequest{CsrPem: csr}, false, errors.New("sealed"), http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca := newMockCAService()
			ca.csrCA = issuancetest.NewCA(t)
			ca.csrCA.Err = tc.caErr
			var kms issuance.KMS
			if !tc.noKMS {
				kms = fleetKMS(t, key)
			}
			rr := postJSON(t, signCSRRouter(ca, kms), "/api/v1/ca/sign-csr", tc.body)
			assert.Equal(t, tc.code, rr.Code, rr.Body.String())
			assert.Equal(t, tc.reached, ca.csrCA.Opts != nil, "reached the CA")
		})
	}
}

func TestCAHandlers_SignCSR_WithoutACA(t *testing.T) {
	rr := postJSON(t, signCSRRouter(nil, nil), "/api/v1/ca/sign-csr", &platformv1.SignCSRRequest{CsrPem: "x"})
	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

// Issuing a certificate never certifies a caller's CSR: a csr_pem field
// is ignored and the request is an ordinary issue.
func TestCAHandlers_IssueCertificate_IgnoresACSR(t *testing.T) {
	ca := newMockCAService()
	ca.csrCA = issuancetest.NewCA(t)
	_, router := setupCAHandlers(ca)

	rr := postJSON(t, router, "/api/v1/ca/certificates", map[string]any{
		"csr_pem": string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet")),
		"request": map[string]any{"subject": map[string]string{"common_name": "rpi/fleet"}},
	})
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	assert.Nil(t, ca.csrCA.Opts, "the issue endpoint certified a CSR")
}

// "kms" names no key store; it used to fall back to a new software key.
func TestCAHandlers_IssueCertificate_UnknownStoreType(t *testing.T) {
	ca := newMockCAService()
	_, router := setupCAHandlers(ca)
	rr := postJSON(t, router, "/api/v1/ca/certificates", &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject:   &platformv1.Subject{CommonName: "rpi/fleet"},
			StoreType: "kms",
		},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `unknown key store type \"kms\"`)
	assert.Empty(t, ca.issuedCerts, "an unknown store reached the CA")
}
