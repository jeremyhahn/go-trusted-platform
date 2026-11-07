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

package ca

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// csrHandlers returns handlers whose CA certifies CSRs for real, and whose
// KMS holds key as "rpi/fleet".
func csrHandlers(t *testing.T, key *rsa.PrivateKey) (*CAHandlers, *mockHttpWriter, *issuancetest.CA) {
	t.Helper()
	root := sharedCSRKeys(t).ca
	// A fresh CA per test on the shared root: Opts and Err start empty.
	signer := &issuancetest.CA{Key: root.Key, Root: root.Root}
	handlers, writer := newTestHandlers(&mockCertificateAuthority{
		initialized: true,
		signCSRFn:   signer.SignCSR,
	})
	handlers.WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey))
	return handlers, writer, signer
}

// csrKeys holds the RSA-2048 keys the CSR tests share: generating them per
// test dominated the package time. Tests only read them.
type csrKeys struct {
	ca     *issuancetest.CA
	device *rsa.PrivateKey
}

var (
	csrKeysOnce   sync.Once
	csrKeysShared csrKeys
)

func sharedCSRKeys(t *testing.T) csrKeys {
	t.Helper()
	csrKeysOnce.Do(func() {
		csrKeysShared = csrKeys{ca: issuancetest.NewCA(t), device: issuancetest.RSAKey(t)}
	})
	if csrKeysShared.ca == nil || csrKeysShared.device == nil {
		t.Fatal("shared CSR keys were not created")
	}
	return csrKeysShared
}

// deviceKey is the shared key a test's CSR certifies and its KMS holds.
func deviceKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	return sharedCSRKeys(t).device
}

// postSignCSR posts a CSR as a caller whose platform token carries scopes;
// no scopes means no platform token at all.
func postSignCSR(t *testing.T, handlers *CAHandlers, req *platformv1.SignCSRRequest, scopes ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := protojson.Marshal(req)
	require.NoError(t, err)
	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	if scopes != nil {
		httpReq = httpReq.WithContext(iammw.SetAuthorizedContext(httpReq.Context(),
			&platformtoken.AuthorizedContext{Subject: "admin", Scopes: scopes}))
	}
	rec := httptest.NewRecorder()
	handlers.SignCSR(rec, httpReq)
	return rec
}

func TestSignCSR_CertifiesTheKMSKeyForCodeSigning(t *testing.T) {
	key := deviceKey(t)
	handlers, writer, signer := csrHandlers(t, key)

	rec := postSignCSR(t, handlers, &platformv1.SignCSRRequest{
		CsrPem:    string(issuancetest.CSR(t, key, "rpi/fleet")),
		ValidDays: 30,
	}, SignCSRScope)
	require.Equal(t, http.StatusCreated, writer.lastStatus, rec.Body.String())

	payload := decodeProtoBody(t, rec)
	certJSON, ok := payload["certificate"].(map[string]interface{})
	require.True(t, ok, "payload.certificate should be an object")
	pemBytes, err := base64.StdEncoding.DecodeString(certJSON["pem"].(string))
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "no certificate PEM in the response")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(cert.PublicKey), "the certificate does not certify the CSR's key")
	assert.Equal(t, 30, signer.Opts.ValidityDays)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, signer.Opts.ExtKeyUsage)
}

// Signing a CSR certifies a key for code signing, so it needs ca:sign-csr;
// ca:write, which issues ordinary certificates, is refused before the CA
// sees the request, as is a session that carries no token scopes at all.
func TestSignCSR_NeedsItsOwnScope(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		code   int
	}{
		{"no platform token", nil, http.StatusForbidden},
		{"ca:write", []string{"ca:write"}, http.StatusForbidden},
		{"every other CA scope", []string{"ca:read", "ca:write", "ca:delete", "kms:write"}, http.StatusForbidden},
		{"*:write", []string{"*:write"}, http.StatusForbidden},
		{"ca:sign-csr", []string{"ca:sign-csr"}, http.StatusCreated},
		{"ca:*", []string{"ca:*"}, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := deviceKey(t)
			handlers, writer, signer := csrHandlers(t, key)

			rec := postSignCSR(t, handlers, &platformv1.SignCSRRequest{
				CsrPem: string(issuancetest.CSR(t, key, "rpi/fleet")),
			}, tc.scopes...)
			assert.Equal(t, tc.code, writer.lastStatus, rec.Body.String())
			assert.Equal(t, tc.code == http.StatusCreated, signer.Opts != nil, "reached the CA")
			if tc.code == http.StatusForbidden {
				var scopeErr ErrSignCSRScopeRequired
				assert.ErrorAs(t, writer.lastError, &scopeErr)
			}
		})
	}
}

func TestSignCSR_Errors(t *testing.T) {
	key := deviceKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	cases := []struct {
		name    string
		csr     string
		noKMS   bool
		caErr   error
		code    int
		reached bool
	}{
		{"malformed CSR", "not a csr", false, nil, http.StatusBadRequest, false},
		{"names no KMS key", string(issuancetest.CSR(t, key, "rpi/unknown")), false, nil, http.StatusBadRequest, false},
		{"key is not the KMS key", string(issuancetest.CSR(t, issuancetest.RSAKey(t), "rpi/fleet")), false, nil, http.StatusBadRequest, false},
		{"no KMS", csr, true, nil, http.StatusInternalServerError, false},
		{"CA failure", csr, false, errors.New("sealed"), http.StatusInternalServerError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlers, writer, signer := csrHandlers(t, key)
			signer.Err = tc.caErr
			if tc.noKMS {
				handlers.WithKMS(nil)
			}
			rec := postSignCSR(t, handlers, &platformv1.SignCSRRequest{CsrPem: tc.csr}, SignCSRScope)
			assert.Equal(t, tc.code, writer.lastStatus, rec.Body.String())
			assert.Equal(t, tc.reached, signer.Opts != nil, "reached the CA")
		})
	}
}

func TestSignCSR_BodyIsNotJSON(t *testing.T) {
	handlers, writer, signer := csrHandlers(t, deviceKey(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", bytes.NewReader([]byte("{")))
	req = req.WithContext(iammw.SetAuthorizedContext(req.Context(),
		&platformtoken.AuthorizedContext{Subject: "admin", Scopes: []string{SignCSRScope}}))
	handlers.SignCSR(httptest.NewRecorder(), req)
	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	assert.Nil(t, signer.Opts, "reached the CA")
}

func TestSignCSR_WithoutACA(t *testing.T) {
	handlers, writer := newTestHandlers(nil)
	postSignCSR(t, handlers, &platformv1.SignCSRRequest{CsrPem: "x"}, SignCSRScope)
	assert.Equal(t, http.StatusServiceUnavailable, writer.lastStatus)
}

// TestCARouter_WithKMS proves the router hands its KMS to the sign-csr
// route: the same CSR is certified through a router given the KMS and
// refused, without reaching the CA, through one that was not.
func TestCARouter_WithKMS(t *testing.T) {
	key := deviceKey(t)
	csr := string(issuancetest.CSR(t, key, "rpi/fleet"))
	cases := []struct {
		name    string
		withKMS bool
		code    int
	}{
		{"with the KMS", true, http.StatusCreated},
		{"without a KMS", false, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer := issuancetest.NewCA(t)
			writer := &mockHttpWriter{}
			caRouter := NewCARouter(newTestLogger(), &mockCertificateAuthority{
				initialized: true,
				signCSRFn:   signer.SignCSR,
			}, writer)
			if tc.withKMS {
				require.Same(t, caRouter, caRouter.WithKMS(issuancetest.NewKMS(t, "rpi/fleet", &key.PublicKey)))
			}

			body, err := protojson.Marshal(&platformv1.SignCSRRequest{CsrPem: csr})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/sign-csr", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(iammw.SetAuthorizedContext(req.Context(),
				&platformtoken.AuthorizedContext{Subject: "admin", Scopes: []string{SignCSRScope}}))
			rec := httptest.NewRecorder()
			newTestRouter(caRouter).ServeHTTP(rec, req)

			assert.Equal(t, tc.code, writer.lastStatus, rec.Body.String())
			assert.Equal(t, tc.withKMS, signer.Opts != nil, "reached the CA")
		})
	}
}

// Issuing a certificate never certifies a caller's CSR: csr_pem is no longer
// part of the request, so the field is dropped and the CA never signs it.
func TestIssueCertificate_IgnoresACSR(t *testing.T) {
	key := deviceKey(t)
	handlers, _, signer := csrHandlers(t, key)
	csr, err := json.Marshal(string(issuancetest.CSR(t, key, "rpi/fleet")))
	require.NoError(t, err)
	body := []byte(`{"request":{"subject":{"commonName":"rpi/fleet"},"csrPem":` + string(csr) + `}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handlers.IssueCertificate(httptest.NewRecorder(), req)
	assert.Nil(t, signer.Opts, "the issue endpoint certified a CSR")
}

// "kms" names no key store; it used to fall back to a new software key.
func TestIssueCertificate_UnknownStoreType(t *testing.T) {
	handlers, writer := newTestHandlers(&mockCertificateAuthority{initialized: true})

	body, err := protojson.Marshal(&platformv1.IssueCertificateRequest{Request: &platformv1.CertificateRequest{
		Subject:   &platformv1.Subject{CommonName: "rpi/fleet"},
		StoreType: "kms",
	}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ca/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	handlers.IssueCertificate(httptest.NewRecorder(), req)
	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	require.NotNil(t, writer.lastError)
	assert.Contains(t, writer.lastError.Error(), `unknown key store type "kms"`)
}
