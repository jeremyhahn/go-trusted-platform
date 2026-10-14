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

package tpm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
)

// certifyingTPM certifies any key under a fresh ECDSA IAK and records the
// handles it was asked to certify.
type certifyingTPM struct {
	xkmssdk.TrustedPlatformModule
	t         *testing.T
	certified []tpmgo.TPMHandle
}

func (c *certifyingTPM) CertifyKey(keyAttrs *xkmssdk.KeyAttributes, nonce []byte, _ xkmssdk.TPMKeyBackend) (*xkmssdk.CertifyResult, error) {
	c.certified = append(c.certified, keyAttrs.TPMAttributes.Handle)
	iak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(c.t, err)
	return &xkmssdk.CertifyResult{
		CertifyInfo:        []byte("attest"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		AttestingKeyPublic: &iak.PublicKey,
		AttestedKeyPublic:  &iak.PublicKey,
		Nonce:              nonce,
	}, nil
}

func (c *certifyingTPM) Config() *xkmssdk.TPMConfig { return nil }

func postCertify(t *testing.T, device *certifyingTPM, body string) *httptest.ResponseRecorder {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	server := daemon.NewTPMGRPCService(logger)
	server.SetTPM2Service(device)
	parent := mux.NewRouter()
	tpm.NewTPMRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	w := httptest.NewRecorder()
	parent.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/tpm/certify", strings.NewReader(body)))
	return w
}

func TestCertify_ReturnsTheAttestation(t *testing.T) {
	device := &certifyingTPM{t: t}

	w := postCertify(t, device, `{"keyHandle":2164260865,"nonce":"bm9uY2U="}`)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var envelope struct {
		Payload struct {
			CertifyInfo        []byte `json:"certifyInfo"`
			SignatureAlgorithm string `json:"signatureAlgorithm"`
			Nonce              []byte `json:"nonce"`
		} `json:"payload"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&envelope))
	assert.Equal(t, []byte("attest"), envelope.Payload.CertifyInfo)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), envelope.Payload.SignatureAlgorithm)
	assert.Equal(t, []byte("nonce"), envelope.Payload.Nonce)
	assert.Equal(t, []tpmgo.TPMHandle{0x81000001}, device.certified)
}

func TestCertify_RefusesABadRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"undecodable body", `{"keyHandle":`},
		{"handle zero", `{}`},
		{"transient handle", `{"keyHandle":2147483649}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device := &certifyingTPM{t: t}

			w := postCertify(t, device, tt.body)

			assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
			assert.Empty(t, device.certified, "the TPM must not be asked to certify")
		})
	}
}
