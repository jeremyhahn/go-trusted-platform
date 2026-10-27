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
	"crypto"
	"crypto/x509"
	"encoding/base64"
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
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
)

// quotingTPM stands in for the node's TPM: it records the qualifying data
// the TPM service hands it.
type quotingTPM struct {
	xkmssdk.TrustedPlatformModule
	quoted []byte
}

func (q *quotingTPM) Quote(_ []uint, nonce []byte) (xkmssdk.Quote, error) {
	q.quoted = nonce
	return xkmssdk.Quote{Quoted: []byte("attest"), Signature: []byte("sig")}, nil
}

// IAKAttributes declares an RSA-PSS IAK, the scheme the quote is signed under.
func (q *quotingTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:       x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		Hash:               crypto.SHA256,
	}, nil
}

// quoteRouter serves POST /api/v1/tpm/quote over the production TPM service.
func quoteRouter(tpmDevice *quotingTPM) http.Handler {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	server := daemon.NewTPMGRPCService(logger)
	server.SetTPM2Service(tpmDevice)
	parent := mux.NewRouter()
	tpm.NewTPMRouter(logger, server, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return parent
}

func postQuote(t *testing.T, client *http.Client, url string, nonce []byte) *http.Response {
	t.Helper()
	body := `{"nonce":"` + base64.StdEncoding.EncodeToString(nonce) + `","pcrIndices":[7]}`
	resp, err := client.Post(url+"/api/v1/tpm/quote", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resp.Body.Close()) })
	return resp
}

// TestQuote_BindsTheConnectionItArrivedOn: over TLS the node quotes
// SHA-256(nonce || binding) and echoes the binding, which is the exporter
// the caller derives from its own end of the connection (#482).
func TestQuote_BindsTheConnectionItArrivedOn(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tpmDevice := &quotingTPM{}
	node := httptest.NewUnstartedServer(quoteRouter(tpmDevice))
	node.TLS = bundle.ServerTLSConfig()
	node.StartTLS()
	t.Cleanup(node.Close)
	clientTLS := bundle.ClientTLSConfig()
	clientTLS.ServerName = "localhost"
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	t.Cleanup(client.CloseIdleConnections)
	nonce := []byte("tpm-nonce")

	resp := postQuote(t, client, node.URL, nonce)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var envelope struct {
		Payload struct {
			ChannelBinding     []byte `json:"channelBinding"`
			SignatureAlgorithm string `json:"signatureAlgorithm"`
		} `json:"payload"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	callerBinding, err := xkmssdk.PeerChannelBinding(resp.TLS)
	require.NoError(t, err)
	assert.Equal(t, callerBinding, envelope.Payload.ChannelBinding, "the echo is the caller's own connection")
	assert.Equal(t, testutil.PSSQuoteScheme, envelope.Payload.SignatureAlgorithm, "the quote names the scheme it is signed under")
	assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, callerBinding), tpmDevice.quoted,
		"the TPM quoted the nonce bound to the connection, not the nonce as sent")
}

// TestQuote_RefusesPlainHTTP: a request with no TLS connection has nothing to
// bind, so the node refuses it before the TPM is asked.
func TestQuote_RefusesPlainHTTP(t *testing.T) {
	tpmDevice := &quotingTPM{}
	node := httptest.NewServer(quoteRouter(tpmDevice))
	t.Cleanup(node.Close)

	resp := postQuote(t, node.Client(), node.URL, []byte("tpm-nonce"))

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	reason, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(reason), "this REST request has none", "refused for the missing binding, not a bad body")
	assert.Nil(t, tpmDevice.quoted, "the TPM was never asked to quote")
}

// TestVerifyQuote_UsesTheDeclaredScheme: POST /api/v1/tpm/quote/verify
// checks the signature under the scheme the request declares (#482). An
// RSA-PSS quote verifies under SHA256-RSAPSS; with no scheme, or PKCS#1
// v1.5 inferred from the RSA key, it does not.
func TestVerifyQuote_UsesTheDeclaredScheme(t *testing.T) {
	quote := tpmgo.Marshal(tpmgo.TPMSAttest{
		Magic:    tpmgo.TPMGeneratedValue,
		Type:     tpmgo.TPMSTAttestQuote,
		Attested: tpmgo.NewTPMUAttest(tpmgo.TPMSTAttestQuote, &tpmgo.TPMSQuoteInfo{}),
	})
	signature, akPublic := testutil.SignPSSQuote(t, quote)
	router := quoteRouter(&quotingTPM{})
	verify := func(scheme string) (bool, string) {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"quote":              base64.StdEncoding.EncodeToString(quote),
			"signature":          base64.StdEncoding.EncodeToString(signature),
			"akPublic":           base64.StdEncoding.EncodeToString(akPublic),
			"signatureAlgorithm": scheme,
		})
		require.NoError(t, err)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/tpm/quote/verify", strings.NewReader(string(body))))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var envelope struct {
			Payload struct {
				Verified bool   `json:"verified"`
				Message  string `json:"message"`
			} `json:"payload"`
		}
		require.NoError(t, json.NewDecoder(w.Body).Decode(&envelope))
		return envelope.Payload.Verified, envelope.Payload.Message
	}

	verified, message := verify(testutil.PSSQuoteScheme)
	assert.True(t, verified, message)

	for _, scheme := range []string{"", x509.SHA256WithRSA.String()} {
		verified, message := verify(scheme)
		assert.False(t, verified, "scheme %q", scheme)
		assert.Contains(t, message, "signature_verification_failed", "scheme %q", scheme)
	}
}
