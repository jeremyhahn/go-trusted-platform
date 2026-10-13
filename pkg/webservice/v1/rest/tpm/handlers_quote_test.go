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
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
			ChannelBinding []byte `json:"channelBinding"`
		} `json:"payload"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	callerBinding, err := xkmssdk.PeerChannelBinding(resp.TLS)
	require.NoError(t, err)
	assert.Equal(t, callerBinding, envelope.Payload.ChannelBinding, "the echo is the caller's own connection")
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

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	reason, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(reason), "this REST request has none", "refused for the missing binding, not a bad body")
	assert.Nil(t, tpmDevice.quoted, "the TPM was never asked to quote")
}
