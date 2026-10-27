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

package attestation_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/quotebind"
	attestationsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/attestation"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// GetQuote quotes the qualifying data the attestation server hands it, as
// the node's TPM does: a TPMS_ATTEST of type quote whose extraData is that
// data, recorded.
func (q *quotingTPM) GetQuote(_ context.Context, _ *daemon.QuoteConfig, qualifyingData []byte) (*daemon.QuoteResult, error) {
	q.quoted = append(q.quoted, qualifyingData)
	attest := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      tpm2.TPMSTAttestQuote,
		ExtraData: tpm2.TPM2BData{Buffer: qualifyingData},
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(7),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		}),
	})
	return &daemon.QuoteResult{QuoteData: attest, Signature: []byte("ak-signature"), Nonce: qualifyingData}, nil
}

// newQuoteCaller is the SDK attestation client over the production REST
// transport, dialing server with the bundle's client certificate.
func newQuoteCaller(t *testing.T, bundle *testutil.TestTLSBundle, server *httptest.Server) *attestationsvc.Client {
	t.Helper()
	clientTLS := bundle.ClientTLSConfig()
	clientTLS.ServerName = "localhost"
	adapter, err := rest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL),
		platform.WithTLSConfig(clientTLS),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })
	return attestationsvc.NewClientFromGRPC(platformv1.NewAttestationServiceClient(adapter.Connection()))
}

var quoteConfig = &platformv1.AttestationQuoteConfig{PcrIndices: []uint32{7}}

// TestGetAttestationQuote_DirectConnectionIsAccepted: POST
// /api/v1/attestation/quote straight to the node. The node quotes
// SHA-256(nonce || binding) for the connection the request arrived on and
// echoes the binding; the SDK derives the same binding from its end.
func TestGetAttestationQuote_DirectConnectionIsAccepted(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tpm := &quotingTPM{}
	node := newAttestor(t, bundle, tpm)
	nonce := []byte("0123456789abcdef0123456789abcdef")

	resp, err := newQuoteCaller(t, bundle, node).GetAttestationQuote(context.Background(), quoteConfig, nonce)
	require.NoError(t, err)

	require.Len(t, resp.GetChannelBinding(), 32)
	require.Len(t, tpm.quoted, 1)
	assert.Equal(t, xkms.PeerQualifyingData(nonce, resp.GetChannelBinding()), tpm.quoted[0],
		"the node quoted the nonce bound to the echoed connection, not the bare nonce")
}

// TestGetAttestationQuote_RelayedQuoteIsRejected is the oracle #482 closes on
// the quote endpoint: a relay holding a valid certificate forwards the
// caller's request (connection A) to a healthy node over its own connection
// (B). The node quotes the nonce bound to B and echoes B; the caller, holding
// A, refuses the quote.
func TestGetAttestationQuote_RelayedQuoteIsRejected(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	tpm := &quotingTPM{}
	node := newAttestor(t, bundle, tpm)
	relay := newRelay(t, bundle, node)
	nonce := []byte("0123456789abcdef0123456789abcdef")

	_, err := newQuoteCaller(t, bundle, relay).GetAttestationQuote(context.Background(), quoteConfig, nonce)

	var failed *attestationsvc.ErrGetQuoteFailed
	require.ErrorAs(t, err, &failed)
	var notBound *quotebind.ErrQuoteNotBound
	require.ErrorAs(t, err, &notBound)
	require.Len(t, tpm.quoted, 1, "the healthy node was reached through the relay and did quote")
	assert.NotEqual(t, nonce, tpm.quoted[0], "the node never quotes the caller's nonce as sent")
}

// TestGetAttestationQuote_RefusesPlainHTTP: a request with no TLS connection
// has nothing to bind, so the node refuses it before the TPM is asked.
func TestGetAttestationQuote_RefusesPlainHTTP(t *testing.T) {
	tpm := &quotingTPM{}
	node := httptest.NewServer(attestorRouter(tpm))
	t.Cleanup(node.Close)
	body := `{"nonce":"` + base64.StdEncoding.EncodeToString([]byte("nonce")) + `","config":{"pcrIndices":[7]}}`

	resp, err := node.Client().Post(node.URL+"/api/v1/attestation/quote", "application/json", strings.NewReader(body))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, resp.Body.Close()) })

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	reason, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(reason), "this REST request has none", "refused for the missing binding, not a bad body")
	assert.Empty(t, tpm.quoted, "the TPM was never asked to quote")
}
