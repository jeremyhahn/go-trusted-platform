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

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
)

// TestCollector_EndToEnd_VerdictReachesDeviceQuoteVerifier is the proof the
// #226 design asked for in code rather than prose: the collector dials a
// node over mTLS with its own nonce, the node's evidence flows through
// NodeQuoteSource into the SAME DeviceQuoteVerifier every transport uses,
// and the verdict lands in both the verifier's sink (event log, quarantine)
// and the collector's cache (the report an operator reads). A cache read
// before collection returns nothing, never a quote.
func TestCollector_EndToEnd_VerdictReachesDeviceQuoteVerifier(t *testing.T) {
	f := newQuoteFixture(t)
	deviceID := strconv.FormatUint(f.device.ID, 10)
	pki := newNodeTestPKI(t, "node-1.example.test")

	// The fake node: requires a client certificate from the PKI and
	// answers POST /api/v1/attestation/host with a quote signed by the
	// device's enrolled AK over the collector's nonce, in the node's
	// protojson envelope.
	signer := f.key
	node := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/attestation/host", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var req struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(body, &req))
		nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(nodeEnvelope(t, signedEvidence(t, signer, nonce, goldenPCRs(), goldenPCRs())))
		require.NoError(t, err)
	}))
	node.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.pool,
		MinVersion:   tls.VersionTLS12,
	}
	node.StartTLS()
	t.Cleanup(node.Close)

	source, err := reporting.NewNodeQuoteSource(reporting.NodeQuoteSourceConfig{
		Addresses: fixedEndpoints{{Address: strings.TrimPrefix(node.URL, "https://"), ServerName: "node-1.example.test", Source: reporting.SourceHeartbeatPeer}},
		TLS: func(context.Context, reporting.Endpoint) (*tls.Config, error) {
			return &tls.Config{Certificates: []tls.Certificate{pki.client}, RootCAs: pki.pool, MinVersion: tls.VersionTLS12}, nil
		},
	})
	require.NoError(t, err)

	verifier, err := DeviceQuoteVerifierForReporting(f.devices, f.profiles, f.trust, f.sink, nil)
	require.NoError(t, err)

	cache := reporting.NewCache(time.Hour)
	collector, err := reporting.NewCollector(reporting.Config{Source: source, Verifier: verifier, Cache: cache})
	require.NoError(t, err)

	_, ok := cache.Report(deviceID)
	assert.False(t, ok, "nothing is collected by reading the cache")

	collector.Collect(context.Background(), deviceID)

	view, ok := cache.View(deviceID)
	require.True(t, ok, "the collector stored a report")
	assert.True(t, view.Verified, view.Message)
	assert.True(t, view.AKCertificateVerified)
	assert.True(t, view.SignatureValid)
	assert.True(t, view.NonceValid)
	assert.True(t, view.PCRsValid)
	assert.True(t, view.PCRBaselineCaptured, "first collection captures the TOFU baseline")
	assert.Equal(t, "tofu", view.PCRBaselineSource)
	assert.False(t, view.CryptographicFailure)
	assert.True(t, view.Fresh)
	assert.Equal(t, "SN-1", view.Serial)

	dv := f.sink.last(t)
	assert.True(t, dv.Passed, "the verdict reached DeviceQuoteVerifier's sink")
	assert.Equal(t, f.device.ID, dv.DeviceID)
	assert.True(t, dv.BaselineCaptured)

	// Second run: a node presenting a quote signed by a key that is NOT the
	// enrolled AK. The verifier ran and said no — a cryptographic failure —
	// and that REPLACES the cached pass, because a verification that ran
	// is a real result.
	rogue, _ := newAttestTestKey(t)
	signer = rogue
	collector.Collect(context.Background(), deviceID)
	view, ok = cache.View(deviceID)
	require.True(t, ok)
	assert.False(t, view.Verified)
	assert.False(t, view.SignatureValid)
	assert.True(t, view.AKCertificateVerified, "the enrolled certificate still chains; the signature is what failed")
	assert.True(t, view.CryptographicFailure)
	dv = f.sink.last(t)
	assert.False(t, dv.Passed)
	assert.True(t, dv.Cryptographic)

	// Third run: the node is unreachable. Absence of evidence is NOT a
	// verdict: the previous (failed) report and its timestamp stay put and
	// the sink sees nothing new.
	node.Close()
	before, _ := cache.Report(deviceID)
	sinkCount := len(f.sink.verdicts)
	collector.Collect(context.Background(), deviceID)
	after, _ := cache.Report(deviceID)
	assert.Same(t, before, after, "an unreachable node leaves the previous report untouched")
	assert.Equal(t, sinkCount, len(f.sink.verdicts), "no verdict is recorded for absent evidence")
}

// fixedEndpoints is an AddressResolver returning a constant list.
type fixedEndpoints []reporting.Endpoint

func (e fixedEndpoints) Endpoints(context.Context, string) ([]reporting.Endpoint, error) {
	return []reporting.Endpoint(e), nil
}

// nodeEnvelope re-encodes verifier-shaped evidence as the node's REST
// envelope around a CollectHostAttestationResponse (protojson names,
// standard base64), which is what a real node's webservice returns.
func nodeEnvelope(t *testing.T, evidence []byte) []byte {
	t.Helper()
	var ev DeviceQuoteEvidence
	require.NoError(t, json.Unmarshal(evidence, &ev))
	pcrs := make([]map[string]any, 0, len(ev.PCRs))
	for idx, val := range ev.PCRs {
		pcrs = append(pcrs, map[string]any{"index": idx, "value": base64.StdEncoding.EncodeToString(val)})
	}
	payload, err := json.Marshal(map[string]any{
		"status": map[string]any{"success": true},
		"attestation": map[string]any{
			"quoteData": base64.StdEncoding.EncodeToString(ev.Quote),
			"signature": base64.StdEncoding.EncodeToString(ev.Signature),
			"pcrs":      pcrs,
			"nonce":     base64.StdEncoding.EncodeToString(ev.Nonce),
		},
	})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{"code": 200, "success": true, "payload": json.RawMessage(payload)})
	require.NoError(t, err)
	return body
}

// nodeTestPKI issues the fake node's server certificate and the collector's
// client certificate from one throwaway root.
type nodeTestPKI struct {
	pool   *x509.CertPool
	server tls.Certificate
	client tls.Certificate
}

func newNodeTestPKI(t *testing.T, serverName string) *nodeTestPKI {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector-test-root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	issue := func(cn string, eku x509.ExtKeyUsage, dns []string) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, DNSNames: dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	return &nodeTestPKI{
		pool:   pool,
		server: issue(serverName, x509.ExtKeyUsageServerAuth, []string{serverName}),
		client: issue("cp.example.test", x509.ExtKeyUsageClientAuth, []string{"cp.example.test"}),
	}
}
