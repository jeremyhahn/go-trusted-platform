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

package vpn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
)

// listenerPKI is a throwaway device-identity anchor with the certificates the
// listener tests present.
type listenerPKI struct {
	pool    *x509.CertPool
	server  tls.Certificate
	device  tls.Certificate
	other   tls.Certificate // a second device under the same anchor
	expired tls.Certificate
	foreign tls.Certificate // a device under another CA
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

// issue signs a leaf valid over [notBefore, notAfter] for usage.
func (ca *testCA) issue(t *testing.T, name string, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func newListenerPKI(t *testing.T) *listenerPKI {
	t.Helper()
	anchor := newTestCA(t, "device anchor")
	stranger := newTestCA(t, "another CA")
	now := time.Now()
	valid := func(ca *testCA, name string, usage x509.ExtKeyUsage) tls.Certificate {
		return ca.issue(t, name, usage, now.Add(-time.Minute), now.Add(time.Hour))
	}
	pool := x509.NewCertPool()
	pool.AddCert(anchor.cert)
	return &listenerPKI{
		pool:    pool,
		server:  valid(anchor, "gateway", x509.ExtKeyUsageServerAuth),
		device:  valid(anchor, "mini-99", x509.ExtKeyUsageClientAuth),
		other:   valid(anchor, "mini-42", x509.ExtKeyUsageClientAuth),
		expired: anchor.issue(t, "mini-99", x509.ExtKeyUsageClientAuth, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		foreign: valid(stranger, "mini-99", x509.ExtKeyUsageClientAuth),
	}
}

// staticCAs is a ClientCASource with a fixed answer.
type staticCAs struct {
	pool *x509.CertPool
	err  error
}

func (s staticCAs) CAPool(context.Context) (*x509.CertPool, error) { return s.pool, s.err }

// newTestListener builds a listener on the harness's service, bound to a
// loopback port the kernel picks.
func newTestListener(t *testing.T, h *harness, pki *listenerPKI, cas ClientCASource) *AdmissionListener {
	t.Helper()
	l, err := NewAdmissionListener(h.svc, ListenerDeps{Certificate: pki.server, ClientCAs: cas})
	require.NoError(t, err)
	l.address = "127.0.0.1:0"
	return l
}

// startTestListener starts a listener and stops it when the test ends.
func startTestListener(t *testing.T, h *harness, pki *listenerPKI, cas ClientCASource) *AdmissionListener {
	t.Helper()
	l := newTestListener(t, h, pki, cas)
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, l.Start(ctx))
	t.Cleanup(func() {
		cancel()
		<-l.Done()
	})
	return l
}

func newTestClient(t *testing.T, pki *listenerPKI, cert *tls.Certificate) *http.Client {
	t.Helper()
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pki.pool}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	transport := &http.Transport{TLSClientConfig: cfg}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

// send issues one call; body is JSON-encoded unless it is already a string.
func send(t *testing.T, c *http.Client, l *AdmissionListener, method, path string, body any) (*http.Response, []byte, error) {
	t.Helper()
	var payload io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case string:
		payload = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(t, err)
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, "https://"+l.Addr().String()+path, payload)
	require.NoError(t, err)
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, raw, nil
}

func mustSend(t *testing.T, c *http.Client, l *AdmissionListener, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	resp, raw, err := send(t, c, l, method, path, body)
	require.NoError(t, err)
	return resp, raw
}

func challengeOver(t *testing.T, c *http.Client, l *AdmissionListener) []byte {
	t.Helper()
	resp, raw := mustSend(t, c, l, http.MethodPost, PathChallenges, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var ch ChallengeWire
	require.NoError(t, json.Unmarshal(raw, &ch))
	require.NotEmpty(t, ch.Nonce)
	return ch.Nonce
}

func (h *harness) admissionBody(nonce []byte) AdmissionRequestWire {
	return AdmissionRequestWire{
		TenantID:     "tenant-a",
		DeviceID:     "mini-99",
		Nonce:        nonce,
		Attestation:  &AttestationWire{Quote: []byte("quote"), PCRs: []PCRWire{{Index: 7, Value: "abcd"}}},
		Posture:      &PostureReport{SecureBoot: SecureBootPosture{Enabled: true, Available: true}, IMA: IMAPosture{Enabled: true, PolicyLoaded: true}, FDE: FDEPosture{RootEncrypted: true}, AgentVersion: "0.1.0", CollectedAt: h.clock.Now()},
		PersonFactor: &PersonFactorWire{Kind: PersonFactorFIDO2, CredentialID: "cred-1", Assertion: []byte("sig")},
		DataPlane:    DataPlaneMASQUE,
		Zones:        []string{"management"},
	}
}

func (h *harness) renewalBody(nonce []byte) RenewalRequestWire {
	b := h.admissionBody(nonce)
	return RenewalRequestWire{Nonce: nonce, Attestation: b.Attestation, Posture: b.Posture, PersonFactor: b.PersonFactor}
}

// admitOver admits the harness device over the listener and returns its lease.
func admitOver(t *testing.T, h *harness, c *http.Client, l *AdmissionListener) LeaseWire {
	t.Helper()
	resp, raw := mustSend(t, c, l, http.MethodPost, PathAdmissions, h.admissionBody(challengeOver(t, c, l)))
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	var lease LeaseWire
	require.NoError(t, json.Unmarshal(raw, &lease))
	return lease
}

func decodeRefusal(t *testing.T, raw []byte) RefusalWire {
	t.Helper()
	var r RefusalWire
	require.NoError(t, json.Unmarshal(raw, &r), string(raw))
	return r
}

// servingGoroutines returns the stacks of goroutines running the listener,
// an HTTP server or client connection, or a TLS handshake. A raw goroutine
// count also sees the runtime's finalizer and cleanup goroutines.
func servingGoroutines() []string {
	buf := make([]byte, 1<<20)
	var serving []string
	for _, stack := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
		if strings.Contains(stack, "(*AdmissionListener)") || strings.Contains(stack, "net/http.") || strings.Contains(stack, "crypto/tls.") {
			serving = append(serving, stack)
		}
	}
	return serving
}

func TestNewAdmissionListener(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	cas := staticCAs{pool: pki.pool}

	t.Run("binds the configured listener address", func(t *testing.T) {
		cfg := testConfig()
		cfg.Listener = ListenerConfig{BindHost: "192.0.2.1"}
		bound := newHarness(t, cfg)
		l, err := NewAdmissionListener(bound.svc, ListenerDeps{Certificate: pki.server, ClientCAs: cas})
		require.NoError(t, err)
		assert.Equal(t, "192.0.2.1:4433", l.address)
		assert.Nil(t, l.Addr(), "no address before Start")
	})

	t.Run("refuses missing inputs", func(t *testing.T) {
		cases := map[string]struct {
			svc  *Service
			deps ListenerDeps
			dep  string
		}{
			"no service":     {nil, ListenerDeps{Certificate: pki.server, ClientCAs: cas}, "service"},
			"no certificate": {h.svc, ListenerDeps{ClientCAs: cas}, "listener certificate"},
			"no anchor":      {h.svc, ListenerDeps{Certificate: pki.server}, "listener client CA source"},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := NewAdmissionListener(tc.svc, tc.deps)
				var missing *ErrDepsMissing
				require.ErrorAs(t, err, &missing)
				assert.Equal(t, tc.dep, missing.Dep)
			})
		}
	})
}

func TestAdmissionListener_VerbsForAValidDevice(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	l := startTestListener(t, h, pki, staticCAs{pool: pki.pool})
	c := newTestClient(t, pki, &pki.device)

	resp, raw := mustSend(t, c, l, http.MethodPost, PathChallenges, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var ch ChallengeWire
	require.NoError(t, json.Unmarshal(raw, &ch))
	assert.Equal(t, []DataPlaneKind{DataPlaneMASQUE}, ch.DataPlanes, "the challenge offers the configured planes")

	lease := admitOver(t, h, c, l)
	assert.NotEmpty(t, lease.ID)
	assert.Equal(t, "mini-99", lease.DeviceID)
	assert.Equal(t, "tenant-a", lease.TenantID)
	assert.Equal(t, DataPlaneMASQUE, lease.DataPlane)
	assert.True(t, lease.Verdict.Passed)
	assert.Less(t, lease.RenewAtUnix, lease.ExpiresAtUnix, "the lease says when its renewal window opens")
	assert.Greater(t, lease.RenewAtUnix, lease.IssuedAtUnix)

	stored, err := h.store.Get(context.Background(), lease.ID)
	require.NoError(t, err)
	sum := sha256.Sum256(pki.device.Leaf.Raw)
	assert.Equal(t, sum[:], stored.Keys.ClientCertificateSHA256, "the lease binds the presented device certificate")

	h.intoRenewWindow()
	resp, raw = mustSend(t, c, l, http.MethodPost, LeaseRenewPath(lease.ID), h.renewalBody(challengeOver(t, c, l)))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var renewed LeaseWire
	require.NoError(t, json.Unmarshal(raw, &renewed))
	assert.Equal(t, lease.ID, renewed.ID)
	assert.Equal(t, 1, renewed.Renewals)

	resp, raw = mustSend(t, c, l, http.MethodDelete, LeasePath(lease.ID), nil)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, string(raw))
	_, err = h.store.Get(context.Background(), lease.ID)
	var notFound *ErrLeaseNotFound
	require.ErrorAs(t, err, &notFound, "disconnect revokes the lease")
}

func TestAdmissionListener_AnotherDevicesLeaseIsNotFound(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	l := startTestListener(t, h, pki, staticCAs{pool: pki.pool})
	owner := newTestClient(t, pki, &pki.device)
	other := newTestClient(t, pki, &pki.other)
	lease := admitOver(t, h, owner, l)
	h.intoRenewWindow()

	resp, raw := mustSend(t, other, l, http.MethodDelete, LeasePath(lease.ID), nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, RefusalLeaseNotFound, decodeRefusal(t, raw).Reason)

	resp, raw = mustSend(t, other, l, http.MethodPost, LeaseRenewPath(lease.ID), h.renewalBody(challengeOver(t, other, l)))
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, RefusalLeaseNotFound, decodeRefusal(t, raw).Reason)

	_, err := h.store.Get(context.Background(), lease.ID)
	require.NoError(t, err, "the owner's lease survives")
}

func TestAdmissionListener_HandshakeRefusals(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	trusted := startTestListener(t, h, pki, staticCAs{pool: pki.pool})

	cases := map[string]struct {
		listener *AdmissionListener
		cert     *tls.Certificate
	}{
		"no client certificate":       {trusted, nil},
		"certificate from another CA": {trusted, &pki.foreign},
		"expired certificate":         {trusted, &pki.expired},
		"anchor unreadable":           {startTestListener(t, h, pki, staticCAs{err: errors.New("anchor file gone")}), &pki.device},
		"anchor empty":                {startTestListener(t, h, pki, staticCAs{}), &pki.device},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := newTestClient(t, pki, tc.cert)
			resp, _, err := send(t, c, tc.listener, http.MethodPost, PathChallenges, nil)
			require.Error(t, err, "the handshake must fail before any handler runs")
			assert.Nil(t, resp)
		})
	}
	assert.Zero(t, h.verifier.callCount())
}

func TestAdmissionListener_MalformedBodyIsTyped400(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	l := startTestListener(t, h, pki, staticCAs{pool: pki.pool})
	c := newTestClient(t, pki, &pki.device)

	cases := map[string]struct{ path, body string }{
		"not JSON":             {PathAdmissions, "{"},
		"unknown field":        {PathAdmissions, `{"bogus": 1}`},
		"trailing data":        {PathAdmissions, `{}{}`},
		"PCR value is not hex": {PathAdmissions, `{"attestation": {"pcrs": [{"index": 7, "value": "zz"}]}}`},
		"missing fields":       {PathAdmissions, `{}`},
		"renewal not JSON":     {LeaseRenewPath("lease-1"), "["},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resp, raw := mustSend(t, c, l, http.MethodPost, tc.path, tc.body)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			assert.Equal(t, RefusalWire{Reason: RefusalInvalidRequest}, decodeRefusal(t, raw))
		})
	}
}

func TestAdmissionListener_RefusalCarriesOnlyTheClass(t *testing.T) {
	h := newHarness(t, testConfig())
	h.verifier.err = errors.New("quote signature does not verify")
	pki := newListenerPKI(t)
	l := startTestListener(t, h, pki, staticCAs{pool: pki.pool})
	c := newTestClient(t, pki, &pki.device)

	resp, raw := mustSend(t, c, l, http.MethodPost, PathAdmissions, h.admissionBody(challengeOver(t, c, l)))
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, RefusalWire{Reason: RefusalAttestationFailed}, decodeRefusal(t, raw))
	assert.NotContains(t, string(raw), "signature", "the verifier's detail stays on the gateway")
}

func TestAdmissionListener_ShutdownReleasesThePort(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	require.Eventually(t, func() bool { return len(servingGoroutines()) == 0 },
		5*time.Second, 10*time.Millisecond, "earlier tests' connections have closed")

	l := newTestListener(t, h, pki, staticCAs{pool: pki.pool})
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, l.Start(ctx))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pki.pool, Certificates: []tls.Certificate{pki.device}}}
	challengeOver(t, &http.Client{Transport: transport}, l)
	addr := l.Addr().String()

	cancel()
	select {
	case <-l.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the listener did not stop after its context was cancelled")
	}
	transport.CloseIdleConnections()

	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the port is released")
	require.NoError(t, ln.Close())
	var serving []string
	if !assert.Eventually(t, func() bool { serving = servingGoroutines(); return len(serving) == 0 },
		5*time.Second, 10*time.Millisecond, "the listener's goroutines exit") {
		t.Logf("goroutines still serving:\n%s", strings.Join(serving, "\n\n"))
	}
}

func TestAdmissionListener_StartErrors(t *testing.T) {
	h := newHarness(t, testConfig())
	pki := newListenerPKI(t)
	cas := staticCAs{pool: pki.pool}

	t.Run("starts once", func(t *testing.T) {
		l := startTestListener(t, h, pki, cas)
		err := l.Start(context.Background())
		var already *ErrAlreadyStarted
		require.ErrorAs(t, err, &already)
	})

	t.Run("a taken port is a typed bind error and leaves the listener startable", func(t *testing.T) {
		taken, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer taken.Close()

		l := newTestListener(t, h, pki, cas)
		l.address = taken.Addr().String()
		err = l.Start(context.Background())
		var bind *ErrListenerBind
		require.ErrorAs(t, err, &bind)
		assert.Equal(t, taken.Addr().String(), bind.Address)

		l.address = "127.0.0.1:0"
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, l.Start(ctx))
		cancel()
		<-l.Done()
	})
}

func TestWireConversion_NilPartsStayNil(t *testing.T) {
	body := AdmissionRequestWire{TenantID: "tenant-a", DeviceID: "mini-99"}
	req, err := body.request(&calleradmission.Peer{})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", req.TenantID)
	assert.Nil(t, req.Attestation, "a missing attestation is refused by the service, not invented")
	assert.Nil(t, req.PersonFactor)

	ev, err := (&RenewalRequestWire{Nonce: []byte("n"), Attestation: &AttestationWire{Quote: []byte("q")}}).evidence()
	require.NoError(t, err)
	require.NotNil(t, ev.Attestation)
	assert.Equal(t, []byte("n"), ev.Attestation.Nonce, "the attestation is bound to the echoed nonce")
	assert.Nil(t, ev.PersonFactor)
}

func TestWireConversion_PCRsArriveDecodedAndBound(t *testing.T) {
	body := AdmissionRequestWire{
		Nonce:       []byte("n"),
		Attestation: &AttestationWire{PCRs: []PCRWire{{Index: 7, Value: "abcd"}}},
		Peer:        PeerWire{WireGuardPublicKey: []byte("wg-key")},
	}
	req, err := body.request(&calleradmission.Peer{})
	require.NoError(t, err)
	require.NotNil(t, req.Attestation)
	require.Len(t, req.Attestation.PCRs, 1)
	assert.Equal(t, []byte{0xab, 0xcd}, req.Attestation.PCRs[0].Value, "PCR values arrive hex-decoded")
	assert.Equal(t, []byte("n"), req.Attestation.Nonce)
	assert.Equal(t, []byte("wg-key"), req.Keys.WireGuardPublicKey)
}

func TestWireConversion_NonHexPCRIsInvalidRequest(t *testing.T) {
	bad := &AttestationWire{PCRs: []PCRWire{{Index: 7, Value: "zz"}}}
	var invalid *ErrInvalidRequest

	_, err := (&AdmissionRequestWire{Attestation: bad}).request(&calleradmission.Peer{})
	require.ErrorAs(t, err, &invalid)

	_, err = (&RenewalRequestWire{Attestation: bad}).evidence()
	require.ErrorAs(t, err, &invalid)
}
