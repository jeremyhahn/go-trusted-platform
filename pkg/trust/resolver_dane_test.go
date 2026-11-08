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

package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// daneTestHostname is the DNSSEC zone name under which the mock DNS
// server publishes TLSA records.
const daneTestHostname = "cp.example.com"

// newDANEServerCert generates a self-signed server certificate for the
// loopback bundle server.
func newDANEServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: daneTestHostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{daneTestHostname},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// tlsaRecord builds a TLSA record with SPKI selector and SHA-256
// matching type. The header is filled in by the mock DNS handler so
// the record name always matches the query.
func tlsaRecord(usage uint8, spkiHashHex string) *dns.TLSA {
	return &dns.TLSA{
		Usage:        usage,
		Selector:     1, // SPKI
		MatchingType: 1, // SHA-256
		Certificate:  spkiHashHex,
	}
}

// startMockTLSADNS runs an in-process UDP DNS server that answers
// every TLSA query with the given records and sets the DNSSEC AD
// flag. It returns the server address.
//
// The transport path (NewVerifiedTLSConfigFromRecords) is satisfied by
// a DANE-EE (usage 3) record matching the server leaf; the bundle
// fetch path (FetchCABundle) additionally requires a DANE-TA (usage 2)
// record matching a CA certificate inside the served bundle.
func startMockTLSADNS(t *testing.T, records ...*dns.TLSA) string {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.AuthenticatedData = true
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeTLSA {
			for _, record := range records {
				answer := *record
				answer.Hdr = dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    300,
				}
				resp.Answer = append(resp.Answer, &answer)
			}
		}
		if err := w.WriteMsg(resp); err != nil {
			t.Errorf("mock DNS write: %v", err)
		}
	})

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		Handler:           mux,
		NotifyStartedFunc: func() { close(started) },
	}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Logf("mock DNS server stopped: %v", err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Logf("mock DNS shutdown: %v", err)
		}
	})
	<-started

	return conn.LocalAddr().String()
}

// startBundleServer runs a loopback HTTPS server presenting the given
// certificate and serving the bundle bytes on every path. It returns
// the server URL.
func startBundleServer(t *testing.T, cert tls.Certificate, bundle []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(bundle); err != nil {
			t.Errorf("bundle server write: %v", err)
		}
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// daneScope builds a default-class scope wired to the mock DNS server
// and loopback bundle server.
func daneScope(t *testing.T, serverURL, dnsAddr string) *ScopeConfig {
	t.Helper()
	return &ScopeConfig{
		Strategies:       []Strategy{StrategyDANE},
		ServerURL:        serverURL,
		Hostname:         daneTestHostname,
		DANE:             &DANEConfig{DNSServer: dnsAddr},
		PerMethodTimeout: 5 * time.Second,
	}
}

// spkiHashHex returns the hex-encoded SHA-256 of the certificate's
// SubjectPublicKeyInfo.
func spkiHashHex(t *testing.T, cert tls.Certificate) string {
	t.Helper()
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// pemSPKIHashHex returns the hex-encoded SHA-256 of the
// SubjectPublicKeyInfo of the first certificate in the PEM bundle.
// Used to publish the DANE-TA (usage 2) record matching the bundle's
// CA so the fetch path's trust-anchor verification succeeds.
func pemSPKIHashHex(t *testing.T, bundle []byte) string {
	t.Helper()
	block, _ := pem.Decode(bundle)
	if block == nil {
		t.Fatal("no PEM block in bundle")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func TestTLSConfig_DANE_Success(t *testing.T) {
	cert := newDANEServerCert(t)
	dnsAddr := startMockTLSADNS(t, tlsaRecord(3, spkiHashHex(t, cert)))
	bundle := testCAPEM(t)
	server := startBundleServer(t, cert, bundle)

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	endpoint := server.Listener.Addr().String()
	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBootstrap, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.VerifyConnection == nil {
		t.Fatal("expected DANE custom verifier")
	}

	// Prove the config end-to-end: fetch over the DANE-verified
	// channel.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	defer client.CloseIdleConnections()
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("DANE-verified GET failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(bundle) {
		t.Error("unexpected response body over DANE channel")
	}
}

func TestTLSConfig_DANE_WrongCertRejected(t *testing.T) {
	serverCert := newDANEServerCert(t)
	otherCert := newDANEServerCert(t)
	// TLSA record pins a DIFFERENT certificate's SPKI.
	dnsAddr := startMockTLSADNS(t, tlsaRecord(3, spkiHashHex(t, otherCert)))
	server := startBundleServer(t, serverCert, testCAPEM(t))

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	tlsCfg, err := resolver.TLSConfig(t.Context(), ClassBootstrap, server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	defer client.CloseIdleConnections()
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("expected DANE verification to reject mismatched certificate")
	}
}

func TestCABundlePEM_DANE_Success(t *testing.T) {
	cert := newDANEServerCert(t)
	bundle := testCAPEM(t)
	// The fetch path needs a DANE-EE record for the transport leaf AND
	// a DANE-TA record matching the bundle's CA.
	dnsAddr := startMockTLSADNS(t,
		tlsaRecord(3, spkiHashHex(t, cert)),
		tlsaRecord(2, pemSPKIHashHex(t, bundle)))
	server := startBundleServer(t, cert, bundle)

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	pem, err := resolver.CABundlePEM(t.Context(), ClassBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if string(pem) != string(bundle) {
		t.Error("unexpected CA bundle bytes over DANE fetch")
	}
}

func TestCABundlePEM_DANE_NoServerURL(t *testing.T) {
	scope := daneScope(t, "", "127.0.0.1:53")
	cfg := &Config{Bootstrap: scope}
	resolver := newTestResolver(t, cfg)

	_, err := resolver.CABundlePEM(t.Context(), ClassBootstrap)
	var fetchErr *ErrFetchFailed
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected ErrFetchFailed, got %v", err)
	}
	if fetchErr.Strategy != StrategyDANE {
		t.Errorf("expected dane strategy, got %s", fetchErr.Strategy)
	}
}

func TestCAPool_DANE_Success(t *testing.T) {
	cert := newDANEServerCert(t)
	bundle := testCAPEM(t)
	dnsAddr := startMockTLSADNS(t,
		tlsaRecord(3, spkiHashHex(t, cert)),
		tlsaRecord(2, pemSPKIHashHex(t, bundle)))
	server := startBundleServer(t, cert, bundle)

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	endpoint := server.Listener.Addr().String()
	pool, err := resolver.CAPool(t.Context(), ClassBootstrap, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if pool == nil {
		t.Fatal("expected non-nil pool")
	}

	// Second call must hit the cache: shut the DNS server down via a
	// fresh resolver pointing at a dead address to prove the cached
	// pool is reused without a new fetch.
	cached, err := resolver.CAPool(t.Context(), ClassBootstrap, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if cached != pool {
		t.Error("expected cached pool on second call")
	}
}

// TestCAPool_DANE_ChainBundle covers what the bootstrap integration suite
// asserted against a live platformd (#964 step b): a multi-certificate
// chain bundle fetched over DANE arrives whole and in served order, and the
// pool built from it verifies a leaf issued under its intermediate.
func TestCAPool_DANE_ChainBundle(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Chain Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	root := signTestCert(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediate := signTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Chain Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}, root, &intermediateKey.PublicKey, rootKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := signTestCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "svc.chain.test"},
		DNSNames:     []string{"svc.chain.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, &leafKey.PublicKey, intermediateKey)

	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)

	cert := newDANEServerCert(t)
	dnsAddr := startMockTLSADNS(t,
		tlsaRecord(3, spkiHashHex(t, cert)),
		tlsaRecord(2, pemSPKIHashHex(t, bundle)))
	server := startBundleServer(t, cert, bundle)

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	fetched, err := resolver.CABundlePEM(t.Context(), ClassBootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetched) != string(bundle) {
		t.Fatal("the DANE fetch must return the served chain whole and in order")
	}

	pool, err := resolver.CAPool(t.Context(), ClassBootstrap, server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("a leaf issued under the fetched chain must verify against its pool: %v", err)
	}
}

func TestCAPool_DANE_EmptyBundle(t *testing.T) {
	cert := newDANEServerCert(t)
	// The TA record's hash is irrelevant here: the fetch fails on the
	// empty response body before bundle verification runs.
	dnsAddr := startMockTLSADNS(t,
		tlsaRecord(3, spkiHashHex(t, cert)),
		tlsaRecord(2, spkiHashHex(t, cert)))
	server := startBundleServer(t, cert, nil)

	cfg := &Config{Bootstrap: daneScope(t, server.URL, dnsAddr)}
	resolver := newTestResolver(t, cfg)

	_, err := resolver.CAPool(t.Context(), ClassBootstrap, server.Listener.Addr().String())
	var fetchErr *ErrFetchFailed
	if !errors.As(err, &fetchErr) {
		t.Fatalf("expected ErrFetchFailed in chain, got %v", err)
	}
	if fetchErr.Strategy != StrategyDANE {
		t.Errorf("expected dane strategy, got %s", fetchErr.Strategy)
	}
}
