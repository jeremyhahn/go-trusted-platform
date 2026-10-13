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

package quotebind

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

var testNonce = []byte("a-caller-nonce-0123456789abcdef")

// tlsPair completes a real TLS handshake over an in-memory pipe and
// returns both ends' connection states.
func tlsPair(t *testing.T, version uint16) (client, server tls.ConnectionState) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quotebind-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"quotebind-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		if err := clientConn.Close(); err != nil {
			t.Logf("close client pipe: %v", err)
		}
		if err := serverConn.Close(); err != nil {
			t.Logf("close server pipe: %v", err)
		}
	})
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	srv := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version})
	cli := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: "quotebind-test", MinVersion: version, MaxVersion: version})

	done := make(chan error, 1)
	go func() { done <- srv.Handshake() }()
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return cli.ConnectionState(), srv.ConnectionState()
}

// capturedOver runs c's call option the way a transport adapter does for a
// call travelling on the connection whose client end is state.
func capturedOver(t *testing.T, state *tls.ConnectionState) (*Capture, error) {
	t.Helper()
	c := &Capture{}
	binder, ok := transport.ChannelBindingFrom([]grpc.CallOption{c.Option()})
	if !ok {
		t.Fatal("Option carries no channel binding")
	}
	return c, transport.BindChannel(context.Background(), "test", state, binder)
}

// nodeBinding is the binding the node derives from its end of a connection.
func nodeBinding(t *testing.T, state *tls.ConnectionState) []byte {
	t.Helper()
	binding, err := xkms.PeerChannelBinding(state)
	if err != nil {
		t.Fatalf("node exporter: %v", err)
	}
	return binding
}

// quoteOf marshals a TPMS_ATTEST of type attestType carrying qualifying.
func quoteOf(attestType tpm2.TPMISTAttest, qualifying []byte) []byte {
	attest := tpm2.TPMSAttest{
		Magic:     tpm2.TPMGeneratedValue,
		Type:      attestType,
		ExtraData: tpm2.TPM2BData{Buffer: qualifying},
	}
	if attestType == tpm2.TPMSTAttestQuote {
		attest.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(0),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)},
		})
	} else {
		attest.Attested = tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{
			Name:          tpm2.TPM2BName{Buffer: []byte("n")},
			QualifiedName: tpm2.TPM2BName{Buffer: []byte("q")},
		})
	}
	return tpm2.Marshal(attest)
}

func requireNotBound(t *testing.T, err error) {
	t.Helper()
	var notBound *ErrQuoteNotBound
	if !errors.As(err, &notBound) {
		t.Fatalf("err = %v, want ErrQuoteNotBound", err)
	}
}

func TestCapture_AcceptsTheQuoteBoundToItsConnection(t *testing.T) {
	client, server := tlsPair(t, tls.VersionTLS13)
	c, err := capturedOver(t, &client)
	if err != nil {
		t.Fatalf("binding the call: %v", err)
	}
	binding := nodeBinding(t, &server)
	if !bytes.Equal(c.Binding(), binding) {
		t.Fatal("the captured binding differs from the node's for the same connection")
	}

	quote := quoteOf(tpm2.TPMSTAttestQuote, xkms.PeerQualifyingData(testNonce, binding))
	if err := c.Check(testNonce, quote); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if err := c.CheckEcho(testNonce, binding, quote); err != nil {
		t.Fatalf("CheckEcho: %v", err)
	}
}

func TestCapture_RefusesARelayedQuote(t *testing.T) {
	// The caller talks to a relay over A; the relay forwards the nonce to
	// the node over B, so the node quotes and echoes B's binding.
	callerToRelay, _ := tlsPair(t, tls.VersionTLS13)
	_, relayToNode := tlsPair(t, tls.VersionTLS13)
	c, err := capturedOver(t, &callerToRelay)
	if err != nil {
		t.Fatalf("binding the call: %v", err)
	}
	nodeSide := nodeBinding(t, &relayToNode)
	quote := quoteOf(tpm2.TPMSTAttestQuote, xkms.PeerQualifyingData(testNonce, nodeSide))

	requireNotBound(t, c.Check(testNonce, quote))
	requireNotBound(t, c.CheckEcho(testNonce, nodeSide, quote))
	// A relay that rewrites the unsigned echo still fails on the quote.
	requireNotBound(t, c.CheckEcho(testNonce, c.Binding(), quote))
}

func TestCapture_RefusesAQuoteOfTheBareNonce(t *testing.T) {
	client, server := tlsPair(t, tls.VersionTLS13)
	c, err := capturedOver(t, &client)
	if err != nil {
		t.Fatalf("binding the call: %v", err)
	}
	quote := quoteOf(tpm2.TPMSTAttestQuote, testNonce)
	requireNotBound(t, c.CheckEcho(testNonce, nodeBinding(t, &server), quote))
}

func TestCapture_RefusesWhenNoBindingWasDerived(t *testing.T) {
	c := &Capture{}
	quote := quoteOf(tpm2.TPMSTAttestQuote, testNonce)
	requireNotBound(t, c.Check(testNonce, quote))
	requireNotBound(t, c.CheckEcho(testNonce, nil, quote))
}

func TestCapture_OptionRefusesAConnectionWithoutTLS13(t *testing.T) {
	client12, _ := tlsPair(t, tls.VersionTLS12)
	for name, state := range map[string]*tls.ConnectionState{"no TLS": nil, "TLS 1.2": &client12} {
		t.Run(name, func(t *testing.T) {
			c, err := capturedOver(t, state)
			var unavailable *transport.ErrChannelBindingUnavailable
			if !errors.As(err, &unavailable) {
				t.Fatalf("err = %v, want ErrChannelBindingUnavailable", err)
			}
			if c.Binding() != nil {
				t.Fatal("a binding was captured from a connection that cannot be bound")
			}
		})
	}
}

func TestQuotedData(t *testing.T) {
	got, err := QuotedData(quoteOf(tpm2.TPMSTAttestQuote, testNonce))
	if err != nil {
		t.Fatalf("QuotedData: %v", err)
	}
	if !bytes.Equal(got, testNonce) {
		t.Fatalf("QuotedData = %x, want %x", got, testNonce)
	}
}

func TestQuotedData_RefusesWhatIsNotAQuote(t *testing.T) {
	tests := map[string][]byte{
		"garbage": []byte("not a quote"),
		"empty":   nil,
		"certify": quoteOf(tpm2.TPMSTAttestCertify, testNonce),
	}
	for name, quote := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := QuotedData(quote)
			var malformed *ErrQuoteMalformed
			if !errors.As(err, &malformed) {
				t.Fatalf("err = %v, want ErrQuoteMalformed", err)
			}
		})
	}
}
