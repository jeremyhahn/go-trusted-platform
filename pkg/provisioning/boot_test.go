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

package provisioning

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startBootServer is a TLS 1.3 server that asks for a client certificate, so
// a handler sees the node's IDevID leaf the way the control plane does.
func startBootServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{bundle.ServerCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, bundle.CAPool
}

func newBootClient(t *testing.T, serverURL string, roots *x509.CertPool) *Client {
	t.Helper()
	cert, key := generateTestCertificate(t, "diskless-node")
	client, err := NewClient(&ClientConfig{
		ServerURL:   serverURL,
		Certificate: cert,
		PrivateKey:  key,
		CACertPool:  roots,
	}, logging.DefaultLogger())
	require.NoError(t, err)
	return client
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestBootDelivery_QuotesOverTheServersChannelValue(t *testing.T) {
	var serverNonce []byte
	var received BootDeliveryRequest
	var peerCN string
	server, roots := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, BootDeliveryPath, r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		nonce, err := BootChannelNonce(r.TLS)
		if !assert.NoError(t, err) {
			return
		}
		serverNonce = nonce
		if len(r.TLS.PeerCertificates) > 0 {
			peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		writeJSON(t, w, BootDeliveryResponse{
			Serial:            "node-1",
			IDevIDChain:       "idevid-pem",
			CABundle:          "ca-pem",
			PCRBaselineSource: "signed",
		})
	}))

	var quotedNonce []byte
	client := newBootClient(t, server.URL, roots)
	resp, err := client.BootDelivery(context.Background(), func(_ context.Context, nonce []byte) ([]byte, error) {
		quotedNonce = nonce
		return []byte(`{"quote":"q"}`), nil
	})
	require.NoError(t, err)

	assert.Len(t, quotedNonce, BootChannelNonceSize)
	assert.Equal(t, serverNonce, quotedNonce,
		"the node must quote over the value the server derives from the same connection")
	assert.JSONEq(t, `{"quote":"q"}`, string(received.Evidence))
	assert.Equal(t, "diskless-node", peerCN, "the delivery must present the node certificate")
	assert.Equal(t, "node-1", resp.Serial)
	assert.Equal(t, "signed", resp.PCRBaselineSource)
}

func TestBootDelivery_EachConnectionHasItsOwnNonce(t *testing.T) {
	server, roots := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, BootDeliveryResponse{Serial: "s", IDevIDChain: "c", CABundle: "b"})
	}))
	client := newBootClient(t, server.URL, roots)

	var nonces [][]byte
	quote := func(_ context.Context, nonce []byte) ([]byte, error) {
		nonces = append(nonces, nonce)
		return []byte(`{}`), nil
	}
	for range 2 {
		_, err := client.BootDelivery(context.Background(), quote)
		require.NoError(t, err)
	}
	require.Len(t, nonces, 2)
	assert.NotEqual(t, nonces[0], nonces[1], "a quote for one connection must not fit another")
}

func TestBootDelivery_Failures(t *testing.T) {
	okQuote := func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil }
	quoteErr := errors.New("tpm quote failed")

	cases := map[string]struct {
		handler  http.HandlerFunc
		quote    BootQuoteFunc
		sentinel error
		cause    error
	}{
		"no quote function": {
			quote:    nil,
			sentinel: ErrBootQuoteRequired,
		},
		"quote fails": {
			quote:    func(context.Context, []byte) ([]byte, error) { return nil, quoteErr },
			sentinel: ErrBootDeliveryFailed,
			cause:    quoteErr,
		},
		"server refuses": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "attestation refused", http.StatusForbidden)
			},
			quote:    okQuote,
			sentinel: ErrServerError,
		},
		"response not JSON": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not json"))
			},
			quote:    okQuote,
			sentinel: ErrInvalidResponse,
		},
		"response missing the CA bundle": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, BootDeliveryResponse{Serial: "s", IDevIDChain: "c"})
			},
			quote:    okQuote,
			sentinel: ErrInvalidResponse,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handler := tc.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, BootDeliveryResponse{Serial: "s", IDevIDChain: "c", CABundle: "b"})
				}
			}
			server, roots := startBootServer(t, handler)
			client := newBootClient(t, server.URL, roots)

			_, err := client.BootDelivery(context.Background(), tc.quote)
			require.ErrorIs(t, err, tc.sentinel)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
		})
	}
}

func TestBootDelivery_ServerRefusalCarriesStatusAndMessage(t *testing.T) {
	server, roots := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "quote nonce is not bound to this connection", http.StatusForbidden)
	}))
	client := newBootClient(t, server.URL, roots)

	_, err := client.BootDelivery(context.Background(), func(context.Context, []byte) ([]byte, error) {
		return []byte(`{}`), nil
	})
	require.ErrorIs(t, err, ErrServerError)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "not bound to this connection")
}

func TestBootDelivery_UntrustedServerIsNotQuotedFor(t *testing.T) {
	server, _ := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, BootDeliveryResponse{Serial: "s", IDevIDChain: "c", CABundle: "b"})
	}))
	otherRoots := testutil.GenerateTestTLSBundle(t).CAPool
	client := newBootClient(t, server.URL, otherRoots)

	quoted := false
	_, err := client.BootDelivery(context.Background(), func(context.Context, []byte) ([]byte, error) {
		quoted = true
		return []byte(`{}`), nil
	})
	require.ErrorIs(t, err, ErrConnectionFailed)
	assert.False(t, quoted, "the TPM must not quote for a server it does not trust")
}

func TestBootChannelNonce_RefusesAnUnboundChannel(t *testing.T) {
	cases := map[string]*tls.ConnectionState{
		"no TLS":  nil,
		"TLS 1.2": {Version: tls.VersionTLS12},
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BootChannelNonce(state)
			var unbound *ErrBootChannelUnbound
			require.ErrorAs(t, err, &unbound)
		})
	}
}

func newProofKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func TestFetchBootCertificate_ProvesPossessionOverTheConnection(t *testing.T) {
	key := newProofKey(t)
	var received BootCertificateRequest
	var sawClientCert bool
	var proofErr error
	server, roots := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, BootCertificatePath, r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		sawClientCert = len(r.TLS.PeerCertificates) > 0
		nonce, err := BootChannelNonce(r.TLS)
		if !assert.NoError(t, err) {
			return
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&received))
		proofErr = VerifyBootCertificateProof(&key.PublicKey, received.Identity, nonce, received.Signature)
		writeJSON(t, w, BootCertificateResponse{Identity: received.Identity, IDevIDChain: "chain-pem"})
	}))

	resp, err := FetchBootCertificate(context.Background(), server.URL, roots, "node a/1", key, 0)
	require.NoError(t, err)
	assert.Equal(t, "chain-pem", resp.IDevIDChain)
	assert.Equal(t, "node a/1", received.Identity)
	assert.NoError(t, proofErr, "the proof must verify over the value the server derives from the same connection")
	assert.False(t, sawClientCert, "the fetch happens before the node has a certificate to present")
}

func TestFetchBootCertificate_AProofDoesNotFitAnotherConnection(t *testing.T) {
	key := newProofKey(t)
	var nonces [][]byte
	var proofs []BootCertificateRequest
	server, roots := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := BootChannelNonce(r.TLS)
		if !assert.NoError(t, err) {
			return
		}
		var req BootCertificateRequest
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		nonces = append(nonces, nonce)
		proofs = append(proofs, req)
		writeJSON(t, w, BootCertificateResponse{Identity: req.Identity, IDevIDChain: "chain-pem"})
	}))
	for range 2 {
		_, err := FetchBootCertificate(context.Background(), server.URL, roots, "n", key, 0)
		require.NoError(t, err)
	}
	require.Len(t, proofs, 2)
	assert.ErrorIs(t, VerifyBootCertificateProof(&key.PublicKey, "n", nonces[1], proofs[0].Signature), ErrBootProofInvalid,
		"a proof captured on one connection must not be accepted on another")
}

func TestFetchBootCertificate_Failures(t *testing.T) {
	signErr := errors.New("tpm sign failed")
	cases := map[string]struct {
		identity string
		noRoots  bool
		noSigner bool
		signer   crypto.Signer
		handler  http.HandlerFunc
		sentinel error
		cause    error
	}{
		"no identity": {
			sentinel: ErrBootIdentityRequired,
		},
		"no roots": {
			identity: "n",
			noRoots:  true,
			sentinel: ErrMissingCABundle,
		},
		"no signer": {
			identity: "n",
			noSigner: true,
			sentinel: ErrMissingPrivateKey,
		},
		"signing fails": {
			identity: "n",
			signer:   failingSigner{key: newProofKey(t), err: signErr},
			sentinel: ErrBootCertificateFetchFailed,
			cause:    signErr,
		},
		"server refuses": {
			identity: "n",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "boot certificate refused", http.StatusForbidden)
			},
			sentinel: ErrServerError,
		},
		"chain for another identity": {
			identity: "n",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, BootCertificateResponse{Identity: "other", IDevIDChain: "c"})
			},
			sentinel: ErrInvalidResponse,
		},
		"empty chain": {
			identity: "n",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, BootCertificateResponse{Identity: "n"})
			},
			sentinel: ErrInvalidResponse,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handler := tc.handler
			if handler == nil {
				handler = func(w http.ResponseWriter, _ *http.Request) {
					t.Error("the server must not be asked")
				}
			}
			server, roots := startBootServer(t, handler)
			if tc.noRoots {
				roots = nil
			}
			signer := tc.signer
			if signer == nil && !tc.noSigner {
				signer = newProofKey(t)
			}
			_, err := FetchBootCertificate(context.Background(), server.URL, roots, tc.identity, signer, 0)
			require.ErrorIs(t, err, tc.sentinel)
			if tc.cause != nil {
				assert.ErrorIs(t, err, tc.cause)
			}
		})
	}
}

func TestFetchBootCertificate_UntrustedServerGetsNoProof(t *testing.T) {
	server, _ := startBootServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, BootCertificateResponse{Identity: "n", IDevIDChain: "c"})
	}))
	signer := &countingSigner{Signer: newProofKey(t)}

	_, err := FetchBootCertificate(context.Background(), server.URL,
		testutil.GenerateTestTLSBundle(t).CAPool, "n", signer, 0)
	require.ErrorIs(t, err, ErrConnectionFailed)
	assert.Zero(t, signer.calls, "the TPM must not sign for a server it does not trust")
}

func TestBootCertificateProof_RoundTrip(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, BootChannelNonceSize)
	signers := map[string]crypto.Signer{
		"ECDSA": newProofKey(t),
		"RSA":   mustRSAKey(t),
	}
	for name, signer := range signers {
		t.Run(name, func(t *testing.T) {
			sig, err := SignBootCertificateProof(signer, "node-1", nonce)
			require.NoError(t, err)
			require.NoError(t, VerifyBootCertificateProof(signer.Public(), "node-1", nonce, sig))
		})
	}
}

func TestBootCertificateProof_Refusals(t *testing.T) {
	key := newProofKey(t)
	nonce := bytes.Repeat([]byte{7}, BootChannelNonceSize)
	sig, err := SignBootCertificateProof(key, "node-1", nonce)
	require.NoError(t, err)
	other := newProofKey(t)
	otherNonce := bytes.Repeat([]byte{8}, BootChannelNonceSize)
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)-1] ^= 0x01

	cases := map[string]struct {
		pub      crypto.PublicKey
		identity string
		nonce    []byte
		sig      []byte
		sentinel error
	}{
		"another device's key": {&other.PublicKey, "node-1", nonce, sig, ErrBootProofInvalid},
		"another identity":     {&key.PublicKey, "node-2", nonce, sig, ErrBootProofInvalid},
		"another connection":   {&key.PublicKey, "node-1", otherNonce, sig, ErrBootProofInvalid},
		"tampered signature":   {&key.PublicKey, "node-1", nonce, tampered, ErrBootProofInvalid},
		"no signature":         {&key.PublicKey, "node-1", nonce, nil, ErrBootProofInvalid},
		"unbound connection":   {&key.PublicKey, "node-1", nil, sig, ErrBootProofInvalid},
		"unsupported key":      {ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), "node-1", nonce, sig, ErrBootProofKeyUnsupported},
		"RSA key, ECDSA proof": {&mustRSAKey(t).PublicKey, "node-1", nonce, sig, ErrBootProofInvalid},
		"no key":               {nil, "node-1", nonce, sig, ErrBootProofKeyUnsupported},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := VerifyBootCertificateProof(tc.pub, tc.identity, tc.nonce, tc.sig)
			require.ErrorIs(t, err, tc.sentinel)
		})
	}
}

func TestSignBootCertificateProof_Refusals(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = SignBootCertificateProof(edKey, "n", []byte("nonce"))
	assert.ErrorIs(t, err, ErrBootProofKeyUnsupported)

	_, err = SignBootCertificateProof(nil, "n", []byte("nonce"))
	assert.ErrorIs(t, err, ErrMissingPrivateKey)

	signErr := errors.New("tpm sign failed")
	_, err = SignBootCertificateProof(failingSigner{key: newProofKey(t), err: signErr}, "n", []byte("nonce"))
	assert.ErrorIs(t, err, signErr)
}

func TestBootCertificateProofDigest_SeparatesItsFields(t *testing.T) {
	nonce := bytes.Repeat([]byte{1}, BootChannelNonceSize)
	assert.NotEqual(t, BootCertificateProofDigest("ab", nonce), BootCertificateProofDigest("a", append([]byte("b"), nonce[1:]...)),
		"moving a byte between the identity and the nonce must change the digest")
	assert.Equal(t, BootCertificateProofDigest("a", nonce), BootCertificateProofDigest("a", nonce))
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := sharedRSAKey()
	require.NoError(t, err)
	return key
}

// sharedRSAKey is generated once: 2048-bit RSA generation is the slowest
// step in this package's tests, and no test needs a key of its own.
var sharedRSAKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// failingSigner reports a key but cannot sign with it, as a TPM that has
// locked out or lost its policy session.
type failingSigner struct {
	key *ecdsa.PrivateKey
	err error
}

func (s failingSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, s.err
}

type countingSigner struct {
	crypto.Signer
	calls int
}

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	return s.Signer.Sign(r, digest, opts)
}

func TestParseCertificateChain_KeepsCertificatesInOrder(t *testing.T) {
	first := testutil.GenerateTestTLSBundle(t).ServerCert.Certificate[0]
	second := testutil.GenerateTestTLSBundle(t).ServerCert.Certificate[0]
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("skipped")})...)
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second})...)

	chain, err := ParseCertificateChain(chainPEM)
	require.NoError(t, err)
	require.Len(t, chain, 2, "non-certificate blocks are skipped")
	assert.Equal(t, first, chain[0].Raw, "the leaf stays first")
	assert.Equal(t, second, chain[1].Raw)
}

func TestParseCertificateChain_Failures(t *testing.T) {
	cases := map[string][]byte{
		"empty":                     nil,
		"no PEM":                    []byte("not a certificate"),
		"no certificate block":      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("key")}),
		"certificate block garbage": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")}),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCertificateChain(input)
			require.ErrorIs(t, err, ErrCertificateChainInvalid)
		})
	}
}
