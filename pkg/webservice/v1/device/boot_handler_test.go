// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package device

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// startBootControlPlane serves the boot routes over TLS 1.3 the way the
// router mounts them: the certificate route without a client certificate,
// the delivery route behind a stand-in for the mTLS middleware that names
// the caller by its CN.
// daemonHealthResponse is the body the daemon's REST listener answers
// GET /health with when no health registry is wired
// (pkg/api/daemon RESTServer.handleHealth).
type daemonHealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// daemonHealthHandler answers GET /health and GET /health/live the way the
// daemon's REST listener does: unauthenticated, 200, a JSON health body. The
// SDK REST transport probes GET /health/live at connect time and refuses a
// listener that does not answer 2xx. The daemon's own handler cannot be mounted here,
// because pkg/api/daemon imports this package.
func daemonHealthHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		body := daemonHealthResponse{Status: "healthy", Timestamp: time.Now().UTC()}
		assert.NoError(t, json.NewEncoder(w).Encode(body))
	}
}

func startBootControlPlane(t *testing.T, f *bootFixture) *httptest.Server {
	t.Helper()
	handler := NewBootHandler(logging.DefaultLogger(), &mockResponseWriter{}, f.service())
	require.NotNil(t, handler)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", daemonHealthHandler(t))
	mux.HandleFunc("GET /health/live", daemonHealthHandler(t))
	mux.HandleFunc("POST "+provisioning.BootCertificatePath, handler.HandleBootCertificate)
	mux.HandleFunc("POST "+provisioning.BootDeliveryPath, func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		handler.HandleBootDelivery(w, r.WithContext(context.WithValue(r.Context(), ContextKeyDeviceSerial, cn)))
	})

	bundle := testutil.GenerateTestTLSBundle(t)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{bundle.ServerCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.serverRoots = bundle.CAPool
	return server
}

// bootControlPlaneClient trusts the control plane's server certificate.
func bootControlPlaneClient(f *bootFixture) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    f.serverRoots,
		MinVersion: tls.VersionTLS13,
	}}}
}

func TestBootControlPlane_AnswersHealthLikeTheDaemon(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)

	resp, err := bootControlPlaneClient(f).Get(server.URL + "/health")
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	var body daemonHealthResponse
	require.NoError(t, decoder.Decode(&body))
	assert.Equal(t, "healthy", body.Status)
	assert.False(t, body.Timestamp.IsZero())
}

func TestBootControlPlane_RefusesHealthWithAnotherMethod(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)

	resp, err := bootControlPlaneClient(f).Post(server.URL+"/health", "application/json", nil)
	require.NoError(t, err)
	defer func() { assert.NoError(t, resp.Body.Close()) }()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// diskless boots the node side end to end: fetch the recorded chain with a
// proof made by the IDevID key, then deliver over mTLS with a quote built by
// quote.
func (f *bootFixture) disklessBoot(t *testing.T, serverURL string, quote provisioning.BootQuoteFunc) (*provisioning.BootDeliveryResponse, error) {
	t.Helper()
	cert, err := provisioning.FetchBootCertificate(context.Background(), serverURL, f.serverRoots, "node-1.example", f.pki.leafKey, 0)
	require.NoError(t, err)
	assert.Equal(t, f.pki.chainPEM, cert.IDevIDChain)

	client, err := provisioning.NewClient(&provisioning.ClientConfig{
		ServerURL:   serverURL,
		Certificate: f.pki.leaf,
		PrivateKey:  f.pki.leafKey,
		CACertPool:  f.serverRoots,
	}, logging.DefaultLogger())
	require.NoError(t, err)
	return client.BootDelivery(context.Background(), quote)
}

func TestBootHandler_DisklessNodeBootsOverTheRealWire(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)

	var quotedNonce []byte
	resp, err := f.disklessBoot(t, server.URL, func(_ context.Context, nonce []byte) ([]byte, error) {
		quotedNonce = nonce
		return json.Marshal(vm.QuoteEvidence{Quote: []byte("quote"), Signature: []byte("sig"), Nonce: nonce})
	})
	require.NoError(t, err)

	assert.Equal(t, "SN-42", resp.Serial)
	assert.Equal(t, f.pki.chainPEM, resp.IDevIDChain)
	assert.Equal(t, string(f.pki.caPEM), resp.CABundle)
	assert.Equal(t, "SN-42", resp.Profile.SerialNumber)
	assert.Equal(t, "signed", resp.PCRBaselineSource)

	var verified vm.QuoteEvidence
	require.NoError(t, json.Unmarshal(f.attestor.gotEvidence, &verified))
	assert.Equal(t, quotedNonce, verified.Nonce, "the verifier checks the quote over the connection's nonce")
}

func TestBootHandler_CertificateCannotEnumerateDevices(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, enrolledErr := provisioning.FetchBootCertificate(context.Background(), server.URL, f.serverRoots, "node-1.example", stranger, 0)
	_, unknownErr := provisioning.FetchBootCertificate(context.Background(), server.URL, f.serverRoots, "stranger", stranger, 0)

	require.ErrorIs(t, enrolledErr, provisioning.ErrServerError)
	require.ErrorIs(t, unknownErr, provisioning.ErrServerError)
	assert.Contains(t, enrolledErr.Error(), "403")
	assert.Equal(t, enrolledErr.Error(), unknownErr.Error(),
		"an enrolled name without its key must read exactly like a name that was never enrolled")
	assert.NotContains(t, enrolledErr.Error(), "node-1.example")
}

func TestBootHandler_ReplayedQuoteIsRefused(t *testing.T) {
	f := newBootFixture(t)
	server := startBootControlPlane(t, f)

	var captured []byte
	_, err := f.disklessBoot(t, server.URL, func(_ context.Context, nonce []byte) ([]byte, error) {
		evidence, err := json.Marshal(vm.QuoteEvidence{Quote: []byte("quote"), Nonce: nonce})
		captured = evidence
		return evidence, err
	})
	require.NoError(t, err)
	f.attestor.gotEvidence = nil

	// The same evidence, valid a moment ago, offered on a new connection.
	_, err = f.disklessBoot(t, server.URL, func(context.Context, []byte) ([]byte, error) {
		return captured, nil
	})
	require.ErrorIs(t, err, provisioning.ErrServerError)
	assert.Contains(t, err.Error(), "403")
	assert.Nil(t, f.attestor.gotEvidence, "a replayed quote must not reach the verifier")
}

func TestBootHandler_FailedAttestationIsRefused(t *testing.T) {
	f := newBootFixture(t)
	f.attestor.resp.Verified = false
	server := startBootControlPlane(t, f)

	_, err := f.disklessBoot(t, server.URL, func(_ context.Context, nonce []byte) ([]byte, error) {
		return json.Marshal(vm.QuoteEvidence{Quote: []byte("tampered"), Nonce: nonce})
	})
	require.ErrorIs(t, err, provisioning.ErrServerError)
	assert.Contains(t, err.Error(), "403")
}

func TestBootHandler_ErrorStatuses(t *testing.T) {
	storage := errors.New("storage offline")
	cases := map[string]struct {
		mutate   func(f *bootFixture)
		request  func(f *bootFixture) *http.Request
		delivery bool
		want     int
	}{
		"certificate: unknown identity": {
			request: func(f *bootFixture) *http.Request {
				return certificateRequest(t, f, "stranger")
			},
			want: http.StatusForbidden,
		},
		"certificate: proof over another connection": {
			request: func(f *bootFixture) *http.Request {
				return certificateRequest(t, f, "node-1.example")
			},
			want: http.StatusForbidden,
		},
		"certificate: no TLS connection to bind to": {
			request: func(f *bootFixture) *http.Request {
				req := certificateRequest(t, f, "node-1.example")
				req.TLS = nil
				return req
			},
			want: http.StatusBadRequest,
		},
		"certificate: no identity": {
			request: func(*bootFixture) *http.Request {
				return boundRequest(t, provisioning.BootCertificatePath, `{}`)
			},
			want: http.StatusBadRequest,
		},
		"certificate: body not JSON": {
			request: func(*bootFixture) *http.Request {
				return boundRequest(t, provisioning.BootCertificatePath, "nope")
			},
			want: http.StatusBadRequest,
		},
		"certificate: storage fault": {
			mutate: func(f *bootFixture) { f.devices.err = storage },
			request: func(f *bootFixture) *http.Request {
				return certificateRequest(t, f, "node-1.example")
			},
			want: http.StatusInternalServerError,
		},
		"delivery: no identity from the mTLS layer": {
			delivery: true,
			request: func(*bootFixture) *http.Request {
				return boundRequest(t, provisioning.BootDeliveryPath, `{"evidence":"e30="}`)
			},
			want: http.StatusBadRequest,
		},
		"delivery: body not JSON": {
			delivery: true,
			request: func(*bootFixture) *http.Request {
				req := boundRequest(t, provisioning.BootDeliveryPath, "nope")
				return req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "node-1.example"))
			},
			want: http.StatusBadRequest,
		},
		"delivery: TLS 1.2 connection cannot be bound": {
			delivery: true,
			request: func(f *bootFixture) *http.Request {
				req := httptest.NewRequest(http.MethodPost, "https://cp"+provisioning.BootDeliveryPath, bytes.NewBufferString(`{"evidence":"e30="}`))
				req.TLS.PeerCertificates = []*x509.Certificate{f.pki.leaf} // the IDevID check would pass; only the binding fails
				return req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "node-1.example"))
			},
			want: http.StatusBadRequest,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			handler := NewBootHandler(logging.DefaultLogger(), &mockResponseWriter{}, f.service())
			rr := httptest.NewRecorder()
			if tc.delivery {
				handler.HandleBootDelivery(rr, tc.request(f))
			} else {
				handler.HandleBootCertificate(rr, tc.request(f))
			}
			assert.Equal(t, tc.want, rr.Code)
		})
	}
}

// certificateRequest is a well-formed boot-certificate request for identity
// signed by the enrolled key over the fixture's nonce, which is not the
// exporter value of the TLS 1.3 connection the request arrives on.
func certificateRequest(t *testing.T, f *bootFixture, identity string) *http.Request {
	t.Helper()
	body, err := json.Marshal(provisioning.BootCertificateRequest{
		Identity:  identity,
		Signature: f.certificateInput(t, identity, f.pki.leafKey).Signature,
	})
	require.NoError(t, err)
	return boundRequest(t, provisioning.BootCertificatePath, string(body))
}

// boundRequest is a POST to path carrying body, arriving on a real TLS 1.3
// connection so the handler can read a channel binding from it.
func boundRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.TLS = tls13State(t)
	return req
}

// tls13State completes a TLS 1.3 handshake over an in-memory pipe and
// returns the server side's connection state.
func tls13State(t *testing.T) *tls.ConnectionState {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		require.NoError(t, clientConn.Close())
		require.NoError(t, serverConn.Close())
	})
	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{bundle.ServerCert}, MinVersion: tls.VersionTLS13})
	client := tls.Client(clientConn, &tls.Config{RootCAs: bundle.CAPool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	require.NoError(t, client.Handshake())
	require.NoError(t, <-done)
	state := server.ConnectionState()
	return &state
}

func TestBootChannel_IsTheConnectionsExporterValue(t *testing.T) {
	state := tls13State(t)

	nonce, err := BootChannel(state, "REST")

	require.NoError(t, err)
	want, err := provisioning.BootChannelNonce(state)
	require.NoError(t, err)
	assert.Equal(t, want, nonce)
}

func TestBootChannel_RefusesAConnectionWithNoBinding(t *testing.T) {
	for name, state := range map[string]*tls.ConnectionState{
		"no TLS":  nil,
		"TLS 1.2": {Version: tls.VersionTLS12},
	} {
		t.Run(name, func(t *testing.T) {
			nonce, err := BootChannel(state, "Unix")

			assert.Nil(t, nonce)
			var refused ErrBootChannelRequired
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, "Unix", refused.Transport)
			var unbound *provisioning.ErrBootChannelUnbound
			assert.ErrorAs(t, err, &unbound)
		})
	}
}

// A transport that classifies errors by gRPC status (MCP) answers the channel
// refusal with the class gRPC answers it with, wrapped or not.
func TestErrBootChannelRequired_IsFailedPrecondition(t *testing.T) {
	_, refusal := BootChannel(nil, "MCP")
	require.Error(t, refusal)

	for name, err := range map[string]error{
		"as returned": refusal,
		"wrapped":     fmt.Errorf("device_boot_certificate: %w", refusal),
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), "this MCP request has none")
		})
	}
}

func TestNewBootHandler_NilServiceYieldsNilHandler(t *testing.T) {
	assert.Nil(t, NewBootHandler(logging.DefaultLogger(), &mockResponseWriter{}, nil))
}

// The node decodes what the control plane encodes; the two types live on
// either side of an import boundary, so their JSON names are pinned here.
func TestBootDeliveryWireMatchesTheNodeClient(t *testing.T) {
	pairs := map[string][2]any{
		"BootDeliveryResponse": {BootDeliveryResponse{}, provisioning.BootDeliveryResponse{}},
		"ProfileResponse":      {ProfileResponse{}, provisioning.ProfileResponse{}},
	}
	for name, pair := range pairs {
		assert.Equal(t, testutil.GoJSONTagNames(pair[0]), testutil.GoJSONTagNames(pair[1]),
			"%s: server and node client disagree on the wire", name)
	}
}
