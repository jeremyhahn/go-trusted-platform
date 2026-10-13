// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net"
	"testing"

	tpmgo "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// boundQuoteContexts returns, per transport, the context a quote handler
// sees for a request that arrived over a TLS 1.3 connection whose
// server-side state is the argument.
func boundQuoteContexts() map[string]func(*tls.ConnectionState) context.Context {
	return map[string]func(*tls.ConnectionState) context.Context{
		"REST": func(state *tls.ConnectionState) context.Context {
			return channelbind.WithConnectionTLS(context.Background(), channelbind.TransportREST, state)
		},
		"MCP": func(state *tls.ConnectionState) context.Context {
			return channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, state)
		},
		"QUIC": func(state *tls.ConnectionState) context.Context {
			return apiquic.WithConnectionTLS(context.Background(), state)
		},
		"gRPC": func(state *tls.ConnectionState) context.Context {
			return peer.NewContext(context.Background(), &peer.Peer{
				Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10443},
				AuthInfo: credentials.TLSInfo{State: *state},
			})
		},
	}
}

// unboundQuoteCase is a request context with no channel binding, and the
// transport the refusal must name.
type unboundQuoteCase struct {
	name      string
	ctx       context.Context
	transport string
}

// unboundQuoteContexts is every way a quote request can arrive with no TLS
// connection to bind to.
func unboundQuoteContexts() []unboundQuoteCase {
	notComplete := &tls.ConnectionState{Version: tls.VersionTLS12}
	return []unboundQuoteCase{
		{"embedded transport", context.Background(), quoteTransportEmbedded},
		{"REST over plain HTTP", channelbind.WithConnectionTLS(context.Background(), channelbind.TransportREST, nil), channelbind.TransportREST},
		{"REST exporter refused", channelbind.WithConnectionTLS(context.Background(), channelbind.TransportREST, notComplete), channelbind.TransportREST},
		{"MCP over stdio", channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, nil), channelbind.TransportMCP},
		{"QUIC exporter refused", apiquic.WithConnectionTLS(context.Background(), notComplete), bootTransportQUIC},
		{"Unix socket without TLS", peer.NewContext(context.Background(), &peer.Peer{
			Addr: &net.UnixAddr{Name: "/run/platformd.sock", Net: "unix"},
		}), bootTransportUnix},
		{"gRPC exporter refused", peer.NewContext(context.Background(), &peer.Peer{
			Addr:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10443},
			AuthInfo: credentials.TLSInfo{State: *notComplete},
		}), bootTransportGRPC},
	}
}

// requireBindingRefusal asserts err is the typed refusal naming transport.
func requireBindingRefusal(t *testing.T, err error, transport string) {
	t.Helper()
	var required channelbind.ErrChannelBindingRequired
	require.ErrorAs(t, err, &required)
	assert.Equal(t, transport, required.Transport)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// exportedBinding is the binding a node derives for the connection whose
// server-side state is state, computed independently of the code under test.
func exportedBinding(t *testing.T, state *tls.ConnectionState) []byte {
	t.Helper()
	binding, err := state.ExportKeyingMaterial(xkmssdk.PeerChannelBindingExporterLabel, nil, xkmssdk.PeerChannelBindingLength)
	require.NoError(t, err)
	return binding
}

// recordingQuoteService is an AttestationService that records the nonce
// GetAttestationQuote handed to GetQuote and the expected nonce
// VerifyAttestationQuote handed to VerifyQuote.
type recordingQuoteService struct {
	AttestationService
	quoted        []byte
	expectedNonce []byte
	verified      *QuoteResult
	calls         int
}

func (r *recordingQuoteService) GetQuote(_ context.Context, _ *QuoteConfig, nonce []byte) (*QuoteResult, error) {
	r.calls++
	r.quoted = nonce
	return &QuoteResult{QuoteData: []byte("attest"), Signature: []byte("sig"), Nonce: nonce, SignatureAlgorithm: "SHA256-RSAPSS"}, nil
}

func (r *recordingQuoteService) VerifyQuote(_ context.Context, quote *QuoteResult, _ []byte, expectedNonce []byte, _ []manifest.PCRValue) (*QuoteVerificationResult, error) {
	r.calls++
	r.verified = quote
	r.expectedNonce = expectedNonce
	return &QuoteVerificationResult{Verified: true}, nil
}

// TestGetAttestationQuote_QuotesTheNonceBoundToItsOwnConnection: the quote
// endpoint has the same contract as collect-host (#482). The TPM quotes
// SHA-256(nonce || binding) for the connection the request arrived on, and
// the response returns that binding so a direct caller can check the echo.
func TestGetAttestationQuote_QuotesTheNonceBoundToItsOwnConnection(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	for transport, withState := range boundQuoteContexts() {
		t.Run(transport, func(t *testing.T) {
			svc := &recordingQuoteService{}
			s := NewAttestationServiceServer(svc, slog.Default())
			state := testutil.ServerConnectionState(t)

			resp, err := s.GetAttestationQuote(withState(state), &platformv1.GetAttestationQuoteRequest{
				Config: &platformv1.AttestationQuoteConfig{PcrIndices: []uint32{0, 7}},
				Nonce:  nonce,
			})
			require.NoError(t, err)

			binding := exportedBinding(t, state)
			assert.Equal(t, binding, resp.GetChannelBinding(), "the node returns the binding it quoted under")
			assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), svc.quoted, "the TPM quotes the connection-bound value")
			assert.NotEqual(t, nonce, svc.quoted, "the bare nonce is never quoted")
		})
	}
}

// TestGetAttestationQuote_RefusesARequestWithNoBinding: a quote request with
// no TLS connection is refused before the TPM, never quoted bare.
func TestGetAttestationQuote_RefusesARequestWithNoBinding(t *testing.T) {
	for _, tc := range unboundQuoteContexts() {
		t.Run(tc.name, func(t *testing.T) {
			svc := &recordingQuoteService{}
			s := NewAttestationServiceServer(svc, slog.Default())

			_, err := s.GetAttestationQuote(tc.ctx, &platformv1.GetAttestationQuoteRequest{
				Config: &platformv1.AttestationQuoteConfig{},
				Nonce:  []byte("fresh-nonce"),
			})

			requireBindingRefusal(t, err, tc.transport)
			assert.Equal(t, 0, svc.calls, "an unbound request must never reach the TPM")
		})
	}
}

// TestVerifyAttestationQuote_ExpectsTheBoundEcho: a caller that passes the
// binding the node returned has the quote checked against
// SHA-256(nonce || binding); a binding with no nonce is refused.
func TestVerifyAttestationQuote_ExpectsTheBoundEcho(t *testing.T) {
	nonce := []byte("fresh-nonce")
	binding := make([]byte, xkmssdk.PeerChannelBindingLength)

	t.Run("binding given", func(t *testing.T) {
		svc := &recordingQuoteService{}
		s := NewAttestationServiceServer(svc, slog.Default())
		_, err := s.VerifyAttestationQuote(context.Background(), &platformv1.VerifyAttestationQuoteRequest{
			Quote:          &platformv1.AttestationQuote{QuoteData: []byte("attest")},
			ExpectedNonce:  nonce,
			ChannelBinding: binding,
		})
		require.NoError(t, err)
		assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), svc.expectedNonce)
	})

	t.Run("no binding", func(t *testing.T) {
		svc := &recordingQuoteService{}
		s := NewAttestationServiceServer(svc, slog.Default())
		_, err := s.VerifyAttestationQuote(context.Background(), &platformv1.VerifyAttestationQuoteRequest{
			Quote:         &platformv1.AttestationQuote{QuoteData: []byte("attest")},
			ExpectedNonce: nonce,
		})
		require.NoError(t, err)
		assert.Equal(t, nonce, svc.expectedNonce)
	})

	t.Run("binding without a nonce", func(t *testing.T) {
		svc := &recordingQuoteService{}
		s := NewAttestationServiceServer(svc, slog.Default())
		_, err := s.VerifyAttestationQuote(context.Background(), &platformv1.VerifyAttestationQuoteRequest{
			Quote:          &platformv1.AttestationQuote{QuoteData: []byte("attest")},
			ChannelBinding: binding,
		})
		var unpaired channelbind.ErrBindingWithoutNonce
		require.ErrorAs(t, err, &unpaired)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assert.Equal(t, 0, svc.calls)
	})
}

// The raw quote signature does not say which scheme the AK used, so the
// declared signature algorithm must survive the wire both ways: out with the
// quote GetAttestationQuote returns, and back in to the verifier.
func TestAttestationQuote_CarriesTheSignatureAlgorithm(t *testing.T) {
	svc := &recordingQuoteService{}
	s := NewAttestationServiceServer(svc, slog.Default())

	for transport, withState := range boundQuoteContexts() {
		t.Run(transport, func(t *testing.T) {
			resp, err := s.GetAttestationQuote(withState(testutil.ServerConnectionState(t)), &platformv1.GetAttestationQuoteRequest{
				Config: &platformv1.AttestationQuoteConfig{PcrIndices: []uint32{0, 7}},
				Nonce:  []byte("0123456789abcdef0123456789abcdef"),
			})
			require.NoError(t, err)
			assert.Equal(t, "SHA256-RSAPSS", resp.GetQuote().GetSignatureAlgorithm())

			_, err = s.VerifyAttestationQuote(context.Background(), &platformv1.VerifyAttestationQuoteRequest{
				Quote: resp.GetQuote(),
			})
			require.NoError(t, err)
			require.NotNil(t, svc.verified)
			assert.Equal(t, "SHA256-RSAPSS", svc.verified.SignatureAlgorithm)
		})
	}
}

// quotingTPM is a TPM whose Quote records the qualifying data it was given
// and whose IAK is an ECDSA P-256 key, so VerifyQuote can run without an
// ak_public from the caller.
type quotingTPM struct {
	xkmssdk.TrustedPlatformModule
	quoted []byte
}

func (q *quotingTPM) IAK() (crypto.PublicKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}

func (q *quotingTPM) IAKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		KeyAlgorithm:       x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Hash:               crypto.SHA256,
	}, nil
}

func (q *quotingTPM) Quote(_ []uint, nonce []byte) (xkmssdk.Quote, error) {
	q.quoted = nonce
	return xkmssdk.Quote{Quoted: []byte("attest"), Signature: []byte("sig")}, nil
}

func newQuotingTPMService(tpm *quotingTPM) *TPMGRPCService {
	svc := NewTPMGRPCService(newTPMTestLogger())
	svc.SetTPM2Service(tpm)
	return svc
}

// TestTPMQuote_QuotesTheNonceBoundToItsOwnConnection: the TPM service's
// Quote, which the gRPC, Unix and MCP TPM quote all run, binds exactly as
// the attestation quote does.
func TestTPMQuote_QuotesTheNonceBoundToItsOwnConnection(t *testing.T) {
	nonce := []byte("tpm-nonce")
	for transport, withState := range boundQuoteContexts() {
		t.Run(transport, func(t *testing.T) {
			tpm := &quotingTPM{}
			state := testutil.ServerConnectionState(t)

			resp, err := newQuotingTPMService(tpm).Quote(withState(state), &platformv1.QuoteRequest{Nonce: nonce, PcrIndices: []uint32{0}})
			require.NoError(t, err)

			binding := exportedBinding(t, state)
			assert.Equal(t, binding, resp.GetChannelBinding())
			assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), tpm.quoted)
		})
	}
}

func TestTPMQuote_RefusesARequestWithNoBinding(t *testing.T) {
	for _, tc := range unboundQuoteContexts() {
		t.Run(tc.name, func(t *testing.T) {
			tpm := &quotingTPM{}
			_, err := newQuotingTPMService(tpm).Quote(tc.ctx, &platformv1.QuoteRequest{Nonce: []byte("n"), PcrIndices: []uint32{0}})
			requireBindingRefusal(t, err, tc.transport)
			assert.Nil(t, tpm.quoted, "nothing may be quoted unbound")
		})
	}
}

// TestTPMVerifyQuote_ChecksTheBoundEcho: VerifyQuote compares ExtraData to
// SHA-256(nonce || binding) when the caller passes the binding, so a quote
// bound to its own connection passes the nonce check and the bare nonce
// does not.
func TestTPMVerifyQuote_ChecksTheBoundEcho(t *testing.T) {
	nonce := []byte("verify-nonce")
	binding := make([]byte, xkmssdk.PeerChannelBindingLength)
	quote := tpmgo.Marshal(tpmgo.TPMSAttest{
		Magic:     tpmgo.TPMGeneratedValue,
		Type:      tpmgo.TPMSTAttestQuote,
		ExtraData: tpmgo.TPM2BData{Buffer: xkmssdk.PeerQualifyingData(nonce, binding)},
		Attested:  tpmgo.NewTPMUAttest(tpmgo.TPMSTAttestQuote, &tpmgo.TPMSQuoteInfo{}),
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	akPublic, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	verify := func(req *platformv1.VerifyQuoteRequest) (*platformv1.VerifyQuoteResponse, error) {
		req.Quote = quote
		req.Signature = []byte("garbage-signature")
		req.AkPublic = akPublic
		return newQuotingTPMService(&quotingTPM{}).VerifyQuote(context.Background(), req)
	}

	t.Run("the bound echo passes the nonce check", func(t *testing.T) {
		resp, err := verify(&platformv1.VerifyQuoteRequest{Nonce: nonce, ChannelBinding: binding})
		require.NoError(t, err)
		assert.False(t, resp.GetVerified())
		assert.Contains(t, resp.GetMessage(), "signature_verification_failed")
	})
	t.Run("the bare nonce does not", func(t *testing.T) {
		resp, err := verify(&platformv1.VerifyQuoteRequest{Nonce: nonce})
		require.NoError(t, err)
		assert.False(t, resp.GetVerified())
		assert.Contains(t, resp.GetMessage(), "nonce mismatch")
	})
	t.Run("a binding without a nonce is refused", func(t *testing.T) {
		_, err := verify(&platformv1.VerifyQuoteRequest{ChannelBinding: binding})
		var unpaired channelbind.ErrBindingWithoutNonce
		require.ErrorAs(t, err, &unpaired)
	})
}

// TestMCPTPMQuote_BindsTheMCPConnection: platform_tpm_quote over MCP HTTP
// quotes under its TLS connection's binding; over stdio it is refused.
func TestMCPTPMQuote_BindsTheMCPConnection(t *testing.T) {
	nonce := []byte("mcp-nonce")

	t.Run("HTTPS", func(t *testing.T) {
		tpm := &quotingTPM{}
		p := &MCPServiceProvider{logger: slog.Default(), tpm2Service: tpm}
		state := testutil.ServerConnectionState(t)

		out, err := p.TPMQuote(channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, state), nonce, []int{0})
		require.NoError(t, err)

		binding := exportedBinding(t, state)
		assert.Equal(t, xkmssdk.PeerQualifyingData(nonce, binding), tpm.quoted)
		result, ok := out.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, base64.StdEncoding.EncodeToString(binding), result["channel_binding"])
	})

	t.Run("stdio", func(t *testing.T) {
		tpm := &quotingTPM{}
		p := &MCPServiceProvider{logger: slog.Default(), tpm2Service: tpm}

		_, err := p.TPMQuote(channelbind.WithConnectionTLS(context.Background(), channelbind.TransportMCP, nil), nonce, []int{0})
		requireBindingRefusal(t, err, channelbind.TransportMCP)
		assert.Nil(t, tpm.quoted)
	})
}

// TestMCPTPMVerifyQuote_PassesTheBinding: the MCP verifier hands the binding
// through, so the bound echo passes the nonce check (and fails only on the
// garbage signature), the bare nonce does not, and a binding with no nonce
// is refused.
func TestMCPTPMVerifyQuote_PassesTheBinding(t *testing.T) {
	nonce := []byte("mcp-verify")
	binding := make([]byte, xkmssdk.PeerChannelBindingLength)
	quote := tpmgo.Marshal(tpmgo.TPMSAttest{
		Magic:     tpmgo.TPMGeneratedValue,
		Type:      tpmgo.TPMSTAttestQuote,
		ExtraData: tpmgo.TPM2BData{Buffer: xkmssdk.PeerQualifyingData(nonce, binding)},
		Attested:  tpmgo.NewTPMUAttest(tpmgo.TPMSTAttestQuote, &tpmgo.TPMSQuoteInfo{}),
	})
	p := &MCPServiceProvider{logger: slog.Default(), tpm2Service: &quotingTPM{}}
	message := func(out interface{}) string {
		t.Helper()
		result, ok := out.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, false, result["verified"])
		text, ok := result["message"].(string)
		require.True(t, ok)
		return text
	}

	out, err := p.TPMVerifyQuote(context.Background(), quote, []byte("sig"), nonce, binding)
	require.NoError(t, err)
	assert.Contains(t, message(out), "signature_verification_failed")

	out, err = p.TPMVerifyQuote(context.Background(), quote, []byte("sig"), nonce, nil)
	require.NoError(t, err)
	assert.Contains(t, message(out), "nonce mismatch")

	_, err = p.TPMVerifyQuote(context.Background(), quote, []byte("sig"), nil, binding)
	var unpaired channelbind.ErrBindingWithoutNonce
	require.ErrorAs(t, err, &unpaired)
}
