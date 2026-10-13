// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/tls"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingHostQuoteService is an AttestationService that records the quote
// config CollectHostAttestation was handed and answers a minimal attestation.
type recordingHostQuoteService struct {
	AttestationService
	gotConfig *QuoteConfig
	gotNonce  []byte
	calls     int
}

func (r *recordingHostQuoteService) CollectHostAttestation(_ context.Context, config *QuoteConfig, nonce []byte) (*manifest.HostAttestation, error) {
	r.calls++
	r.gotConfig = config
	r.gotNonce = nonce
	return &manifest.HostAttestation{Nonce: nonce}, nil
}

// restRequestContext is the context the REST router hands the server for a
// request that arrived over a real TLS 1.3 connection.
func restRequestContext(t *testing.T) context.Context {
	t.Helper()
	return channelbind.WithConnectionTLS(context.Background(), channelbind.TransportREST, testutil.ServerConnectionState(t))
}

// boundTo is the value a node must quote for nonce over the connection whose
// server-side state is state, derived independently of the code under test.
func boundTo(t *testing.T, state *tls.ConnectionState, nonce []byte) []byte {
	t.Helper()
	binding, err := state.ExportKeyingMaterial(xkmssdk.PeerChannelBindingExporterLabel, nil, xkmssdk.PeerChannelBindingLength)
	require.NoError(t, err)
	return xkmssdk.PeerQualifyingData(nonce, binding)
}

// TestCollectHostAttestation_AbsentConfigMeansNodeDefaults is the fleet
// finding of 2026-09-05: the handler refused every collection with
// "quote config is required" although the service substitutes the default
// PCR selection for a nil config. An absent config is a valid request.
func TestCollectHostAttestation_AbsentConfigMeansNodeDefaults(t *testing.T) {
	svc := &recordingHostQuoteService{}
	s := NewAttestationServiceServer(svc, slog.Default())

	resp, err := s.CollectHostAttestation(restRequestContext(t), &platformv1.CollectHostAttestationRequest{
		Nonce: []byte("fresh-nonce"),
	})
	require.NoError(t, err, "a request without a config must reach the service, which defaults the PCR selection")
	assert.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, 1, svc.calls)
	assert.Nil(t, svc.gotConfig, "no config on the wire is handed to the service as nil, which selects the defaults")
}

func TestCollectHostAttestation_EmptyConfigIsPassedThrough(t *testing.T) {
	svc := &recordingHostQuoteService{}
	s := NewAttestationServiceServer(svc, slog.Default())

	_, err := s.CollectHostAttestation(restRequestContext(t), &platformv1.CollectHostAttestationRequest{
		Config: &platformv1.AttestationQuoteConfig{},
		Nonce:  []byte("fresh-nonce"),
	})
	require.NoError(t, err)
	require.NotNil(t, svc.gotConfig)
	assert.Empty(t, svc.gotConfig.PCRIndices, "an empty selection reaches the service empty; hostQuote fills in the defaults")
}

func TestCollectHostAttestation_ExplicitPCRsArePassedThrough(t *testing.T) {
	svc := &recordingHostQuoteService{}
	s := NewAttestationServiceServer(svc, slog.Default())

	_, err := s.CollectHostAttestation(restRequestContext(t), &platformv1.CollectHostAttestationRequest{
		Config: &platformv1.AttestationQuoteConfig{PcrIndices: []uint32{0, 7}},
		Nonce:  []byte("fresh-nonce"),
	})
	require.NoError(t, err)
	require.NotNil(t, svc.gotConfig)
	assert.Equal(t, []int{0, 7}, svc.gotConfig.PCRIndices)
}

func TestCollectHostAttestation_StillRequiresANonce(t *testing.T) {
	svc := &recordingHostQuoteService{}
	s := NewAttestationServiceServer(svc, slog.Default())

	_, err := s.CollectHostAttestation(restRequestContext(t), &platformv1.CollectHostAttestationRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Contains(t, err.Error(), "nonce is required")
	assert.Equal(t, 0, svc.calls, "a nonce-less request must never reach the TPM")
}

// TestCollectHostAttestation_QuotesTheNonceBoundToItsOwnConnection is the
// node half of #482: whatever transport the request arrived over, the TPM
// quotes the nonce bound to that connection, never the nonce as sent, so a
// relay forwarding it over a second connection cannot obtain a quote bound
// to the collector's.
func TestCollectHostAttestation_QuotesTheNonceBoundToItsOwnConnection(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	for transport, withState := range boundQuoteContexts() {
		t.Run(transport, func(t *testing.T) {
			svc := &recordingHostQuoteService{}
			s := NewAttestationServiceServer(svc, slog.Default())
			state := testutil.ServerConnectionState(t)

			resp, err := s.CollectHostAttestation(withState(state), &platformv1.CollectHostAttestationRequest{Nonce: nonce})
			require.NoError(t, err)

			assert.Equal(t, boundTo(t, state, nonce), svc.gotNonce, "the TPM quotes the connection-bound value")
			assert.NotEqual(t, nonce, svc.gotNonce, "the bare nonce is never quoted")
			assert.Equal(t, svc.gotNonce, resp.GetAttestation().GetNonce(), "the node echoes the value it quoted")
		})
	}
}

// TestCollectHostAttestation_RefusesARequestWithNoBinding: a request whose
// connection carries no channel binding is refused before the TPM, never
// quoted bare, since a bare quote is what a relay needs.
func TestCollectHostAttestation_RefusesARequestWithNoBinding(t *testing.T) {
	for _, tc := range unboundQuoteContexts() {
		t.Run(tc.name, func(t *testing.T) {
			svc := &recordingHostQuoteService{}
			s := NewAttestationServiceServer(svc, slog.Default())

			_, err := s.CollectHostAttestation(tc.ctx, &platformv1.CollectHostAttestationRequest{Nonce: []byte("fresh-nonce")})

			requireBindingRefusal(t, err, tc.transport)
			assert.Equal(t, 0, svc.calls, "an unbound request must never reach the TPM")
		})
	}
}
