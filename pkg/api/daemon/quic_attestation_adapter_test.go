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

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// errNoTPMSession is worded as attestation/service.ErrTPMSessionNotConfigured,
// which this package cannot import (the service imports it); the servicer's
// mapError classes both by the same text.
type errNoTPMSession struct{ op string }

func (e errNoTPMSession) Error() string {
	return "attestation/service: " + e.op + " requires a daemon-managed TPM session which is not configured"
}

// collectingManifestService adds host and VM collection to the in-memory
// manifest service: host collection records the nonce it was asked to
// quote, VM collection answers vmErr when set.
type collectingManifestService struct {
	*memoryManifestService
	hostNonce []byte
	hostCalls int
	vmErr     error
}

func (s *collectingManifestService) CollectHostAttestation(_ context.Context, _ *QuoteConfig, nonce []byte) (*manifest.HostAttestation, error) {
	s.hostCalls++
	s.hostNonce = nonce
	return &manifest.HostAttestation{QuoteData: []byte("attest"), Signature: []byte("sig"), Nonce: nonce, HashAlgorithm: manifest.HashAlgorithmSHA256}, nil
}

func (s *collectingManifestService) CollectVMAttestation(_ context.Context, vmID string, _ *QuoteConfig, nonce []byte) (*manifest.VMAttestation, error) {
	if s.vmErr != nil {
		return nil, s.vmErr
	}
	return &manifest.VMAttestation{VMID: vmID, QuoteData: []byte("vm-attest"), Nonce: nonce, HashAlgorithm: manifest.HashAlgorithmSHA256}, nil
}

// quicAttestationHandler is a daemon QUIC handler wired as daemon.go wires
// it: the quote opcodes on the servicer, the manifest opcodes on the
// adapter over the same servicer.
func quicAttestationHandler(svc AttestationService) *QUICServiceHandler {
	servicer := NewAttestationServiceServer(svc, slog.Default())
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	h.SetAttestationGRPCService(servicer)
	h.SetAttestationService(newAttestationQUICAdapter(servicer))
	return h
}

func newCollectingManifestService() *collectingManifestService {
	return &collectingManifestService{memoryManifestService: newMemoryManifestService()}
}

// callAttestation sends msg on opcode through the daemon's attestation
// routing and returns the response.
func callAttestation(t *testing.T, ctx context.Context, h *QUICServiceHandler, opcode byte, msg any) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(msg)
	require.NoError(t, err)
	resp := h.handleAttestationOperation(ctx, &quicwire.Request{Opcode: opcode, Payload: payload})
	require.NotNil(t, resp)
	return resp
}

var adapterNonce = []byte("0123456789abcdef0123456789abcdef")

func TestQUICAttestation_GetManifest(t *testing.T) {
	h := quicAttestationHandler(newCollectingManifestService())

	resp := callAttestation(t, context.Background(), h, quicwire.OpAttestGetManifest, &apiquic.GetManifestRequest{ID: "m-1"})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got apiquic.GetManifestResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	require.NotNil(t, got.Manifest)
	assert.Equal(t, "m-1", got.Manifest.ID)
	assert.Equal(t, "host-a", got.Manifest.HostID)

	resp = callAttestation(t, context.Background(), h, quicwire.OpAttestGetManifest, &apiquic.GetManifestRequest{ID: "absent"})
	assert.Equal(t, quicwire.StatusNotFound, resp.Status, "gRPC NotFound is QUIC NotFound")
	assert.Contains(t, string(resp.Payload), "manifest absent not found")

	resp = callAttestation(t, context.Background(), h, quicwire.OpAttestGetManifest, &apiquic.GetManifestRequest{})
	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, "gRPC InvalidArgument is QUIC InvalidArgument")
}

func TestQUICAttestation_BuildManifest(t *testing.T) {
	svc := newCollectingManifestService()
	h := quicAttestationHandler(svc)

	resp := callAttestation(t, context.Background(), h, quicwire.OpAttestBuildManifest, &apiquic.BuildManifestRequest{
		HostID: "host-b", Nonce: adapterNonce, PCRIndices: []int{0, 7}, IncludeVMs: true, Sign: true,
	})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got apiquic.BuildManifestResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	require.NotNil(t, got.Manifest)
	assert.Equal(t, "built", got.Manifest.ID)
	require.NotNil(t, svc.built)
	assert.Equal(t, "host-b", svc.built.HostID)
	assert.Equal(t, adapterNonce, svc.buildNonce)
	assert.True(t, svc.buildOpts.IncludeVMs)
	assert.True(t, svc.buildOpts.Sign)

	// No backend behind the servicer is the FailedPrecondition gRPC
	// answers, carried as QUIC's StatusInvalidRequest.
	resp = callAttestation(t, context.Background(), quicAttestationHandler(nil), quicwire.OpAttestBuildManifest, &apiquic.BuildManifestRequest{HostID: "host-b"})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	assert.Contains(t, string(resp.Payload), "attestation service backend is not configured")
}

func TestQUICAttestation_VerifyManifest(t *testing.T) {
	svc := newCollectingManifestService()
	h := quicAttestationHandler(svc)
	m := &apiquic.ManifestData{ID: "m-1", HostID: "host-a", Nonce: []byte{1, 2, 3}, MerkleRoot: []byte{9}, Version: "1"}

	resp := callAttestation(t, context.Background(), h, quicwire.OpAttestVerifyManifest, &apiquic.VerifyManifestRequest{Manifest: m})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got apiquic.VerifyManifestResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	assert.True(t, got.Valid)
	assert.Equal(t, 1, svc.verified)

	// A public key asks for a signature check the service cannot make: the
	// FailedPrecondition gRPC answers.
	resp = callAttestation(t, context.Background(), h, quicwire.OpAttestVerifyManifest, &apiquic.VerifyManifestRequest{Manifest: m, PublicKeyPEM: []byte("pem")})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
}

// TestQUICAttestation_CollectHost_QuotesTheNonceBoundOnce: the QUIC handler
// binds the nonce to the connection (#482) and the adapter hands that value
// to the service unchanged, so the TPM quotes SHA-256(nonce || binding),
// not that value bound a second time.
func TestQUICAttestation_CollectHost_QuotesTheNonceBoundOnce(t *testing.T) {
	svc := newCollectingManifestService()
	h := quicAttestationHandler(svc)
	state := testutil.ServerConnectionState(t)

	resp := callAttestation(t, apiquic.WithConnectionTLS(context.Background(), state), h, quicwire.OpAttestHost,
		&apiquic.CollectHostAttestationRequest{Nonce: adapterNonce, PCRIndices: []int{0, 7}})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got apiquic.CollectHostAttestationResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	require.NotNil(t, got.Attestation)
	assert.Equal(t, []byte("attest"), got.Attestation.QuoteData)

	want := xkmssdk.PeerQualifyingData(adapterNonce, exportedBinding(t, state))
	assert.Equal(t, want, svc.hostNonce, "the TPM quotes the nonce bound once to this connection")
}

func TestQUICAttestation_CollectHost_Refusals(t *testing.T) {
	t.Run("no binding", func(t *testing.T) {
		svc := newCollectingManifestService()
		ctx := apiquic.WithConnectionTLS(context.Background(), &tls.ConnectionState{Version: tls.VersionTLS12})

		resp := callAttestation(t, ctx, quicAttestationHandler(svc), quicwire.OpAttestHost, &apiquic.CollectHostAttestationRequest{Nonce: adapterNonce})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Zero(t, svc.hostCalls, "an unbound request never reaches the TPM")
	})
	t.Run("no backend", func(t *testing.T) {
		ctx := apiquic.WithConnectionTLS(context.Background(), testutil.ServerConnectionState(t))

		resp := callAttestation(t, ctx, quicAttestationHandler(nil), quicwire.OpAttestHost, &apiquic.CollectHostAttestationRequest{Nonce: adapterNonce})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "attestation service backend is not configured")
	})
}

func TestQUICAttestation_AttestVM(t *testing.T) {
	svc := newCollectingManifestService()

	resp := callAttestation(t, context.Background(), quicAttestationHandler(svc), quicwire.OpAttestVMWorkload,
		&apiquic.AttestVMRequest{VMID: "vm-1", Nonce: adapterNonce})
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	var got apiquic.AttestVMResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &got))
	require.NotNil(t, got.Attestation)
	assert.Equal(t, "vm-1", got.Attestation.VMID)
	assert.Equal(t, adapterNonce, got.Attestation.Nonce)
}

// TestQUICAttestation_AttestVM_NoTPMSession: without a TPM session the
// service refuses VM collection, and QUIC carries that refusal as gRPC does:
// Internal, the message intact.
func TestQUICAttestation_AttestVM_NoTPMSession(t *testing.T) {
	svc := newCollectingManifestService()
	svc.vmErr = errNoTPMSession{op: "CollectVMAttestation"}

	resp := callAttestation(t, context.Background(), quicAttestationHandler(svc), quicwire.OpAttestVMWorkload,
		&apiquic.AttestVMRequest{VMID: "vm-1", Nonce: adapterNonce})
	assert.Equal(t, quicwire.StatusInternalError, resp.Status)
	assert.Contains(t, string(resp.Payload), svc.vmErr.Error())
}

// TestQUICAttestation_GetReport_NotImplemented: no transport has a report
// store behind GetReportByID, so QUIC answers StatusNotImplemented rather
// than inventing one.
func TestQUICAttestation_GetReport_NotImplemented(t *testing.T) {
	resp := callAttestation(t, context.Background(), quicAttestationHandler(newCollectingManifestService()), quicwire.OpAttestGetReportByID,
		&apiquic.GetReportRequest{ID: "r-1"})
	assert.Equal(t, quicwire.StatusNotImplemented, resp.Status)
	assert.Contains(t, string(resp.Payload), "GetReport is not served by any transport")
}

// TestAttestationQUICAdapter_UnservedOperations: the operations no
// transport serves refuse with the typed NotImplemented error, never a
// zero result.
func TestAttestationQUICAdapter_UnservedOperations(t *testing.T) {
	a := newAttestationQUICAdapter(NewAttestationServiceServer(newCollectingManifestService(), slog.Default()))
	ctx := context.Background()

	calls := map[string]func() error{
		"AttestDevice": func() error { _, err := a.AttestDevice(ctx, "d-1", &apiquic.AttestationCollectOptions{}); return err },
		"ListReports":  func() error { _, _, err := a.ListReports(ctx, &apiquic.AttestationReportFilter{}); return err },
		"GetReport":    func() error { _, err := a.GetReport(ctx, "r-1"); return err },
		"CreatePolicy": func() error {
			_, err := a.CreatePolicy(ctx, &apiquic.AttestationPolicyCreateRequest{Name: "p"})
			return err
		},
		"ListPolicies": func() error { _, _, err := a.ListPolicies(ctx, &apiquic.AttestationPolicyListFilter{}); return err },
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			err := call()
			var refused ErrQUICAttestationNoService
			require.ErrorAs(t, err, &refused)
			assert.Equal(t, op, refused.Op)
			assert.Equal(t, quicwire.StatusNotImplemented, refused.QUICStatus())
		})
	}
}
