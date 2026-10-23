//go:build integration

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

package attestation

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// fakeQUICManifestStore holds one manifest. The embedded interface is nil:
// a call to any other method panics, which fails the test loudly.
type fakeQUICManifestStore struct {
	quicapi.AttestationServiceInterface
	stored   *manifest.HostManifest
	verified atomic.Pointer[manifest.HostManifest]
}

// GetManifest answers (nil, nil) for an unknown id, which the daemon's handler
// turns into StatusNotFound.
func (f *fakeQUICManifestStore) GetManifest(_ context.Context, id string) (*manifest.HostManifest, error) {
	if id != f.stored.ID {
		return nil, nil
	}
	return f.stored, nil
}

func (f *fakeQUICManifestStore) VerifyManifest(_ context.Context, m *manifest.HostManifest, _ *quicapi.AttestationVerifyManifestOptions) (*manifest.VerificationResult, error) {
	f.verified.Store(m)
	return &manifest.VerificationResult{
		Status:          manifest.VerificationStatusVerified,
		SignatureValid:  true,
		MerkleRootValid: true,
		VerifiedAt:      time.Now(),
	}, nil
}

func newFakeQUICManifestStore() *fakeQUICManifestStore {
	return &fakeQUICManifestStore{stored: &manifest.HostManifest{
		ID:         "manifest-1",
		HostID:     "host-1",
		Timestamp:  time.Unix(1700000000, 0),
		MerkleRoot: []byte("merkle-root"),
		Signature:  []byte("signature"),
		Version:    "1.0",
	}}
}

// newQUICAdapterAgainstHandler serves the daemon's QUIC attestation handler
// on a loopback mTLS listener and returns an adapter connected to it.
func newQUICAdapterAgainstHandler(t *testing.T, service quicapi.AttestationServiceInterface) *QUICAdapter {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)

	serverTLS := bundle.ServerTLSConfig()
	serverTLS.NextProtos = []string{quicwire.ALPNProtocol}
	listener, err := quicgo.ListenAddr("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	handler := quicapi.NewAttestationHandler(logging.NewLogger(slog.LevelError, nil), service)
	go acceptQUICConns(listener, handler)

	clientTLS := bundle.ClientTLSConfig()
	clientTLS.NextProtos = []string{quicwire.ALPNProtocol}
	a := &QUICAdapter{endpoint: listener.Addr().String(), tlsConfig: clientTLS, quicConfig: &quicgo.Config{}}
	require.NoError(t, a.Setup(context.Background()))
	t.Cleanup(func() { require.NoError(t, a.Teardown(context.Background())) })
	return a
}

func acceptQUICConns(listener *quicgo.Listener, handler *quicapi.AttestationHandler) {
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		go serveQUICStreams(conn, handler)
	}
}

func serveQUICStreams(conn *quicgo.Conn, handler *quicapi.AttestationHandler) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			req, err := quicwire.ReadRequest(stream)
			if err != nil {
				return
			}
			if err := quicwire.WriteResponse(stream, handler.HandleRequest(context.Background(), req)); err != nil {
				return
			}
		}()
	}
}

func TestQUICAdapter_GetManifest(t *testing.T) {
	store := newFakeQUICManifestStore()
	a := newQUICAdapterAgainstHandler(t, store)

	got, err := a.GetManifest(context.Background(), GetManifestOptions{ManifestID: "manifest-1"})
	require.NoError(t, err)
	assert.Equal(t, "manifest-1", got.ManifestID)
	assert.Equal(t, "host-1", got.HostID)
	assert.Equal(t, []byte("merkle-root"), got.MerkleRoot)
	assert.True(t, got.Timestamp.Equal(time.Unix(1700000000, 0)), "timestamp = %v", got.Timestamp)
}

func TestQUICAdapter_GetManifestUnknownIsNotFound(t *testing.T) {
	a := newQUICAdapterAgainstHandler(t, newFakeQUICManifestStore())

	_, err := a.GetManifest(context.Background(), GetManifestOptions{ManifestID: "absent"})
	assert.True(t, IsNotFound(err), "GetManifest of an unknown manifest = %v, want StatusNotFound", err)
}

func TestQUICAdapter_VerifyManifestSendsTheStoredManifest(t *testing.T) {
	store := newFakeQUICManifestStore()
	a := newQUICAdapterAgainstHandler(t, store)

	got, err := a.VerifyManifest(context.Background(), VerifyManifestOptions{ManifestID: "manifest-1", ExpectedHostID: "host-1"})
	require.NoError(t, err)
	verified := store.verified.Load()
	require.NotNil(t, verified, "the daemon never received a manifest to verify")
	assert.Equal(t, "manifest-1", verified.ID)
	assert.Equal(t, []byte("merkle-root"), verified.MerkleRoot)
	assert.True(t, got.Valid)
	assert.True(t, got.SignatureValid)
	assert.True(t, got.MerkleRootValid)
	assert.True(t, got.HostIDMatch)
}

func TestQUICAdapter_VerifyManifestUnknownIsNotFound(t *testing.T) {
	store := newFakeQUICManifestStore()
	a := newQUICAdapterAgainstHandler(t, store)

	_, err := a.VerifyManifest(context.Background(), VerifyManifestOptions{ManifestID: "absent"})
	assert.True(t, IsNotFound(err), "VerifyManifest of an unknown manifest = %v, want StatusNotFound", err)
	assert.Nil(t, store.verified.Load(), "an unknown manifest reached the verifier")
}
