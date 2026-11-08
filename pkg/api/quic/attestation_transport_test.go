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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttestationTransport_BuildManifestIsAnsweredOverQUIC sends an
// attestation opcode over a real QUIC connection that negotiates the
// production ALPN, and requires the attestation handler's refusal to come
// back as a response frame. An ALPN mismatch fails the handshake, and a
// request that reaches no handler gets no status, so either shows here.
func TestAttestationTransport_BuildManifestIsAnsweredOverQUIC(t *testing.T) {
	serverTLS := generateTestTLSConfig()
	serverTLS.NextProtos = []string{quicwire.ALPNProtocol}

	handler, _ := createTestAttestationHandler()
	srv, err := NewServer(
		&ServerConfig{ListenAddr: "127.0.0.1:0", TLSConfig: serverTLS},
		WithHandler(handler),
		WithLogger(newAttestTestLogger()),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Stop() })

	clientTLS := generateTestClientTLSConfig(serverTLS)
	clientTLS.NextProtos = []string{quicwire.ALPNProtocol}
	client, err := quicwire.NewClient(&quicwire.ClientConfig{
		ServerAddr: srv.ListenAddr(),
		Timeout:    5 * time.Second,
		TLSConfig:  clientTLS,
	})
	require.NoError(t, err, "the QUIC handshake with the production ALPN failed")
	t.Cleanup(func() { _ = client.Close() })

	// A nonce shorter than 16 bytes is refused by the handler itself.
	payload, err := quicwire.EncodePayload(&BuildManifestRequest{HostID: "no-such-host-486", Nonce: []byte("short")})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	_, err = client.SendRequest(ctx, quicwire.OpAttestBuildManifest, payload)

	var refusal *quicwire.ErrProtocol
	require.True(t, errors.As(err, &refusal), "no response frame came back, so the request reached no handler: %v", err)
	assert.Equal(t, quicwire.StatusInvalidArgument, refusal.Status)
	assert.NotEmpty(t, refusal.Message)
}
