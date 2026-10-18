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

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
)

func TestKMSQUICAdapter_TenantBoundCallerNeverReachesTheSystemNamespace(t *testing.T) {
	t.Parallel()
	kmsAdapter, cryptoAdapter, _ := newTripwireKMSAdapters()
	calls := contextEntryPoints(newKMSQUICAdapter(kmsAdapter, cryptoAdapter), "")
	require.Contains(t, calls, "GenerateKey")
	require.Contains(t, calls, "GenerateRandom")
	assertEveryEntryPointRefused(t, "QUIC", calls, quicTenantContext("tenant-a"))
}

func TestKMSQUICAdapter_SystemCallerIsServedRandomBytes(t *testing.T) {
	t.Parallel()
	kmsAdapter, cryptoAdapter, _ := newTripwireKMSAdapters()
	adapter := newKMSQUICAdapter(kmsAdapter, cryptoAdapter)
	for name, ctx := range map[string]context.Context{
		"system tenant":    quicTenantContext(scopeSystemTenant),
		"unbound operator": context.Background(),
	} {
		resp, err := adapter.GenerateRandom(ctx, &pb.GenerateRandomRequest{NumBytes: 16})
		require.NoError(t, err, name)
		assert.Len(t, resp.GetRandomBytes(), 16, name)
	}
}

// TestQUICKMSHandler_TenantBoundCallerIsPermissionDenied drives the wire
// handler past the authorization guard (which refuses a context with no
// permissions on its own): the refusal reaches a QUIC client as
// StatusPermissionDenied, the status gRPC, Unix and MCP answer.
func TestQUICKMSHandler_TenantBoundCallerIsPermissionDenied(t *testing.T) {
	t.Parallel()
	kmsAdapter, cryptoAdapter, _ := newTripwireKMSAdapters()
	handler := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICKMSService(newKMSQUICAdapter(kmsAdapter, cryptoAdapter)))

	payload, err := quicwire.EncodePayload(KMSGetKeyRequest{KeyId: "key-1"})
	require.NoError(t, err)
	var resp *quicwire.Response
	require.NotPanics(t, func() {
		resp = handler.handleKMSGetKey(quicTenantContext("tenant-a"), &quicwire.Request{Opcode: quicwire.OpKMSGetKey, Payload: payload})
	})
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}
