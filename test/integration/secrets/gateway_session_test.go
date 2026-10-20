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

//go:build integration

package secrets

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwsecrets "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// gatewayResolveTimeout bounds one gateway secret read against platformd.
const gatewayResolveTimeout = 10 * time.Second

// TestGatewaySecretStoreSession drives the gatewayd secret store against the
// real platformd, which requires a client certificate (--enable-mtls). The
// gateway presents its node mTLS identity and reads the secret; the same
// store without that identity is refused (#658).
func TestGatewaySecretStoreSession(t *testing.T) {
	ctx, cancel := DefaultTestContext()
	defer cancel()

	admin := NewGRPCAdapter()
	require.NoError(t, admin.Setup(ctx))
	defer func() { assert.NoError(t, admin.Teardown()) }()

	name := GenerateUniqueSecretName("gateway-session")
	value := []byte("gateway-bgp-session-key")
	_, err := admin.Store(ctx, DefaultStoreOptions(name, value))
	require.NoError(t, err)
	defer CleanupSecret(admin, ctx, name)

	// The harness client pair stands in for the provisioned node identity
	// (control-plane: cert-file and key-file); its CA verifies platformd.
	harness := helpers.TLSConfigOrInsecure()
	require.Len(t, harness.Certificates, 1, "the harness mTLS config carries one client pair")
	identity := harness.Certificates[0]
	server := func(context.Context, string) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: harness.RootCAs}, nil
	}
	ref := "kms://" + name

	t.Run("NodeIdentityIsAccepted", func(t *testing.T) {
		store := newGatewayStore(t, gwsecrets.WithClientIdentity(server, identity))

		got, err := store.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, value, got)
	})

	t.Run("UnidentifiedCallerIsRefused", func(t *testing.T) {
		store := newGatewayStore(t, server)

		got, err := store.Resolve(ctx, ref)
		require.Error(t, err)
		assert.Nil(t, got)

		var unavailable *gwsecrets.ErrStoreUnavailable
		var unresolvable *gwsecrets.ErrSecretUnresolvable
		assert.True(t, errors.As(err, &unavailable) || errors.As(err, &unresolvable),
			"the refused session surfaces as a store error, got %v", err)
	})
}

// newGatewayStore builds the gatewayd secret store dialling platformd's gRPC
// endpoint through the quicbaas SDK with tlsFn.
func newGatewayStore(t *testing.T, tlsFn gwsecrets.TLSFunc) *gwsecrets.Store {
	t.Helper()
	cfg := gwsecrets.Config{QuicBaaSAddr: platformdGRPCEndpoint()}
	store, err := gwsecrets.NewStore(gwsecrets.QuicBaaSDial(cfg, tlsFn), gatewayResolveTimeout, slog.Default())
	require.NoError(t, err)
	return store
}
