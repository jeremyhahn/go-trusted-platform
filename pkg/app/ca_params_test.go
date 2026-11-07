package app

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"
)

// InitCA and LoadCA both build the SDK CA through caParams, so these tests
// pin the contract for both. The operator's require-key-password setting is
// not forwarded: the pinned go-xkms drops the CA key password when NewCA
// rebuilds the identity, so a forwarded true failed a fresh InitCA with
// ErrKeyPasswordRequired (go-xkms #1768, #833). This test flips when the
// forwarding returns after go-xkms #1768 is tagged.
func TestCAParams_DoesNotForwardRequireKeyPassword(t *testing.T) {
	for _, required := range []bool{true, false} {
		app := &App{CAConfig: &trustedca.CAConfig{RequireKeyPassword: required}}

		params := app.caParams(NewCAStoreFactory(app, t.TempDir(), nil, nil, nil))

		assert.False(t, params.RequireKeyPassword, "config RequireKeyPassword=%v", required)
	}
}

func TestCAParams_CarriesIdentityAndStoreFactories(t *testing.T) {
	app := &App{CAConfig: defaultCAConfig()}
	require.NotEmpty(t, app.CAConfig.Identity)

	params := app.caParams(NewCAStoreFactory(app, t.TempDir(), nil, nil, nil))

	assert.Equal(t, app.CAConfig.Identity, params.Identity)
	assert.NotNil(t, params.KeyStoreFactory)
	assert.NotNil(t, params.CertStoreFactory)
	assert.NotNil(t, params.ObjectStoreFactory)
}
