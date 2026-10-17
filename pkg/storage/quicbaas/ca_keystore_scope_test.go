//go:build raft

package quicbaas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/require"

	caquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/ca/quicbaas"
)

// newCAKeyStoreOnSharedServer builds the platform CA keystore over the real
// in-process SDK, as pkg/app CAStoreFactory.CreateKeyStore does.
func newCAKeyStoreOnSharedServer(t *testing.T, prefix string) *caquicbaas.QuicBaaSKeyStore {
	t.Helper()

	sharedServer.once.Do(func() { sharedServer.err = bootSharedServer() })
	require.NoError(t, sharedServer.err, "failed to start the shared embedded server")

	sdk, err := NewSDKClientWithEmbeddedServer(sharedServer.config, sharedServer.server)
	require.NoError(t, err)

	ks, err := caquicbaas.NewQuicBaaSKeyStore(&caquicbaas.QuicBaaSKeyStoreConfig{
		KMS:    sdk.KMS(),
		Crypto: sdk.Crypto(),
		Prefix: prefix,
	})
	require.NoError(t, err)
	return ks
}

func caECDSAAttributes(cn string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
	}
}

// TestCAKeyStoreSigner_UnboundAndSystemScopeResolveTheSameKey is the #949
// proof for the CLI/Unix "kms.GetPublicKey: not_found" on vTPM EK issuance.
// The CA key is generated with an unbound context, as LoadOrInitCA does at
// startup, and its Signer is then fetched with no tenant (the Unix
// listener's context) and with the system tenant. Both resolve the same key
// and sign with it: upstream treats the empty tenant as the system tenant
// (go-qrdb sdk IsSystemTenant), so pinning the platform CA to the system
// scope cannot change the outcome of a Unix request.
func TestCAKeyStoreSigner_UnboundAndSystemScopeResolveTheSameKey(t *testing.T) {
	ks := newCAKeyStoreOnSharedServer(t, "ca.scope-proof.")
	attrs := caECDSAAttributes("root")

	_, err := ks.GenerateECDSA(context.Background(), attrs)
	require.NoError(t, err)

	scopes := map[string]context.Context{
		"unbound": context.Background(),
		"system":  sdktransport.ContextWithTenant(context.Background(), quicbaassdk.SystemTenantID),
	}

	digest := sha256.Sum256([]byte("vtpm ek certificate tbs"))
	var publicKeys []crypto.PublicKey
	for name, ctx := range scopes {
		signer, err := ks.Signer(ctx, attrs)
		require.NoError(t, err, "Signer in the %s scope", name)

		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		require.NoError(t, err, "Sign in the %s scope", name)

		pub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok, "%s scope: public key is %T, want *ecdsa.PublicKey", name, signer.Public())
		require.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "%s scope: signature does not verify", name)
		publicKeys = append(publicKeys, pub)
	}

	require.Len(t, publicKeys, 2)
	first, ok := publicKeys[0].(*ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, first.Equal(publicKeys[1]), "the unbound and system scopes resolved different keys")
}

// TestCAKeyStoreSigner_MissingKeyIsKeyNotFoundInEveryScope pins the error a
// CA key that was never generated returns, so a not_found from the public-key
// leg stays distinguishable from a missing key.
func TestCAKeyStoreSigner_MissingKeyIsKeyNotFoundInEveryScope(t *testing.T) {
	ks := newCAKeyStoreOnSharedServer(t, "ca.scope-missing.")
	attrs := caECDSAAttributes("never-generated")

	scopes := map[string]context.Context{
		"unbound": context.Background(),
		"system":  sdktransport.ContextWithTenant(context.Background(), quicbaassdk.SystemTenantID),
	}
	for name, ctx := range scopes {
		_, err := ks.Signer(ctx, attrs)
		require.Error(t, err, "%s scope", name)

		var notFound caquicbaas.ErrKeyNotFound
		require.True(t, errors.As(err, &notFound), "%s scope: got %T %v, want ErrKeyNotFound", name, err, err)
	}
}
