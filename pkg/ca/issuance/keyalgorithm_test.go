package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestKeyAttributes_KeepsSizeAndCurve(t *testing.T) {
	tests := []struct {
		alg     platformv1.KeyAlgorithm
		family  x509.PublicKeyAlgorithm
		rsaBits int
		curve   elliptic.Curve
	}{
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED, x509.ECDSA, 0, elliptic.P256()},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048, x509.RSA, 2048, nil},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072, x509.RSA, 3072, nil},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096, x509.RSA, 4096, nil},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256, x509.ECDSA, 0, elliptic.P256()},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384, x509.ECDSA, 0, elliptic.P384()},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521, x509.ECDSA, 0, elliptic.P521()},
		{platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519, x509.Ed25519, 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			attrs, err := KeyAttributes(tt.alg, "leaf.example.com", xkmssdk.StoreSoftware)
			require.NoError(t, err)
			assert.Equal(t, "leaf.example.com", attrs.CN)
			assert.Equal(t, tt.family, attrs.KeyAlgorithm)
			assert.Equal(t, xkmssdk.StoreSoftware, attrs.StoreType)
			assert.Equal(t, xkmssdk.KeyTypeTLS, attrs.KeyType)

			if tt.rsaBits == 0 {
				assert.Nil(t, attrs.RSAAttributes)
			} else {
				require.NotNil(t, attrs.RSAAttributes)
				assert.Equal(t, tt.rsaBits, attrs.RSAAttributes.KeySize)
			}
			if tt.curve == nil {
				assert.Nil(t, attrs.ECCAttributes)
			} else {
				require.NotNil(t, attrs.ECCAttributes)
				assert.Equal(t, tt.curve, attrs.ECCAttributes.Curve)
			}
		})
	}
}

func TestKeyAttributes_UnsupportedAlgorithm(t *testing.T) {
	tests := []platformv1.KeyAlgorithm{
		platformv1.KeyAlgorithm_KEY_ALGORITHM_DILITHIUM3,
		platformv1.KeyAlgorithm(999),
	}

	for _, alg := range tests {
		t.Run(alg.String(), func(t *testing.T) {
			attrs, err := KeyAttributes(alg, "leaf.example.com", xkmssdk.StoreSoftware)
			assert.Nil(t, attrs)

			var unsupported *UnsupportedKeyAlgorithmError
			require.ErrorAs(t, err, &unsupported)
			assert.Equal(t, alg.String(), unsupported.Algorithm)
			assert.Contains(t, err.Error(), "unsupported key algorithm")
		})
	}
}

// TestPublicKeyAlgorithm reads the algorithm, size and curve from real keys;
// a size, curve or key type the CA does not issue is UNSPECIFIED.
func TestPublicKeyAlgorithm(t *testing.T) {
	rsaKey := func(bits int) crypto.PublicKey {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		require.NoError(t, err)
		return key.Public()
	}
	ecKey := func(curve elliptic.Curve) crypto.PublicKey {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		return key.Public()
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cases := []struct {
		name string
		key  crypto.PublicKey
		want platformv1.KeyAlgorithm
	}{
		{"RSA-2048", rsaKey(2048), platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048},
		{"RSA-3072", rsaKey(3072), platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072},
		{"RSA-4096", rsaKey(4096), platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096},
		{"RSA-1024 is not issued", rsaKey(1024), platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
		{"P-256", ecKey(elliptic.P256()), platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256},
		{"P-384", ecKey(elliptic.P384()), platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384},
		{"P-521", ecKey(elliptic.P521()), platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521},
		{"P-224 is not issued", ecKey(elliptic.P224()), platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
		{"Ed25519", edPub, platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519},
		{"unknown key type", struct{}{}, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
		{"nil key", nil, platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, PublicKeyAlgorithm(tc.key))
		})
	}
}
