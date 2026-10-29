package issuance

import (
	"crypto/elliptic"
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
