package caquicbaas

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	quicbaascrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kmsKeyGenerators creates a real private key for each KMS algorithm the
// fake KMS below is able to serve.
var kmsKeyGenerators = map[kms.KeyAlgorithm]func() (crypto.Signer, error){
	kms.AlgorithmRSA2048:   func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 2048) },
	kms.AlgorithmRSA4096:   func() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 4096) },
	kms.AlgorithmECDSAP256: func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) },
	kms.AlgorithmECDSAP384: func() (crypto.Signer, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) },
}

var sdkHashes = map[quicbaascrypto.HashAlgorithm]crypto.Hash{
	quicbaascrypto.HashSHA256: crypto.SHA256,
	quicbaascrypto.HashSHA384: crypto.SHA384,
	quicbaascrypto.HashSHA512: crypto.SHA512,
}

// realKeyKMS is a fake KMS that generates a real key for the requested
// algorithm, serves its public key and signs with it, so a certificate
// issued through the adapter carries the key the KMS actually produced.
type realKeyKMS struct {
	generateCalls int
	requested     []kms.KeyAlgorithm
	key           crypto.Signer
}

func (r *realKeyKMS) clients(t *testing.T) (*mockSDKKMSClient, *mockSDKCryptoClient) {
	t.Helper()
	kmsClient := &mockSDKKMSClient{
		generateKeyFunc: func(ctx context.Context, req *kms.GenerateKeyRequest) (*kms.GenerateKeyResponse, error) {
			r.generateCalls++
			r.requested = append(r.requested, req.Algorithm)
			generate, ok := kmsKeyGenerators[req.Algorithm]
			if !ok {
				return nil, errors.New("fake KMS: unsupported algorithm")
			}
			key, err := generate()
			if err != nil {
				return nil, err
			}
			r.key = key
			return &kms.GenerateKeyResponse{KeyID: req.Name, Algorithm: req.Algorithm, Version: 1}, nil
		},
		getPublicKeyFunc: func(ctx context.Context, keyID string) (*kms.GetPublicKeyResponse, error) {
			der, err := x509.MarshalPKIXPublicKey(r.key.Public())
			if err != nil {
				return nil, err
			}
			return &kms.GetPublicKeyResponse{KeyID: keyID, PublicKey: der}, nil
		},
	}
	cryptoClient := &mockSDKCryptoClient{
		signFunc: func(ctx context.Context, req *quicbaascrypto.SignRequest) (*quicbaascrypto.SignResponse, error) {
			signature, err := r.key.Sign(rand.Reader, req.Data, sdkHashes[req.HashAlg])
			if err != nil {
				return nil, err
			}
			return &quicbaascrypto.SignResponse{Signature: signature}, nil
		},
	}
	return kmsClient, cryptoClient
}

func newRealKeyStore(t *testing.T) (*QuicBaaSKeyStore, *realKeyKMS) {
	t.Helper()
	fake := &realKeyKMS{}
	kmsClient, cryptoClient := fake.clients(t)
	ks, err := NewQuicBaaSKeyStore(&QuicBaaSKeyStoreConfig{KMS: kmsClient, Crypto: cryptoClient, Prefix: "ca.test."})
	require.NoError(t, err)
	return ks, fake
}

// issueSelfSigned issues a certificate whose key and signature both come
// from the adapter, and returns it parsed back from DER.
func issueSelfSigned(t *testing.T, key crypto.PrivateKey) *x509.Certificate {
	t.Helper()
	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "keysize.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestQuicBaaSKeyStore_GenerateRSA_ExactSize(t *testing.T) {
	cases := []struct {
		name  string
		attrs *xkmssdk.RSAAttributes
		want  kms.KeyAlgorithm
		bits  int
	}{
		{name: "nil attributes default to 2048", attrs: nil, want: kms.AlgorithmRSA2048, bits: 2048},
		{name: "2048", attrs: &xkmssdk.RSAAttributes{KeySize: 2048}, want: kms.AlgorithmRSA2048, bits: 2048},
		{name: "4096", attrs: &xkmssdk.RSAAttributes{KeySize: 4096}, want: kms.AlgorithmRSA4096, bits: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks, fake := newRealKeyStore(t)
			key, err := ks.GenerateRSA(context.Background(), &xkmssdk.KeyAttributes{
				CN: "rsa", KeyAlgorithm: x509.RSA, RSAAttributes: tc.attrs,
			})
			require.NoError(t, err)
			assert.Equal(t, []kms.KeyAlgorithm{tc.want}, fake.requested)

			cert := issueSelfSigned(t, key)
			pub, ok := cert.PublicKey.(*rsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, tc.bits, pub.N.BitLen())
		})
	}
}

func TestQuicBaaSKeyStore_GenerateRSA_RejectsSizeWithoutExactKMSAlgorithm(t *testing.T) {
	for _, size := range []int{0, 1024, 3072, 8192} {
		ks, fake := newRealKeyStore(t)
		key, err := ks.GenerateRSA(context.Background(), &xkmssdk.KeyAttributes{
			CN: "rsa", KeyAlgorithm: x509.RSA, RSAAttributes: &xkmssdk.RSAAttributes{KeySize: size},
		})
		require.Error(t, err, "size %d", size)
		assert.Nil(t, key)
		var inputErr ErrInvalidInput
		require.True(t, errors.As(err, &inputErr), "size %d", size)
		assert.Equal(t, "RSAAttributes.KeySize", inputErr.Field)
		assert.Zero(t, fake.generateCalls, "size %d reached the KMS", size)
	}
}

func TestQuicBaaSKeyStore_GenerateECDSA_ExactCurve(t *testing.T) {
	cases := []struct {
		name  string
		attrs *xkmssdk.ECCAttributes
		want  kms.KeyAlgorithm
		curve elliptic.Curve
	}{
		{name: "nil attributes default to P-256", attrs: nil, want: kms.AlgorithmECDSAP256, curve: elliptic.P256()},
		{name: "P-256", attrs: &xkmssdk.ECCAttributes{Curve: elliptic.P256()}, want: kms.AlgorithmECDSAP256, curve: elliptic.P256()},
		{name: "P-384", attrs: &xkmssdk.ECCAttributes{Curve: elliptic.P384()}, want: kms.AlgorithmECDSAP384, curve: elliptic.P384()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks, fake := newRealKeyStore(t)
			key, err := ks.GenerateECDSA(context.Background(), &xkmssdk.KeyAttributes{
				CN: "ec", KeyAlgorithm: x509.ECDSA, ECCAttributes: tc.attrs,
			})
			require.NoError(t, err)
			assert.Equal(t, []kms.KeyAlgorithm{tc.want}, fake.requested)

			cert := issueSelfSigned(t, key)
			pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			require.True(t, ok)
			assert.Equal(t, tc.curve, pub.Curve)
		})
	}
}

func TestQuicBaaSKeyStore_GenerateECDSA_RejectsCurveWithoutExactKMSAlgorithm(t *testing.T) {
	cases := map[string]*xkmssdk.ECCAttributes{
		"P-521":     {Curve: elliptic.P521()},
		"P-224":     {Curve: elliptic.P224()},
		"nil curve": {Curve: nil},
	}
	for name, attrs := range cases {
		t.Run(name, func(t *testing.T) {
			ks, fake := newRealKeyStore(t)
			key, err := ks.GenerateECDSA(context.Background(), &xkmssdk.KeyAttributes{
				CN: "ec", KeyAlgorithm: x509.ECDSA, ECCAttributes: attrs,
			})
			require.Error(t, err)
			assert.Nil(t, key)
			var inputErr ErrInvalidInput
			require.True(t, errors.As(err, &inputErr))
			assert.Equal(t, "ECCAttributes.Curve", inputErr.Field)
			assert.Zero(t, fake.generateCalls)
		})
	}
}
