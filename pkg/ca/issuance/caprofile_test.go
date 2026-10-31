package issuance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	xkmscertstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"
)

// TestIssue_CARequestReturnsCACertificate issues CA requests through a real
// go-xkms CA and checks the certificate it returns is a CA that signs a leaf
// which verifies to the root. It fails if caProfileName stops selecting the
// go-xkms CA profile, because the default profile issues a leaf.
func TestIssue_CARequestReturnsCACertificate(t *testing.T) {
	root := newSoftwareRootCA(t)
	rootCert, err := root.CACertificate()
	require.NoError(t, err)

	// -1 asks for no path-length limit; the issued certificate then has no
	// pathLenConstraint, which crypto/x509 parses as MaxPathLen -1.
	for _, maxPathLen := range []int{-1, 0, 1} {
		name := "sub-ca-path-length-" + strconv.Itoa(maxPathLen)
		t.Run(name, func(t *testing.T) {
			key := newECKey(t)
			issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
				Subject:    quicbaasca.CASubject{CommonName: name, Organization: "Test Org", Country: "US"},
				Valid:      1,
				IsCA:       true,
				MaxPathLen: maxPathLen,
				Signer:     key,
			})
			require.NoError(t, err)
			require.NotNil(t, issued)
			sub := issued.Certificate
			require.NotNil(t, sub)

			assert.True(t, sub.IsCA, "an isCA request must return a CA certificate")
			assert.True(t, sub.BasicConstraintsValid)
			assert.NotZero(t, sub.KeyUsage&x509.KeyUsageCertSign, "a CA certificate must carry keyCertSign")
			assert.Equal(t, maxPathLen, sub.MaxPathLen)
			assert.Equal(t, maxPathLen == 0, sub.MaxPathLenZero)

			leaf := signLeaf(t, sub, key)
			roots := x509.NewCertPool()
			roots.AddCert(rootCert)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(sub)
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			require.NoError(t, err, "the issued CA must sign a leaf that chains to the root")
		})
	}
}

// The SDK's CA profile writes keyCertSign | cRLSign | digitalSignature. A CA
// request for exactly that mask issues it unchanged; a narrower one is
// refused, because the profile would grant usages the request withheld.
func TestIssue_CAKeyUsageIsNeverBroadened(t *testing.T) {
	root := newSoftwareRootCA(t)

	t.Run("the profile mask issues exactly", func(t *testing.T) {
		issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
			Subject:  quicbaasca.CASubject{CommonName: "full-mask-ca", Organization: "Test Org", Country: "US"},
			Valid:    1,
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			Signer:   newECKey(t),
		})
		require.NoError(t, err)
		assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature,
			issued.Certificate.KeyUsage)
	})

	t.Run("only keyCertSign is refused", func(t *testing.T) {
		issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
			Subject:  quicbaasca.CASubject{CommonName: "cert-sign-only-ca", Organization: "Test Org", Country: "US"},
			Valid:    1,
			IsCA:     true,
			KeyUsage: x509.KeyUsageCertSign,
			Signer:   newECKey(t),
		})
		assert.Nil(t, issued)
		var refusal *CAKeyUsageUnsupportedError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, x509.KeyUsageCertSign, refusal.Requested)
		assert.True(t, IsInvalidRequest(err))
	})
}

// TestIssue_LeafRequestReturnsLeaf checks a request without IsCA keeps the
// default leaf profile.
func TestIssue_LeafRequestReturnsLeaf(t *testing.T) {
	root := newSoftwareRootCA(t)
	issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{CommonName: "leaf.test", Organization: "Test Org", Country: "US"},
		Valid:   1,
		Signer:  newECKey(t),
	})
	require.NoError(t, err)
	require.NotNil(t, issued.Certificate)
	assert.False(t, issued.Certificate.IsCA)
}

// TestIssue_NilRequest checks Issue refuses a missing request with its typed
// error instead of passing nil to the CA.
func TestIssue_NilRequest(t *testing.T) {
	issued, err := Issue(context.Background(), newSoftwareRootCA(t), nil)
	assert.Nil(t, issued)
	assert.ErrorAs(t, err, &ErrNilCertificateRequest{})
}

// TestRenew_CACertificateStaysCA issues a CA certificate through a real go-xkms
// CA, renews it through Renew, and checks the replacement is still a CA with
// the same path length that signs a leaf chaining to the root. It fails if
// Renew issues through IssueCertificate, whose default profile is a leaf.
func TestRenew_CACertificateStaysCA(t *testing.T) {
	for _, maxPathLen := range []int{0, 1} {
		name := "renew-sub-ca-path-length-" + strconv.Itoa(maxPathLen)
		t.Run(name, func(t *testing.T) {
			root := newRenewableRootCA(t)
			rootCert, err := root.CACertificate()
			require.NoError(t, err)

			issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
				Subject:       quicbaasca.CASubject{CommonName: name, Organization: "Test Org", Country: "US"},
				Valid:         1,
				IsCA:          true,
				MaxPathLen:    maxPathLen,
				KeyAttributes: softwareTLSKey(name),
			})
			require.NoError(t, err)
			require.True(t, issued.Certificate.IsCA)

			renewed, err := Renew(context.Background(), root, issued.Certificate, RenewOptions{ValidDays: 1})
			require.NoError(t, err)
			require.NotNil(t, renewed)

			assert.True(t, renewed.IsCA, "renewing a CA certificate must return a CA certificate")
			assert.True(t, renewed.BasicConstraintsValid)
			assert.NotZero(t, renewed.KeyUsage&x509.KeyUsageCertSign, "a renewed CA certificate must carry keyCertSign")
			assert.Equal(t, maxPathLen, renewed.MaxPathLen)
			assert.Equal(t, maxPathLen == 0, renewed.MaxPathLenZero)
			assert.NotEqual(t, issued.Certificate.SerialNumber, renewed.SerialNumber)

			signer, err := root.KeyStore().Signer(context.Background(), softwareTLSKey(name))
			require.NoError(t, err)
			leaf := signLeafWith(t, renewed, signer)
			roots := x509.NewCertPool()
			roots.AddCert(rootCert)
			intermediates := x509.NewCertPool()
			intermediates.AddCert(renewed)
			_, err = leaf.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			require.NoError(t, err, "the renewed CA must sign a leaf that chains to the root")
		})
	}
}

// TestRenew_LeafStaysLeaf checks renewing a leaf certificate keeps the leaf
// profile.
func TestRenew_LeafStaysLeaf(t *testing.T) {
	root := newRenewableRootCA(t)
	issued, err := Issue(context.Background(), root, &quicbaasca.CACertificateRequest{
		Subject:       quicbaasca.CASubject{CommonName: "renew-leaf.test", Organization: "Test Org", Country: "US"},
		Valid:         1,
		KeyAttributes: softwareTLSKey("renew-leaf.test"),
	})
	require.NoError(t, err)
	require.False(t, issued.Certificate.IsCA)

	renewed, err := Renew(context.Background(), root, issued.Certificate, RenewOptions{ValidDays: 1})
	require.NoError(t, err)
	require.NotNil(t, renewed)
	assert.False(t, renewed.IsCA, "renewing a leaf must not return a CA certificate")
	assert.Zero(t, renewed.KeyUsage&x509.KeyUsageCertSign, "a renewed leaf must not carry keyCertSign")
}

// newRenewableRootCA is newSoftwareRootCA as the CA surface Renew takes.
func newRenewableRootCA(t *testing.T) quicbaasca.CACertificateAuthority {
	t.Helper()
	root, ok := newSoftwareRootCA(t).(quicbaasca.CACertificateAuthority)
	require.True(t, ok, "the go-xkms CA must implement the TCG CA surface")
	return root
}

// softwareTLSKey is the key renewalRequest names for a certificate with
// common name cn, so the issued certificate's key is the one Renew rotates.
func softwareTLSKey(cn string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:            cn,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &xkmssdk.ECCAttributes{Curve: elliptic.P256()},
		StoreType:     xkmssdk.StoreSoftware,
		KeyType:       xkmssdk.KeyTypeTLS,
	}
}

// newSoftwareRootCA builds a real go-xkms root CA over in-memory stores.
func newSoftwareRootCA(t *testing.T) xkmssdk.TrustedCA {
	t.Helper()
	root, _, err := quicbaasca.NewCA(context.Background(), &quicbaasca.Params{
		Identity: []quicbaasca.CAIdentity{{
			Subject: quicbaasca.CASubject{CommonName: "issuance-test-root", Organization: "Test Org", Country: "US"},
			Valid:   1,
			Keys: []*xkmssdk.KeyConfig{{
				KeyAlgorithm:       "RSA",
				Hash:               "SHA-256",
				SignatureAlgorithm: "SHA256-RSAPSS",
				RSAConfig:          &xkmssdk.KeyRSAConfig{KeySize: 2048},
			}},
			KeystoreType: xkmssdk.StoreSoftware,
			IsRoot:       true,
		}},
		KeyStoreFactory: func(string) (xkmsbackend.Backend, error) {
			pkcs8, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
				KeyStorage:         xkmssdk.NewStorageMemory(),
				AllowPlaintextKeys: true,
			})
			if err != nil {
				return nil, err
			}
			return xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
				Backend:     pkcs8,
				CertStorage: xkmssdk.NewStorageMemory(),
			})
		},
		CertStoreFactory: func(string) (xkmscertstore.CertStore, error) {
			return xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
				CertStorage: xkmssdk.NewStorageCertAdapter(xkmssdk.NewStorageMemory()),
			})
		},
	})
	require.NoError(t, err)
	require.NotNil(t, root)
	return root
}

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// signLeaf signs a leaf certificate with the CA certificate's key.
func signLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	return signLeafWith(t, ca, caKey)
}

// signLeafWith signs a leaf certificate with caKey, the CA certificate's key.
func signLeafWith(t *testing.T, ca *x509.Certificate, caKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "leaf.sub-ca.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &newECKey(t).PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leaf
}
