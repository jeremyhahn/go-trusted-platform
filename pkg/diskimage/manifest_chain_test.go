package diskimage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
)

// newIntermediatePKI builds a platform root, an intermediate CA it issued
// and a signing leaf the intermediate issued. The fake CA returns the leaf
// for the manifest key and, when withChain is set, its issuer chain.
func newIntermediatePKI(t *testing.T, withChain bool) manifestPKI {
	t.Helper()
	now := time.Now()
	issue := func(serial int64, cn string, ca bool, pub any, parent *x509.Certificate, signer *ecdsa.PrivateKey) *x509.Certificate {
		t.Helper()
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour).Truncate(time.Second)}
		if ca {
			tmpl.NotAfter = now.Add(48 * time.Hour)
			tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
		} else {
			tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		}
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	root := issue(1, "platform root CA", true, rootKey.Public(), nil, rootKey)
	interKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	inter := issue(2, "platform intermediate CA", true, interKey.Public(), root, rootKey)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leaf := issue(3, "image builds", false, key.Public(), inter, interKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"build/manifest": leaf}}
	if withChain {
		ca.Chains = map[string][]*x509.Certificate{"build/manifest": {inter, root}}
	}
	return manifestPKI{roots: roots, leaf: leaf, kms: &ecKMS{key: key}, ca: ca}
}

// TestWriteManifestCarriesTheIssuerChain: a manifest signed by a key an
// intermediate platform CA certified verifies against the platform root
// alone, because the manifest carries the leaf and its intermediates.
func TestWriteManifestCarriesTheIssuerChain(t *testing.T) {
	digest := sha256.Sum256([]byte("the image"))
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("chain", func(t *testing.T) {
		pki := newIntermediatePKI(t, true)
		image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
		cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
		path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks())
		if err != nil {
			t.Fatalf("writeManifest: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := measure.VerifyManifest(data, pki.roots, time.Now())
		if err != nil {
			t.Fatalf("verify against the platform root: %v", err)
		}
		if len(got.Chain) < 2 || !got.Chain[0].Equal(pki.leaf) {
			t.Errorf("chain %v, want the leaf then its intermediate", got.Chain)
		}
	})
	t.Run("no chain", func(t *testing.T) {
		pki := newIntermediatePKI(t, false)
		image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
		cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
		path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks())
		if err == nil {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if _, verr := measure.VerifyManifest(data, pki.roots, time.Now()); verr == nil {
				t.Fatal("a manifest without the issuer chain verified against the platform root")
			}
		}
	})
}
