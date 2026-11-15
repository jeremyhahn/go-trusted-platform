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
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// bundleCA is the fake platform CA: it returns certificates by reference and
// the CA bundle (intermediates and roots) the platform publishes.
type bundleCA struct {
	*secureboottest.CA
	bundle []*x509.Certificate
}

func (c bundleCA) GetCABundle(_ context.Context, in *platformv1.GetCABundleRequest, _ ...grpc.CallOption) (*platformv1.GetCABundleResponse, error) {
	var out []byte
	for _, cert := range c.bundle {
		if !in.GetIncludeIntermediates() && !isSelfSigned(cert) {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return &platformv1.GetCABundleResponse{Bundle: &platformv1.CABundle{Pem: out, CertCount: int32(len(c.bundle))}}, nil
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// newIntermediatePKI is a platform root, an intermediate platform CA and a
// manifest signing leaf the intermediate issued.
func newIntermediatePKI(t *testing.T) (manifestPKI, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	issue := func(tmpl, parent *x509.Certificate, pub any, priv *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
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
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "platform root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(72 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := issue(rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	interKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	inter := issue(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "platform intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign},
		root, interKey.Public(), rootKey)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leaf := issue(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "image builds"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour).Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature},
		inter, key.Public(), interKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	pki := manifestPKI{roots: roots, leaf: leaf, kms: &ecKMS{key: key},
		ca: &secureboottest.CA{Certs: map[string]*x509.Certificate{"build/manifest": leaf}}, bundle: []*x509.Certificate{inter, root}}
	return pki, inter, root
}

// TestWriteManifestCarriesTheIssuerChain is Codex P1 on #1907: a manifest
// signed by a key an intermediate platform CA certified verifies against the
// platform root alone, because the manifest carries the intermediate.
func TestWriteManifestCarriesTheIssuerChain(t *testing.T) {
	pki, inter, _ := newIntermediatePKI(t)
	image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
	digest := sha256.Sum256([]byte("the image"))
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("the manifest does not verify against the platform root: %v", err)
	}
	if len(got.Chain) < 2 || !got.Chain[0].Equal(pki.leaf) || !got.Chain[1].Equal(inter) {
		t.Errorf("chain %v, want the leaf then the intermediate", got.Chain)
	}
}

// TestWriteManifestRefusesAMissingChain: with the intermediate dropped from
// the platform's bundle the signer cannot chain to a root, and the build
// refuses rather than writing a manifest no consumer can verify.
func TestWriteManifestRefusesAMissingChain(t *testing.T) {
	pki, _, root := newIntermediatePKI(t)
	pki.bundle = []*x509.Certificate{root}
	image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
	digest := sha256.Sum256([]byte("the image"))
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
	if _, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks()); err == nil {
		t.Fatal("writeManifest wrote a manifest that does not chain to the platform root")
	}
	if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
		t.Errorf("a manifest was written: %v", err)
	}
}
