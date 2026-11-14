package diskimage

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ecKMS signs a pre-hashed digest with an ECDSA key, as the platform KMS
// signs with a P-384 manifest key.
type ecKMS struct {
	key *ecdsa.PrivateKey
}

func (k *ecKMS) Sign(_ context.Context, in *platformv1.SignRequest, _ ...grpc.CallOption) (*platformv1.SignResponse, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, in.GetMessage())
	if err != nil {
		return nil, err
	}
	return &platformv1.SignResponse{Signature: sig}, nil
}

// manifestPKI is a platform CA and the manifest key's certificate under it,
// on the CA as "build/manifest".
type manifestPKI struct {
	roots *x509.CertPool
	leaf  *x509.Certificate
	kms   *ecKMS
	ca    *secureboottest.CA
}

func newManifestPKI(t *testing.T) manifestPKI {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now()
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "platform CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rootDER)
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "image builds"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour).Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return manifestPKI{roots: roots, leaf: leaf, kms: &ecKMS{key: key},
		ca: &secureboottest.CA{Certs: map[string]*x509.Certificate{"build/manifest": leaf}}}
}

func (p manifestPKI) clients() iso.KMSClientsFunc {
	return func() (*iso.KMSClients, error) { return &iso.KMSClients{KMS: p.kms, CA: p.ca}, nil }
}

func manifestBanks() []measure.Bank {
	b := measure.Bank{Hash: crypto.SHA256, PCRs: map[int][]byte{}}
	for _, pcr := range measure.ManifestPCRs {
		b.PCRs[pcr] = bytes.Repeat([]byte{byte(pcr)}, sha256.Size)
	}
	return []measure.Bank{b}
}

func TestWriteManifestSignsBesideTheImage(t *testing.T) {
	pki := newManifestPKI(t)
	image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
	digest := sha256.Sum256([]byte("the image"))
	for _, tc := range []struct{ target, model, want string }{
		{"rpi", "", "rpi/rpi4"},
		{"rpi", "cm4", "rpi/cm4"},
		{"qemu-virt", "", "qemu-virt/virt"},
	} {
		target, err := NewTarget(tc.target, tc.model)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
		path, unsigned, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks())
		if err != nil || unsigned != "" {
			t.Fatalf("%s: writeManifest: %v (unsigned %q)", tc.want, err, unsigned)
		}
		if path != filepath.Join(filepath.Dir(image), ManifestFileName) {
			t.Fatalf("written to %s, want beside the image", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := measure.VerifyManifest(data, pki.roots, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		id, _ := measure.ManifestTagID(digest[:])
		if got.Manifest.TagID != id || got.Manifest.Model != tc.want || !reflect.DeepEqual(got.Manifest.Banks, manifestBanks()) {
			t.Errorf("manifest %+v, want tag %v model %s", got.Manifest, id, tc.want)
		}
		if got.Signer.Name != "image builds" || !got.Signer.NotAfter.Equal(pki.leaf.NotAfter) || !got.Chain[0].Equal(pki.leaf) {
			t.Errorf("signer %+v, chain %v", got.Signer, got.Chain)
		}
	}
}

func TestWriteManifestWithoutAKey(t *testing.T) {
	image := filepath.Join(t.TempDir(), "img.img")
	target, _ := NewTarget("qemu-virt", "")
	path, unsigned, err := (&BuildConfig{}).writeManifest(context.Background(), image, hex.EncodeToString(make([]byte, 32)), target, manifestBanks())
	if err != nil || path != "" || unsigned != UnsignedNoManifestKey {
		t.Fatalf("path %q, unsigned %q, err %v", path, unsigned, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(image), ManifestFileName)); !os.IsNotExist(err) {
		t.Errorf("a manifest was written without a key: %v", err)
	}
}

func TestWriteManifestRefuses(t *testing.T) {
	pki := newManifestPKI(t)
	target, _ := NewTarget("qemu-virt", "")
	sum := hex.EncodeToString(make([]byte, 32))
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for _, tc := range []struct {
		name string
		cfg  *BuildConfig
		step string
	}{
		{"a file key", &BuildConfig{ManifestKey: "file:///keys/manifest.key", KMSClients: pki.clients()}, "the manifest key"},
		{"no platform client", &BuildConfig{ManifestKey: "kms://build/manifest"}, "the manifest key"},
		{"a key the CA has no certificate for", &BuildConfig{ManifestKey: "kms://build/other", KMSClients: pki.clients()}, "opening the manifest key"},
		{"a KMS that signs with another key", &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: func() (*iso.KMSClients, error) {
			return &iso.KMSClients{KMS: &ecKMS{key: other}, CA: pki.ca}, nil
		}}, "checking the signed measurement manifest"},
		{"an unreachable platform", &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: func() (*iso.KMSClients, error) {
			return nil, errors.New("connection refused")
		}}, "connecting to the platform"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := filepath.Join(t.TempDir(), "img.img")
			path, _, err := tc.cfg.writeManifest(context.Background(), image, sum, target, manifestBanks())
			var me *MeasureError
			if !errors.As(err, &me) || me.Step != tc.step || path != "" {
				t.Fatalf("path %q, err %v, want step %q", path, err, tc.step)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(image), ManifestFileName)); !os.IsNotExist(err) {
				t.Errorf("a refused manifest was written: %v", err)
			}
		})
	}
}

// Create refuses a manifest key it cannot sign with before it builds.
func TestCreateRefusesAFileManifestKey(t *testing.T) {
	t.Parallel()
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.ManifestKey = "file:///keys/manifest.key"
	var ref *ManifestKeyRefError
	if res, err := Create(context.Background(), cfg); !errors.As(err, &ref) || res != nil {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("the build ran before refusing: %v", rec.Calls)
	}
}
