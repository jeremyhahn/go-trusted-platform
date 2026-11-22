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
	"strings"
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
	return newManifestPKIWithUsage(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
}

// newManifestPKIWithUsage is newManifestPKI with a leaf whose extended key
// usage is usage.
func newManifestPKIWithUsage(t *testing.T, usage []x509.ExtKeyUsage) manifestPKI {
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
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour).Truncate(time.Second), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, key.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return manifestPKI{roots: roots, leaf: leaf, kms: &ecKMS{key: key},
		ca: &secureboottest.CA{Certs: map[string]*x509.Certificate{"build/manifest": leaf},
			Chains: map[string][]*x509.Certificate{"build/manifest": {root}}}}
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
		path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks())
		if err != nil {
			t.Fatalf("%s: writeManifest: %v", tc.want, err)
		}
		if path != ManifestPath(image) {
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

// fakeRegistrar records the manifests Create registers and fails with err.
type fakeRegistrar struct {
	err    error
	sum    string
	signed []byte
}

func (f *fakeRegistrar) RegisterManifest(_ context.Context, sum string, signed []byte) error {
	f.sum, f.signed = sum, signed
	return f.err
}

// TestPublishManifestRegistersTheSignedManifest: Create's manifest step
// registers the bytes it wrote in the reference-values store, and a
// registration failure fails the build.
func TestPublishManifestRegistersTheSignedManifest(t *testing.T) {
	pki := newManifestPKI(t)
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("the image"))
	sum := hex.EncodeToString(digest[:])

	reg := &fakeRegistrar{}
	image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
	cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients(), ReferenceValues: reg}
	path, registered, err := cfg.publishManifest(context.Background(), image, sum, target, manifestBanks())
	if err != nil || !registered {
		t.Fatalf("publishManifest: registered %v, err %v", registered, err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if reg.sum != sum || !reflect.DeepEqual(reg.signed, written) {
		t.Errorf("registered digest %q and %d bytes, want %q and the %d written", reg.sum, len(reg.signed), sum, len(written))
	}

	refused := errors.New("store refused")
	cfg.ReferenceValues = &fakeRegistrar{err: refused}
	_, registered, err = cfg.publishManifest(context.Background(), image, sum, target, manifestBanks())
	var me *MeasureError
	if !errors.As(err, &me) || me.Step != "registering the measurement manifest" || !errors.Is(err, refused) || registered {
		t.Fatalf("a refused registration: registered %v, err %v", registered, err)
	}
}

func TestWriteManifestRefusesAnEmptyKey(t *testing.T) {
	image := filepath.Join(t.TempDir(), "img.img")
	target, _ := NewTarget("qemu-virt", "")
	path, err := (&BuildConfig{}).writeManifest(context.Background(), image, hex.EncodeToString(make([]byte, 32)), target, manifestBanks())
	var me *MeasureError
	if !errors.As(err, &me) || me.Step != "the manifest key" || path != "" {
		t.Fatalf("path %q, err %v", path, err)
	}
	if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
		t.Errorf("a manifest was written without a key: %v", err)
	}
}

// TestWithDefaultsSignsWithTheReleaseKey: a build names no manifest key and
// signs with the tenant release key (ruling 134); a named key is kept.
func TestWithDefaultsSignsWithTheReleaseKey(t *testing.T) {
	if got := (&BuildConfig{}).withDefaults().ManifestKey; got != DefaultManifestKey {
		t.Errorf("default manifest key %q, want %q", got, DefaultManifestKey)
	}
	if got := (&BuildConfig{ManifestKey: "kms://build/manifest"}).withDefaults().ManifestKey; got != "kms://build/manifest" {
		t.Errorf("named manifest key became %q", got)
	}
}

// Two images built into one directory keep their own manifests: the second
// build never overwrites the first image's measurements.
func TestWriteManifestPerImage(t *testing.T) {
	pki := newManifestPKI(t)
	dir := t.TempDir()
	cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
	written := map[string]measure.Manifest{}
	for _, tc := range []struct{ image, target string }{{"rpi.img", "rpi"}, {"qemu.img", "qemu-virt"}} {
		target, err := NewTarget(tc.target, "")
		if err != nil {
			t.Fatal(err)
		}
		image := filepath.Join(dir, tc.image)
		digest := sha256.Sum256([]byte(tc.image))
		path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(digest[:]), target, manifestBanks())
		if err != nil {
			t.Fatal(err)
		}
		if path != image+".corim" {
			t.Fatalf("%s: manifest at %s, want %s.corim", tc.image, path, image)
		}
		id, _ := measure.ManifestTagID(digest[:])
		written[path] = measure.Manifest{TagID: id, Model: target.Name() + "/" + target.ModelName()}
	}
	for path, want := range written {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got, err := measure.VerifyManifest(data, pki.roots, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got.Manifest.TagID != want.TagID || got.Manifest.Model != want.Model {
			t.Errorf("%s holds tag %v model %s, want tag %v model %s", path, got.Manifest.TagID, got.Manifest.Model, want.TagID, want.Model)
		}
	}
}

// removeManifest deletes a previous build's manifest and is a no-op when
// there is none.
func TestRemoveManifest(t *testing.T) {
	image := filepath.Join(t.TempDir(), "img.img")
	if err := removeManifest(image); err != nil {
		t.Fatalf("no manifest to remove: %v", err)
	}
	if err := os.WriteFile(ManifestPath(image), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeManifest(image); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
		t.Errorf("the stale manifest is still there: %v", err)
	}
	// A manifest path that cannot be removed fails the build.
	if err := os.Remove(ManifestPath(image)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ManifestPath(image), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var me *MeasureError
	if err := removeManifest(image); !errors.As(err, &me) {
		t.Errorf("an unremovable manifest path: err %v, want a MeasureError", err)
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
			path, err := tc.cfg.writeManifest(context.Background(), image, sum, target, manifestBanks())
			var me *MeasureError
			if !errors.As(err, &me) || me.Step != tc.step || path != "" {
				t.Fatalf("path %q, err %v, want step %q", path, err, tc.step)
			}
			if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
				t.Errorf("a refused manifest was written: %v", err)
			}
		})
	}
}

func TestWriteManifestRefusesATLSOnlyManifestCertificate(t *testing.T) {
	pki := newManifestPKIWithUsage(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	cfg := &BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}
	target, _ := NewTarget("qemu-virt", "")
	image := filepath.Join(t.TempDir(), "img.img")
	path, err := cfg.writeManifest(context.Background(), image, hex.EncodeToString(make([]byte, 32)), target, manifestBanks())
	var me *MeasureError
	if want := "building the manifest certificate's chain"; !errors.As(err, &me) || me.Step != want || path != "" {
		t.Fatalf("path %q, err %v, want step %q", path, err, want)
	}
	if _, err := os.Stat(ManifestPath(image)); !os.IsNotExist(err) {
		t.Errorf("a refused manifest was written: %v", err)
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

// TestCreateRefusesASecureBootBuildWithoutAPlatformClient: a measured build
// is always signed, so with no platform client to reach the release key it
// is refused before any container runs.
func TestCreateRefusesASecureBootBuildWithoutAPlatformClient(t *testing.T) {
	t.Parallel()
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.ISO.SecureBoot = true
	cfg.KMSClients = nil
	var se *StageError
	res, err := Create(context.Background(), cfg)
	if !errors.As(err, &se) || !errors.Is(err, errNoManifestKMS) || res != nil {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("the build ran before refusing: %v", rec.Calls)
	}
}

// TestPublishManifestSkipsRegistrationWithoutARegistrar: the pinned
// go-quicbaas SDK has no reference-values client, so with no registrar
// publishManifest refuses a measured build it cannot register: docs/SPEC.md:57
// requires every image's signed manifest in the reference-values store, so a
// missing registrar is a MeasureError, never a success (Codex P1, #1907).
func TestPublishManifestRefusesWithoutARegistrar(t *testing.T) {
	pki := newManifestPKI(t)
	target, err := NewTarget("rpi", "")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("the image"))
	sum := hex.EncodeToString(digest[:])
	image := filepath.Join(t.TempDir(), "trusted-platform-rpi.img")
	cfg := (&BuildConfig{ManifestKey: "kms://build/manifest", KMSClients: pki.clients()}).withDefaults()
	_, registered, err := cfg.publishManifest(context.Background(), image, sum, target, manifestBanks())
	var me *MeasureError
	if !errors.As(err, &me) || registered {
		t.Fatalf("no registrar: registered %v, err %v, want a MeasureError", registered, err)
	}
	if !strings.Contains(me.Error(), "reference-values registrar") {
		t.Fatalf("error %q does not name the missing registrar", me.Error())
	}
}

// TestValidateManifestKeyAllowsASecureBootBuildWithoutARegistrar:
// validateManifestKey checks only the manifest signing key, so a measured
// build with no reference-values registrar passes it; Create refuses the
// missing registrar itself, before it stages anything
// (TestCreateRefusesAMeasuredBuildWithoutARegistrarBeforeAssembly).
func TestValidateManifestKeyAllowsASecureBootBuildWithoutARegistrar(t *testing.T) {
	t.Parallel()
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.ISO.SecureBoot = true
	cfg.KMSClients = newManifestPKI(t).clients()
	cfg.ReferenceValues = nil
	if err := cfg.withDefaults().validateManifestKey(); err != nil {
		t.Fatalf("validateManifestKey: %v", err)
	}
}

// TestCreateReportsAnUnknownTargetBeforeAMissingRegistrar: a usage error (an
// unknown target) wins over a missing dependency, so a measured build with no
// registrar and a bad target is told about the target.
func TestCreateReportsAnUnknownTargetBeforeAMissingRegistrar(t *testing.T) {
	t.Parallel()
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.Target = "nope"
	cfg.SkipPreflight = true
	cfg.ISO.SecureBoot = true
	cfg.KMSClients = newManifestPKI(t).clients()
	cfg.ReferenceValues = nil
	var ue *UnknownTargetError
	res, err := Create(context.Background(), cfg)
	if !errors.As(err, &ue) || res != nil {
		t.Fatalf("result %+v, err %v", res, err)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("the build ran before refusing: %v", rec.Calls)
	}
}

// TestCreateRefusesAMeasuredBuildWithoutARegistrarBeforeAssembly: a Secure
// Boot build is the measured one and docs/SPEC.md:57 needs its manifest
// registered, so with no reference-values registrar Create refuses it at
// configuration, before it stages media, removes the earlier manifest or
// assembles: the earlier image and its manifest are left untouched.
func TestCreateRefusesAMeasuredBuildWithoutARegistrarBeforeAssembly(t *testing.T) {
	t.Parallel()
	rec := &diskimagetest.Runner{}
	cfg := buildConfigForTest(t, "qemu-virt", rec)
	cfg.ISO.SecureBoot = true
	cfg.KMSClients = newManifestPKI(t).clients()
	cfg.ReferenceValues = nil
	if err := os.MkdirAll(filepath.Dir(cfg.Output), 0o755); err != nil {
		t.Fatal(err)
	}
	earlierImage := []byte("earlier image")
	earlierManifest := []byte("earlier manifest")
	if err := os.WriteFile(cfg.Output, earlierImage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ManifestPath(cfg.Output), earlierManifest, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Create(context.Background(), cfg)
	var se *StageError
	if !errors.As(err, &se) || se.Step != "configuration" {
		t.Fatalf("want a configuration StageError, got result %+v, err %v", res, err)
	}
	if !errors.Is(err, errNoRegistrar) {
		t.Errorf("err %v, want errNoRegistrar", err)
	}
	if res != nil {
		t.Errorf("result %+v, want nil", res)
	}
	if len(rec.Calls) != 0 {
		t.Errorf("the build ran before refusing: %v", rec.Calls)
	}
	for path, want := range map[string][]byte{cfg.Output: earlierImage, ManifestPath(cfg.Output): earlierManifest} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s = %q, want the earlier %q", path, got, want)
		}
	}
}
