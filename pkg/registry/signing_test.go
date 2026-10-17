// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package registry

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// errKeyStoreDown is the failure the unavailable key store returns.
type errKeyStoreDown struct{}

func (errKeyStoreDown) Error() string { return "key store down" }

// downKeyStore is a SigningKeyStore that can neither create nor find keys.
type downKeyStore struct{}

func (downKeyStore) GenerateKey(context.Context, *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errKeyStoreDown{}
}

func (downKeyStore) Signer(context.Context, *xkmssdk.KeyAttributes) (crypto.Signer, error) {
	return nil, errKeyStoreDown{}
}

func newTestSigner(t *testing.T, dir string) *ManifestSigner {
	t.Helper()
	signer, err := NewFileManifestSigner(dir)
	if err != nil {
		t.Fatalf("NewFileManifestSigner: %v", err)
	}
	return signer
}

func testManifest() *ImageManifest {
	return &ImageManifest{
		Reference:     "apps/web:v1",
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Layers:        []Descriptor{{MediaType: "application/octet-stream", Digest: "sha256:" + repeat64("a"), Size: 5}},
	}
}

// newSigningRegistry is a registry on in-memory storage that signs with
// signer; a nil signer leaves the registry without one.
func newSigningRegistry(t *testing.T, signer *ManifestSigner) *Registry {
	t.Helper()
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	opts := []RegistryOption{WithStorage(storage), WithVersion("v1.2.3")}
	if signer != nil {
		opts = append(opts, WithSigner(signer))
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), opts...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func pushTestImage(t *testing.T, reg *Registry, ref string, opts PushOptions) {
	t.Helper()
	image := &Image{
		Manifest: &ImageManifest{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json"},
	}
	if err := reg.Push(context.Background(), ref, image, opts); err != nil {
		t.Fatalf("Push %s: %v", ref, err)
	}
}

func TestNewManifestSigner_RequiresKeyStore(t *testing.T) {
	_, err := NewManifestSigner(nil)

	var required ErrSigningKeyStoreRequired
	if !errors.As(err, &required) {
		t.Fatalf("NewManifestSigner(nil) error = %v, want ErrSigningKeyStoreRequired", err)
	}
}

// The first signature creates the default key; the manifest then carries
// the signature, key ID and algorithm, and verifies.
func TestManifestSigner_SignThenVerify(t *testing.T) {
	signer := newTestSigner(t, t.TempDir())
	m := testManifest()

	if err := signer.Sign(context.Background(), m, ""); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if m.Annotations[ManifestAnnotationSigningKeyID] != DefaultSigningKeyID ||
		m.Annotations[ManifestAnnotationSignatureAlgorithm] != SignatureAlgorithm ||
		!isSigned(m) {
		t.Fatalf("annotations after Sign = %v", m.Annotations)
	}
	if err := signer.Verify(context.Background(), m); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// The signing keys are files under the key store directory, so a signer
// opened later on the same directory verifies what an earlier one signed.
func TestNewFileManifestSigner_KeysPersist(t *testing.T) {
	dir := t.TempDir()
	m := testManifest()
	if err := newTestSigner(t, dir).Sign(context.Background(), m, "apps-web-signer"); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := newTestSigner(t, dir).Verify(context.Background(), m); err != nil {
		t.Fatalf("Verify with a reopened key store: %v", err)
	}
}

// A key store directory that cannot be created leaves the signer unable to
// get a key.
func TestNewFileManifestSigner_UnusableDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	dir := filepath.Join(file, "signing-keys")

	signer, err := NewFileManifestSigner(dir)
	if err != nil {
		var unavailable ErrSigningKeyStoreUnavailable
		if !errors.As(err, &unavailable) || unavailable.Dir != dir {
			t.Fatalf("NewFileManifestSigner error = %v, want ErrSigningKeyStoreUnavailable for %s", err, dir)
		}
		return
	}
	err = signer.Sign(context.Background(), testManifest(), "")
	var keyErr ErrSigningKeyUnavailable
	if !errors.As(err, &keyErr) {
		t.Fatalf("Sign error = %v, want ErrSigningKeyUnavailable", err)
	}
}

func TestManifestSigner_SignRejectsInvalidKeyID(t *testing.T) {
	signer := newTestSigner(t, t.TempDir())

	err := signer.Sign(context.Background(), testManifest(), "../escape")

	var invalid ErrInvalidSigningKeyID
	if !errors.As(err, &invalid) || invalid.KeyID != "../escape" {
		t.Fatalf("Sign error = %v, want ErrInvalidSigningKeyID", err)
	}
}

func TestManifestSigner_SignWithoutAKey(t *testing.T) {
	signer, err := NewManifestSigner(downKeyStore{})
	if err != nil {
		t.Fatalf("NewManifestSigner: %v", err)
	}

	err = signer.Sign(context.Background(), testManifest(), "")

	var unavailable ErrSigningKeyUnavailable
	if !errors.As(err, &unavailable) || !errors.Is(err, errKeyStoreDown{}) {
		t.Fatalf("Sign error = %v, want ErrSigningKeyUnavailable wrapping the key store error", err)
	}
}

// Every way a signed manifest can fail to verify is refused with a typed
// error.
func TestManifestSigner_VerifyRefuses(t *testing.T) {
	signer := newTestSigner(t, t.TempDir())
	signed := func(t *testing.T) *ImageManifest {
		m := testManifest()
		if err := signer.Sign(context.Background(), m, ""); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return m
	}

	tests := []struct {
		name    string
		tamper  func(m *ImageManifest)
		wantErr error
	}{
		{"changed layer", func(m *ImageManifest) { m.Layers[0].Digest = "sha256:" + repeat64("c") }, ErrSignatureInvalid{}},
		{"changed annotation", func(m *ImageManifest) { m.Annotations["org.example.extra"] = "x" }, ErrSignatureInvalid{}},
		{"unsupported algorithm", func(m *ImageManifest) { m.Annotations[ManifestAnnotationSignatureAlgorithm] = "RSA" }, ErrSignatureInvalid{}},
		{"signature not base64", func(m *ImageManifest) { m.Annotations[ManifestAnnotationSignature] = "!!" }, ErrSignatureInvalid{}},
		{"unknown key", func(m *ImageManifest) { m.Annotations[ManifestAnnotationSigningKeyID] = "never-created" }, ErrSigningKeyUnavailable{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := signed(t)
			tt.tamper(m)

			err := signer.Verify(context.Background(), m)
			switch tt.wantErr.(type) {
			case ErrSignatureInvalid:
				var invalid ErrSignatureInvalid
				if !errors.As(err, &invalid) {
					t.Fatalf("Verify error = %v, want ErrSignatureInvalid", err)
				}
			case ErrSigningKeyUnavailable:
				var unavailable ErrSigningKeyUnavailable
				if !errors.As(err, &unavailable) {
					t.Fatalf("Verify error = %v, want ErrSigningKeyUnavailable", err)
				}
			}
		})
	}
}

// A signed push stores a manifest that a verifying pull accepts.
func TestRegistryPull_VerifiesSignedManifest(t *testing.T) {
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	pushTestImage(t, reg, "apps/web:v1", PushOptions{SignImage: true})

	img, err := reg.Pull(context.Background(), "apps/web:v1", PullOptions{VerifySignature: true})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if !isSigned(img.Manifest) {
		t.Fatalf("pulled manifest carries no signature: %v", img.Manifest.Annotations)
	}
}

// A signed manifest changed in storage is refused on every pull, whether
// or not the caller asked for verification.
func TestRegistryPull_RefusesTamperedSignedManifest(t *testing.T) {
	ctx := context.Background()
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	pushTestImage(t, reg, "apps/web:v1", PushOptions{SignImage: true})
	img, err := reg.Pull(ctx, "apps/web:v1", PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	img.Manifest.Annotations["org.example.injected"] = "x"
	if err := reg.storage.StoreManifest(ctx, "apps/web:v1", img.Manifest); err != nil {
		t.Fatalf("StoreManifest: %v", err)
	}

	_, err = reg.Pull(ctx, "apps/web:v1", PullOptions{})

	var invalid ErrSignatureInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("Pull error = %v, want ErrSignatureInvalid", err)
	}
}

// A verifying pull refuses an unsigned image; a plain pull serves it.
func TestRegistryPull_VerifyRefusesUnsignedManifest(t *testing.T) {
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	pushTestImage(t, reg, "apps/web:v1", PushOptions{})

	_, err := reg.Pull(context.Background(), "apps/web:v1", PullOptions{VerifySignature: true})
	var notSigned ErrImageNotSigned
	if !errors.As(err, &notSigned) {
		t.Fatalf("verifying Pull error = %v, want ErrImageNotSigned", err)
	}
	if _, err := reg.Pull(context.Background(), "apps/web:v1", PullOptions{}); err != nil {
		t.Fatalf("plain Pull: %v", err)
	}
}

// A registry with no signer cannot vouch for a signed manifest and refuses
// it.
func TestRegistryPull_SignedManifestWithoutSigner(t *testing.T) {
	ctx := context.Background()
	m := testManifest()
	if err := newTestSigner(t, t.TempDir()).Sign(ctx, m, ""); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	reg := newSigningRegistry(t, nil)
	if err := reg.storage.StoreManifest(ctx, "apps/web:v1", m); err != nil {
		t.Fatalf("StoreManifest: %v", err)
	}

	_, err := reg.Pull(ctx, "apps/web:v1", PullOptions{})

	var notConfigured ErrSigningNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("Pull error = %v, want ErrSigningNotConfigured", err)
	}
}

// Signature annotations a client sends are dropped; only the registry's
// signer writes them.
func TestRegistryPush_DropsClientSignatureAnnotations(t *testing.T) {
	ctx := context.Background()
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	image := &Image{Manifest: &ImageManifest{
		SchemaVersion: 2,
		Annotations:   map[string]string{ManifestAnnotationSignature: "Zm9yZ2Vk", ManifestAnnotationSigningKeyID: "forged"},
	}}
	if err := reg.Push(ctx, "apps/web:v1", image, PushOptions{}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	img, err := reg.Pull(ctx, "apps/web:v1", PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if isSigned(img.Manifest) || img.Manifest.Annotations[ManifestAnnotationSigningKeyID] != "" {
		t.Fatalf("stored manifest kept client signature annotations: %v", img.Manifest.Annotations)
	}
}

// inspect --signature reports the signature of a signed image and nothing
// for an unsigned one.
func TestGRPCAdapter_InspectReportsSignature(t *testing.T) {
	reg := newSigningRegistry(t, newTestSigner(t, t.TempDir()))
	pushTestImage(t, reg, "apps/web:signed", PushOptions{SignImage: true, SigningKeyID: "apps-web-signer"})
	pushTestImage(t, reg, "apps/web:plain", PushOptions{})
	a := NewGRPCAdapter(reg)

	resp, err := a.Inspect(context.Background(), &grpcapi.RegistryInspectRequest{
		Repository: "apps/web", Reference: "signed", IncludeSignatures: true,
	})
	if err != nil {
		t.Fatalf("Inspect signed: %v", err)
	}
	sigs := resp.Detail.Signatures
	if len(sigs) != 1 || sigs[0].KeyID != "apps-web-signer" || sigs[0].Algorithm != SignatureAlgorithm || len(sigs[0].Signature) == 0 {
		t.Fatalf("signatures = %+v, want one ECDSA signature by apps-web-signer", sigs)
	}

	resp, err = a.Inspect(context.Background(), &grpcapi.RegistryInspectRequest{
		Repository: "apps/web", Reference: "plain", IncludeSignatures: true,
	})
	if err != nil {
		t.Fatalf("Inspect plain: %v", err)
	}
	if len(resp.Detail.Signatures) != 0 {
		t.Fatalf("unsigned image reports signatures %+v", resp.Detail.Signatures)
	}
}

// A signed push over the gRPC adapter reaches the signer, and its response
// artifact carries the signature annotation a verifying client checks.
func TestGRPCAdapter_PushSignAnnotationSigns(t *testing.T) {
	a := NewGRPCAdapter(newSigningRegistry(t, newTestSigner(t, t.TempDir())))
	meta := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{regsvc.AnnotationSign: "true"},
	}

	resp, err := a.PushStream(context.Background(), meta, bytes.NewReader(pushEnvelope(t, []byte("one"))))
	if err != nil {
		t.Fatalf("signed PushStream: %v", err)
	}
	if !regsvc.IsSigned(resp.Artifact.Annotations) {
		t.Fatalf("artifact annotations %v carry no signature", resp.Artifact.Annotations)
	}
}

// Status reports the daemon version and the time the registry started, not
// the time of the request.
func TestGRPCAdapter_StatusReportsVersionAndStartTime(t *testing.T) {
	reg := newSigningRegistry(t, nil)
	a := NewGRPCAdapter(reg)
	a.clock = func() time.Time { return reg.startedAt.Add(time.Hour) }

	resp, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.Version != "v1.2.3" {
		t.Fatalf("Version = %q, want %q", resp.Version, "v1.2.3")
	}
	if !resp.StartedAt.Equal(reg.startedAt) || resp.Timestamp.Sub(resp.StartedAt) != time.Hour {
		t.Fatalf("StartedAt = %v, Timestamp = %v, want an hour of uptime", resp.StartedAt, resp.Timestamp)
	}
}

// An unhealthy status still reports the version and start time.
func TestGRPCAdapter_StatusUnhealthyKeepsVersionAndStartTime(t *testing.T) {
	client := newMockStorageClient()
	client.listErr = errKeyStoreDown{}
	storage, err := NewQuicBaaSStorage(client)
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage), WithVersion("v1.2.3"))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	resp, err := NewGRPCAdapter(reg).Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.Health != grpcapi.RegistryHealthStatusUnhealthy || resp.Version != "v1.2.3" || !resp.StartedAt.Equal(reg.startedAt) {
		t.Fatalf("status = health %v version %q started %v", resp.Health, resp.Version, resp.StartedAt)
	}
}
