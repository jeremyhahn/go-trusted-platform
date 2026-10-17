// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// pushEnvelope marshals the JSON push envelope the gRPC and REST transports
// carry for one image with the given layers.
func pushEnvelope(t *testing.T, layers ...[]byte) []byte {
	t.Helper()
	const layerType = "application/vnd.oci.image.layer.v1.tar"
	img := Image{Manifest: &ImageManifest{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json"}}
	for _, content := range layers {
		sum := sha256.Sum256(content)
		d := "sha256:" + hex.EncodeToString(sum[:])
		img.Layers = append(img.Layers, Layer{Digest: d, MediaType: layerType, Size: int64(len(content)), Content: content})
		img.Manifest.Layers = append(img.Manifest.Layers, Descriptor{MediaType: layerType, Digest: d, Size: int64(len(content))})
	}
	data, err := json.Marshal(img)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

// TestGRPCAdapter_PushPullRoundTripsLayerContent pins the envelope: a layer
// pushed through PushStream comes back byte for byte from Pull. The layer
// bytes used to be dropped from the JSON envelope, so storage held empty
// blobs and every pull returned layers without content.
func TestGRPCAdapter_PushPullRoundTripsLayerContent(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()
	layers := [][]byte{[]byte("layer-one"), []byte("layer-two")}

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	if _, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, layers...))); err != nil {
		t.Fatalf("PushStream: %v", err)
	}

	resp, err := a.Pull(ctx, &grpcapi.RegistryPullRequest{Repository: "apps/web", Reference: "v1"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	var pulled Image
	if err := json.Unmarshal(resp.Data, &pulled); err != nil {
		t.Fatalf("decode pull envelope: %v", err)
	}
	if len(pulled.Layers) != len(layers) {
		t.Fatalf("pulled %d layers, want %d", len(pulled.Layers), len(layers))
	}
	for i, want := range layers {
		if !bytes.Equal(pulled.Layers[i].Content, want) {
			t.Errorf("layer %d content = %q, want %q", i, pulled.Layers[i].Content, want)
		}
	}
}

// TestGRPCAdapter_PushRejectsAnEnvelopeWithoutAManifest asserts a payload
// that decodes but carries no manifest is refused with ErrInvalidManifest.
func TestGRPCAdapter_PushRejectsAnEnvelopeWithoutAManifest(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}

	_, err := a.PushStream(context.Background(), meta, bytes.NewReader([]byte(`{"layers":[]}`)))
	var invalid ErrInvalidManifest
	if !errors.As(err, &invalid) {
		t.Fatalf("PushStream error = %v, want ErrInvalidManifest", err)
	}
}

// TestGRPCAdapter_PushRefusesAnExistingTagWithoutOverwrite pins the default:
// a second push to the same tag is refused when the overwrite annotation is
// absent or not "true".
func TestGRPCAdapter_PushRefusesAnExistingTagWithoutOverwrite(t *testing.T) {
	for name, annotations := range map[string]map[string]string{
		"absent": nil,
		"false":  {regsvc.AnnotationOverwrite: "false"},
	} {
		t.Run(name, func(t *testing.T) {
			a := NewGRPCAdapter(newTestRegistry(t))
			ctx := context.Background()
			first := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
			if _, err := a.PushStream(ctx, first, bytes.NewReader(pushEnvelope(t, []byte("one")))); err != nil {
				t.Fatalf("first PushStream: %v", err)
			}

			second := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1", Annotations: annotations}
			_, err := a.PushStream(ctx, second, bytes.NewReader(pushEnvelope(t, []byte("two"))))
			var exists grpcapi.ErrArtifactAlreadyExists
			if !errors.As(err, &exists) {
				t.Fatalf("second PushStream error = %v, want ErrArtifactAlreadyExists", err)
			}
		})
	}
}

// TestGRPCAdapter_PushOverwriteReplacesTheTag pins the overwrite annotation:
// the adapter used to drop it, so `registry push --overwrite` and the REST
// X-Trusted-Platform-Overwrite header were refused like a plain push.
func TestGRPCAdapter_PushOverwriteReplacesTheTag(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()
	first := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	if _, err := a.PushStream(ctx, first, bytes.NewReader(pushEnvelope(t, []byte("one")))); err != nil {
		t.Fatalf("first PushStream: %v", err)
	}

	second := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{regsvc.AnnotationOverwrite: "true"},
	}
	if _, err := a.PushStream(ctx, second, bytes.NewReader(pushEnvelope(t, []byte("two")))); err != nil {
		t.Fatalf("overwrite PushStream: %v", err)
	}

	resp, err := a.Pull(ctx, &grpcapi.RegistryPullRequest{Repository: "apps/web", Reference: "v1"})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	var pulled Image
	if err := json.Unmarshal(resp.Data, &pulled); err != nil {
		t.Fatalf("decode pull envelope: %v", err)
	}
	if len(pulled.Layers) != 1 || !bytes.Equal(pulled.Layers[0].Content, []byte("two")) {
		t.Fatalf("pulled layers = %+v, want the overwriting layer %q", pulled.Layers, "two")
	}
}

// TestPushOptionsOf_MapsEveryPushAnnotation pins the annotation contract the
// CLI's push flags travel on (docs/registry/cli.md §3).
func TestPushOptionsOf_MapsEveryPushAnnotation(t *testing.T) {
	opts := pushOptionsOf(map[string]string{
		regsvc.AnnotationOverwrite:    "true",
		regsvc.AnnotationEncrypt:      "true",
		regsvc.AnnotationKeyID:        "apps-web-dek",
		regsvc.AnnotationSign:         "true",
		regsvc.AnnotationSigningKeyID: "apps-web-signer",
	})

	if !opts.AllowOverwrite || !opts.Encrypt || !opts.SignImage {
		t.Fatalf("flags = overwrite %v encrypt %v sign %v, want all true", opts.AllowOverwrite, opts.Encrypt, opts.SignImage)
	}
	if opts.KeyID != "apps-web-dek" || opts.SigningKeyID != "apps-web-signer" {
		t.Fatalf("key IDs = %q %q, want %q %q", opts.KeyID, opts.SigningKeyID, "apps-web-dek", "apps-web-signer")
	}
}

// TestPushOptionsOf_OnlyTrueTurnsAnOptionOn guards against a non-"true"
// value (or none) requesting encryption, signing or an overwrite.
func TestPushOptionsOf_OnlyTrueTurnsAnOptionOn(t *testing.T) {
	for name, annotations := range map[string]map[string]string{
		"absent": nil,
		"false": {
			regsvc.AnnotationOverwrite: "false",
			regsvc.AnnotationEncrypt:   "false",
			regsvc.AnnotationSign:      "yes",
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := pushOptionsOf(annotations)
			if opts.AllowOverwrite || opts.Encrypt || opts.SignImage {
				t.Fatalf("flags = overwrite %v encrypt %v sign %v, want all false", opts.AllowOverwrite, opts.Encrypt, opts.SignImage)
			}
		})
	}
}

// TestGRPCAdapter_PushEncryptAnnotationEncryptsUnderTheKey covers
// `registry push --encrypt --key-id`: the adapter used to drop both, so the
// image was stored in the clear. The response artifact reports the
// encryption and key the CLI prints.
func TestGRPCAdapter_PushEncryptAnnotationEncryptsUnderTheKey(t *testing.T) {
	storage, err := NewQuicBaaSStorage(newMockStorageClient())
	if err != nil {
		t.Fatalf("NewQuicBaaSStorage: %v", err)
	}
	kms, err := NewLocalKMSClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalKMSClient: %v", err)
	}
	enc, err := NewImageEncryptor(kms)
	if err != nil {
		t.Fatalf("NewImageEncryptor: %v", err)
	}
	reg, err := NewRegistry(validTestConfig(), testLogger(), WithStorage(storage), WithEncryptor(enc))
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	a := NewGRPCAdapter(reg)
	meta := &grpcapi.RegistryPushMetadata{
		Repository: "apps/web",
		Tag:        "v1",
		Annotations: map[string]string{
			regsvc.AnnotationEncrypt: "true",
			regsvc.AnnotationKeyID:   "apps-web-dek",
		},
	}
	resp, err := a.PushStream(context.Background(), meta, bytes.NewReader(pushEnvelope(t, []byte("secret"))))
	if err != nil {
		t.Fatalf("encrypted PushStream: %v", err)
	}
	if got := resp.Artifact.Annotations[regsvc.ManifestAnnotationEncrypted]; got != "true" {
		t.Fatalf("artifact annotation %q = %q, want %q", regsvc.ManifestAnnotationEncrypted, got, "true")
	}
	if got := resp.Artifact.Annotations[regsvc.ManifestAnnotationKeyID]; got == "" {
		t.Fatalf("artifact annotation %q is empty, want the encryption key", regsvc.ManifestAnnotationKeyID)
	}
}

// TestGRPCAdapter_PushSignAnnotationIsRefusedWithoutASigner covers
// `registry push --sign`: the adapter used to drop the annotation and store
// the image unsigned. A registry with no manifest signer refuses instead.
func TestGRPCAdapter_PushSignAnnotationIsRefusedWithoutASigner(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	meta := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{regsvc.AnnotationSign: "true"},
	}

	_, err := a.PushStream(context.Background(), meta, bytes.NewReader(pushEnvelope(t, []byte("one"))))
	var notConfigured ErrSigningNotConfigured
	if !errors.As(err, &notConfigured) {
		t.Fatalf("signed PushStream error = %v, want ErrSigningNotConfigured", err)
	}
}
