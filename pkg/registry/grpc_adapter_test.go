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

// TestGRPCAdapter_PushAnswersTheManifestDigest is the regression for the
// push response whose artifact carried no digest: the digest is the one the
// OCI distribution endpoint serves for the stored manifest.
func TestGRPCAdapter_PushAnswersTheManifestDigest(t *testing.T) {
	reg := newTestRegistry(t)
	a := NewGRPCAdapter(reg)
	ctx := context.Background()

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	resp, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, []byte("layer-one"))))
	if err != nil {
		t.Fatalf("PushStream: %v", err)
	}
	_, body, err := reg.GetManifest(ctx, "apps/web", "v1")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if want := sha256Digest(body); resp.Artifact.Digest != want {
		t.Errorf("push digest = %q, want the stored manifest's %q", resp.Artifact.Digest, want)
	}
}

func TestGRPCAdapter_ManifestToArtifactWithoutAManifestCarriesNoDigest(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	artifact, err := a.manifestToArtifact("apps/web", "v1", nil)
	if err != nil {
		t.Fatalf("manifestToArtifact: %v", err)
	}
	if artifact.Digest != "" {
		t.Errorf("digest = %q, want empty for a missing manifest", artifact.Digest)
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

// An uppercase repository breaks the OCI distribution-spec name grammar: the
// adapter answers with the typed client error the gRPC surface maps to
// InvalidArgument, not the registry's internal error (m779, run 58285).
func TestGRPCAdapter_InvalidReferenceIsTheClientsError(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()

	meta := &grpcapi.RegistryPushMetadata{Repository: "Unix-1792467644-push-basic", Tag: "v1"}
	_, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, []byte("one"))))
	var invalid grpcapi.ErrInvalidArtifactReference
	if !errors.As(err, &invalid) {
		t.Fatalf("PushStream error = %v, want ErrInvalidArtifactReference", err)
	}
	if invalid.Reference != "Unix-1792467644-push-basic:v1" {
		t.Errorf("Reference = %q, want the pushed reference", invalid.Reference)
	}

	_, err = a.Delete(ctx, &grpcapi.RegistryDeleteRequest{Repository: "Apps/Web", Reference: "v1"})
	if !errors.As(err, &invalid) {
		t.Fatalf("Delete error = %v, want ErrInvalidArtifactReference", err)
	}
}

func TestGRPCAdapter_PullOfAnAbsentImageIsNotFound(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	_, err := a.Pull(context.Background(), &grpcapi.RegistryPullRequest{Repository: "apps/absent", Reference: "v1"})
	var notFound grpcapi.ErrArtifactNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Pull error = %v, want ErrArtifactNotFound", err)
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
