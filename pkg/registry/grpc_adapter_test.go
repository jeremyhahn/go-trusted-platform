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
