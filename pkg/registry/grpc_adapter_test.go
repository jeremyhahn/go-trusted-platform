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
	"time"

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

// configuredEnvelope is pushEnvelope with an image config blob attached.
func configuredEnvelope(t *testing.T, config []byte, layers ...[]byte) []byte {
	t.Helper()
	var img Image
	if err := json.Unmarshal(pushEnvelope(t, layers...), &img); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	sum := sha256.Sum256(config)
	img.Config = config
	img.Manifest.Config = Descriptor{
		MediaType: "application/vnd.oci.image.config.v1+json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Size:      int64(len(config)),
	}
	data, err := json.Marshal(img)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return data
}

func TestGRPCAdapter_InspectReportsTheConfigAndEveryLayer(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()
	config := []byte(`{"architecture":"amd64","os":"linux","author":"platform"}`)
	layers := [][]byte{[]byte("layer-one"), []byte("layer-two")}

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	if _, err := a.PushStream(ctx, meta, bytes.NewReader(configuredEnvelope(t, config, layers...))); err != nil {
		t.Fatalf("PushStream: %v", err)
	}

	resp, err := a.Inspect(ctx, &grpcapi.RegistryInspectRequest{Repository: "apps/web", Reference: "v1"})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	art := resp.Detail.Artifact
	if art.OS != "linux" || art.Architecture != "amd64" || art.Author != "platform" {
		t.Errorf("config = os %q arch %q author %q, want linux amd64 platform", art.OS, art.Architecture, art.Author)
	}
	if got := len(art.Manifest.Layers); got != len(layers) {
		t.Fatalf("inspect reports %d layers, want %d", got, len(layers))
	}
	if want := int64(len(layers[0]) + len(layers[1])); art.Size != want {
		t.Errorf("size = %d, want %d", art.Size, want)
	}
	if art.Manifest.ConfigDigest == "" {
		t.Error("config digest is empty")
	}
}

func TestGRPCAdapter_PushRefusesAConfigThatIsNotJSONBeforeStoring(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	envelope := configuredEnvelope(t, []byte("not-json"), []byte("layer-one"))
	_, err := a.PushStream(ctx, meta, bytes.NewReader(envelope))
	if !errors.As(err, &ErrInvalidManifest{}) {
		t.Fatalf("PushStream error = %v, want ErrInvalidManifest", err)
	}
	if _, err := a.Inspect(ctx, &grpcapi.RegistryInspectRequest{Repository: "apps/web", Reference: "v1"}); err == nil {
		t.Error("Inspect found an image whose push was refused")
	}
}

// newEncryptingTestRegistry is newTestRegistry with an image encryptor
// over a local KMS.
func newEncryptingTestRegistry(t *testing.T) *Registry {
	t.Helper()
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
	return reg
}

func TestPushOptionsOf(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        PushOptions
	}{
		{name: "no annotations", annotations: nil, want: PushOptions{}},
		{
			name:        "encrypt with a key",
			annotations: map[string]string{PushAnnotationEncrypt: "true", PushAnnotationKeyID: "k1"},
			want:        PushOptions{Encrypt: true, KeyID: "k1"},
		},
		{
			name:        "encrypt other than true is off",
			annotations: map[string]string{PushAnnotationEncrypt: "yes"},
			want:        PushOptions{},
		},
		{
			name:        "sign",
			annotations: map[string]string{PushAnnotationSign: "true"},
			want:        PushOptions{SignImage: true},
		},
		{
			name:        "overwrite",
			annotations: map[string]string{regsvc.AnnotationOverwrite: "true"},
			want:        PushOptions{AllowOverwrite: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pushOptionsOf(tt.annotations)
			if got.Encrypt != tt.want.Encrypt || got.KeyID != tt.want.KeyID ||
				got.AllowOverwrite != tt.want.AllowOverwrite || got.SignImage != tt.want.SignImage {
				t.Errorf("pushOptionsOf = encrypt %v key %q overwrite %v sign %v, want encrypt %v key %q overwrite %v sign %v",
					got.Encrypt, got.KeyID, got.AllowOverwrite, got.SignImage,
					tt.want.Encrypt, tt.want.KeyID, tt.want.AllowOverwrite, tt.want.SignImage)
			}
		})
	}
}

func TestGRPCAdapter_PushWithEncryptAnnotationEncryptsTheLayers(t *testing.T) {
	reg := newEncryptingTestRegistry(t)
	a := NewGRPCAdapter(reg)
	ctx := context.Background()
	layers := [][]byte{[]byte("layer-one"), []byte("layer-two")}

	meta := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{PushAnnotationEncrypt: "true", PushAnnotationKeyID: "web-key"},
	}
	resp, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, layers...)))
	if err != nil {
		t.Fatalf("PushStream: %v", err)
	}
	if got := resp.Artifact.Annotations[ManifestAnnotationEncrypted]; got != "true" {
		t.Errorf("encrypted annotation = %q, want true", got)
	}
	// The annotation records the KMS key the layers were wrapped with.
	if resp.Artifact.Annotations[ManifestAnnotationKeyID] == "" {
		t.Error("key-id annotation is empty on an encrypted push")
	}

	// The stored blob is ciphertext, and Pull decrypts it back.
	stored, err := reg.storage.GetBlob(ctx, resp.Artifact.Manifest.Layers[0].Digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if bytes.Contains(stored, layers[0]) {
		t.Error("stored layer blob holds the plaintext")
	}
	pulled, err := reg.Pull(ctx, "apps/web:v1", PullOptions{})
	if err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if !bytes.Equal(pulled.Layers[0].Content, layers[0]) {
		t.Errorf("pulled layer = %q, want %q", pulled.Layers[0].Content, layers[0])
	}
}

func TestGRPCAdapter_PushWithoutEncryptAnnotationStoresPlaintext(t *testing.T) {
	a := NewGRPCAdapter(newEncryptingTestRegistry(t))
	ctx := context.Background()

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	resp, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, []byte("layer-one"))))
	if err != nil {
		t.Fatalf("PushStream: %v", err)
	}
	if _, ok := resp.Artifact.Annotations[ManifestAnnotationEncrypted]; ok {
		t.Error("an unencrypted push carries the encrypted annotation")
	}
}

func TestGRPCAdapter_PushWithEncryptAnnotationNeedsAnEncryptor(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	meta := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{PushAnnotationEncrypt: "true"},
	}
	if _, err := a.PushStream(context.Background(), meta, bytes.NewReader(pushEnvelope(t, []byte("layer-one")))); err == nil {
		t.Fatal("encrypted push succeeded on a registry with no encryptor")
	}
}

func TestGRPCAdapter_PushWithSignAnnotationIsRefusedAndStoresNothing(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()
	meta := &grpcapi.RegistryPushMetadata{
		Repository:  "apps/web",
		Tag:         "v1",
		Annotations: map[string]string{PushAnnotationSign: "true"},
	}
	_, err := a.PushStream(ctx, meta, bytes.NewReader(pushEnvelope(t, []byte("layer-one"))))
	if !errors.As(err, &ErrSigningNotConfigured{}) {
		t.Fatalf("PushStream error = %v, want ErrSigningNotConfigured", err)
	}
	if _, err := a.Inspect(ctx, &grpcapi.RegistryInspectRequest{Repository: "apps/web", Reference: "v1"}); err == nil {
		t.Error("Inspect found an image whose signed push was refused")
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

func TestGRPCAdapter_StatusMeasuresUptimeFromTheAdapterStart(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	started := a.startedAt
	a.clock = func() time.Time { return started.Add(5 * time.Second) }

	first, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	second, err := a.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !second.StartedAt.Equal(first.StartedAt) || !second.StartedAt.Equal(started) {
		t.Fatalf("StartedAt moved between calls: %v then %v, want %v", first.StartedAt, second.StartedAt, started)
	}
	if uptime := second.Timestamp.Sub(second.StartedAt); uptime <= 0 {
		t.Fatalf("uptime = %v, want > 0", uptime)
	}
	if second.Health != grpcapi.RegistryHealthStatusHealthy {
		t.Fatalf("Health = %v, want healthy", second.Health)
	}
	if second.Version == "" {
		t.Fatal("Version is empty")
	}
	if len(second.Components) != 1 || second.Components[0].Name != StatusComponentStorage ||
		second.Components[0].Details[StatusDetailBackend] != StorageBackendQuicBaaS {
		t.Fatalf("Components = %+v, want the storage component naming the quicbaas backend", second.Components)
	}
}

func TestGRPCAdapter_StatusReportsUnconfiguredStorageAsUnhealthy(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })

	resp, err := NewGRPCAdapter(reg).Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if resp.Health != grpcapi.RegistryHealthStatusUnhealthy {
		t.Fatalf("Health = %v, want unhealthy", resp.Health)
	}
	if len(resp.Components) != 1 || resp.Components[0].Status != grpcapi.RegistryHealthStatusUnhealthy ||
		resp.Components[0].Message == "" {
		t.Fatalf("Components = %+v, want an unhealthy storage component with the cause", resp.Components)
	}
	if resp.Version == "" || resp.StartedAt.IsZero() {
		t.Fatalf("Version %q / StartedAt %v must be set on the unhealthy path too", resp.Version, resp.StartedAt)
	}
}
