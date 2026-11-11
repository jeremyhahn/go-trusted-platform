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
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
)

// ociTestManifest is a minimal OCI image manifest the /v2/ backend accepts.
func ociTestManifest() []byte {
	return []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest": "sha256:` + repeat64("c") + `",
			"size": 4
		},
		"layers": []
	}`)
}

func TestGRPCAdapter964_PushPullStreamListDeleteLifecycle(t *testing.T) {
	reg := newTestRegistry(t)
	a := NewGRPCAdapter(reg)
	ctx := context.Background()

	meta := &grpcapi.RegistryPushMetadata{Repository: "apps/web", Tag: "v1"}
	if _, err := a.Push(ctx, &grpcapi.RegistryPushRequest{Metadata: meta, Data: pushEnvelope(t, []byte("layer"))}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	stream, err := a.PullStream(ctx, &grpcapi.RegistryPullRequest{Repository: "apps/web", Reference: "v1"})
	if err != nil {
		t.Fatalf("PullStream: %v", err)
	}
	data, err := io.ReadAll(stream.Reader)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}
	if int64(len(data)) != stream.TotalSize {
		t.Errorf("stream carried %d bytes, TotalSize = %d", len(data), stream.TotalSize)
	}
	var pulled Image
	if err := json.Unmarshal(data, &pulled); err != nil {
		t.Fatalf("decode stream: %v", err)
	}
	if len(pulled.Layers) != 1 || !bytes.Equal(pulled.Layers[0].Content, []byte("layer")) {
		t.Errorf("streamed layers = %+v, want the one pushed layer", pulled.Layers)
	}

	// The OCI /v2/ path stores a digest-keyed copy beside the tag; List
	// must show the image once.
	if _, err := reg.PutManifest(ctx, "alpine", "3.20", "application/vnd.oci.image.manifest.v1+json", ociTestManifest()); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	list, err := a.List(ctx, &grpcapi.RegistryListRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	rows := map[string]int{}
	for _, art := range list.Artifacts {
		rows[art.Repository+":"+art.Tag]++
		if isHex64(art.Tag) {
			t.Errorf("List shows the digest-keyed copy %s:%s", art.Repository, art.Tag)
		}
	}
	if rows["apps/web:v1"] != 1 || rows["alpine:3.20"] != 1 {
		t.Errorf("List rows = %v, want apps/web:v1 and alpine:3.20 once each", rows)
	}
	if int(list.Total) != len(list.Artifacts) {
		t.Errorf("Total = %d, want %d", list.Total, len(list.Artifacts))
	}

	del, err := a.Delete(ctx, &grpcapi.RegistryDeleteRequest{Repository: "apps/web", Reference: "v1"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if del.Timestamp.IsZero() {
		t.Error("Delete returned a zero timestamp")
	}
	_, err = a.Pull(ctx, &grpcapi.RegistryPullRequest{Repository: "apps/web", Reference: "v1"})
	var notFound grpcapi.ErrArtifactNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Pull after Delete error = %v, want ErrArtifactNotFound", err)
	}
}

func TestGRPCAdapter964_DeleteOfAnAbsentImageIsNotFound(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	_, err := a.Delete(context.Background(), &grpcapi.RegistryDeleteRequest{Repository: "apps/none", Reference: "v1"})
	var notFound grpcapi.ErrArtifactNotFound
	if !errors.As(err, &notFound) {
		t.Fatalf("Delete error = %v, want ErrArtifactNotFound", err)
	}
	if notFound.Repository != "apps/none" || notFound.Reference != "v1" {
		t.Errorf("ErrArtifactNotFound = %+v, want apps/none v1", notFound)
	}
}

func TestGRPCAdapter964_RequestsWithoutAReferenceAreRefused(t *testing.T) {
	a := NewGRPCAdapter(newTestRegistry(t))
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"Push nil request", func() error { _, err := a.Push(ctx, nil); return err }, grpcapi.ErrMissingPushMetadata{}},
		{"Push without metadata", func() error {
			_, err := a.Push(ctx, &grpcapi.RegistryPushRequest{Data: []byte("{}")})
			return err
		}, grpcapi.ErrMissingPushMetadata{}},
		{"PullStream nil request", func() error { _, err := a.PullStream(ctx, nil); return err }, grpcapi.ErrMissingReference{}},
		{"Delete nil request", func() error { _, err := a.Delete(ctx, nil); return err }, grpcapi.ErrMissingReference{}},
		{"Delete empty reference", func() error {
			_, err := a.Delete(ctx, &grpcapi.RegistryDeleteRequest{})
			return err
		}, grpcapi.ErrMissingReference{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %T", err, tt.want)
			}
		})
	}
}

func TestGRPCAdapter964_ListOfAClosedRegistryFails(t *testing.T) {
	reg := newTestRegistry(t)
	a := NewGRPCAdapter(reg)
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := a.List(context.Background(), nil); !errors.As(err, &ErrRegistryClosed{}) {
		t.Fatalf("List error = %v, want ErrRegistryClosed", err)
	}
}

func TestReferenceHelpers964(t *testing.T) {
	splits := []struct {
		ref, repo, tag string
		oci            bool
	}{
		{"apps/web:v1", "apps/web", "v1", false},
		{"apps/web", "apps/web", "", false},
		{"alpine:sha256:" + repeat64("a"), "alpine:sha256", repeat64("a"), false},
		{"host:5000/apps/web", "host:5000/apps/web", "", true},
	}
	for _, s := range splits {
		repo, tag := splitOCIRef(s.ref)
		if repo != s.repo || tag != s.tag {
			t.Errorf("splitOCIRef(%q) = (%q, %q), want (%q, %q)", s.ref, repo, tag, s.repo, s.tag)
		}
		if s.oci {
			continue
		}
		repo, tag = splitRef(s.ref)
		if repo != s.repo || tag != s.tag {
			t.Errorf("splitRef(%q) = (%q, %q), want (%q, %q)", s.ref, repo, tag, s.repo, s.tag)
		}
	}

	sentinels := map[string]bool{"alpine:sha256": true, "sha256": false, "": false, "alpine:sha512": false}
	for in, want := range sentinels {
		if got := endsWithSha256Sentinel(in); got != want {
			t.Errorf("endsWithSha256Sentinel(%q) = %v, want %v", in, got, want)
		}
	}

	refs := []struct{ repo, tag, digest, want string }{
		{"apps/web", "v1", "", "apps/web:v1"},
		{"apps/web", "v1", "sha256:abc", "sha256:abc"},
		{"", "apps/web:v1", "", "apps/web:v1"},
		{"apps/web", "", "", "apps/web"},
	}
	for _, r := range refs {
		if got := refOf(r.repo, r.tag, r.digest); got != r.want {
			t.Errorf("refOf(%q, %q, %q) = %q, want %q", r.repo, r.tag, r.digest, got, r.want)
		}
	}

	if got := refJoin("alpine", ""); got != "alpine" {
		t.Errorf("refJoin without reference = %q, want alpine", got)
	}
	if got := refJoin("alpine", "3.20"); got != "alpine:3.20" {
		t.Errorf("refJoin = %q, want alpine:3.20", got)
	}
}

func TestOCIDistBackend964_RefusesWithoutStorage(t *testing.T) {
	reg, err := NewRegistry(validTestConfig(), testLogger())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	ctx := context.Background()
	digest := "sha256:" + repeat64("b")

	calls := map[string]func() error{
		"PutBlob":    func() error { return reg.PutBlob(ctx, digest, []byte("x")) },
		"GetBlob":    func() error { _, err := reg.GetBlob(ctx, digest); return err },
		"BlobExists": func() error { _, err := reg.BlobExists(ctx, digest); return err },
		"PutManifest": func() error {
			_, err := reg.PutManifest(ctx, "alpine", "3.20", "", ociTestManifest())
			return err
		},
		"GetManifest":      func() error { _, _, err := reg.GetManifest(ctx, "alpine", "3.20"); return err },
		"DeleteManifest":   func() error { return reg.DeleteManifest(ctx, "alpine", "3.20") },
		"ListRepositories": func() error { _, err := reg.ListRepositories(ctx, 10); return err },
		"ListTags":         func() error { _, err := reg.ListTags(ctx, "alpine"); return err },
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			var notConfigured ErrStorageNotConfigured
			if err := call(); !errors.As(err, &notConfigured) {
				t.Fatalf("error = %v, want ErrStorageNotConfigured", err)
			}
			if notConfigured.Op != op {
				t.Errorf("Op = %q, want %q", notConfigured.Op, op)
			}
		})
	}
}

func TestOCIDistBackend964_RefusesWhenClosed(t *testing.T) {
	reg := newTestRegistry(t)
	if err := reg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()
	digest := "sha256:" + repeat64("b")

	calls := map[string]func() error{
		"PutBlob":    func() error { return reg.PutBlob(ctx, digest, []byte("x")) },
		"GetBlob":    func() error { _, err := reg.GetBlob(ctx, digest); return err },
		"BlobExists": func() error { _, err := reg.BlobExists(ctx, digest); return err },
		"PutManifest": func() error {
			_, err := reg.PutManifest(ctx, "alpine", "3.20", "", ociTestManifest())
			return err
		},
		"GetManifest":    func() error { _, _, err := reg.GetManifest(ctx, "alpine", "3.20"); return err },
		"DeleteManifest": func() error { return reg.DeleteManifest(ctx, "alpine", "3.20") },
	}
	for op, call := range calls {
		t.Run(op, func(t *testing.T) {
			if err := call(); !errors.As(err, &ErrRegistryClosed{}) {
				t.Fatalf("error = %v, want ErrRegistryClosed", err)
			}
		})
	}
}

func TestOCIDistBackend964_DeleteManifestRemovesTheTag(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()
	if _, err := reg.PutManifest(ctx, "alpine", "3.20", "application/vnd.oci.image.manifest.v1+json", ociTestManifest()); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if err := reg.DeleteManifest(ctx, "alpine", "3.20"); err != nil {
		t.Fatalf("DeleteManifest: %v", err)
	}
	if _, _, err := reg.GetManifest(ctx, "alpine", "3.20"); !errors.As(err, &ErrManifestNotFound{}) {
		t.Fatalf("GetManifest after delete error = %v, want ErrManifestNotFound", err)
	}
}

func TestOCIDistBackend964_PutManifestRefusesABadBody(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	_, err := reg.PutManifest(ctx, "alpine", "3.20", "", nil)
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("empty body error = %v, want *MessageError", err)
	}

	_, err = reg.PutManifest(ctx, "alpine", "3.20", "", []byte("{not json"))
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("bad JSON error = %v, want *WrappedError", err)
	}
	if !strings.HasPrefix(wrapped.Error(), "registry: decode manifest: ") {
		t.Errorf("WrappedError message = %q", wrapped.Error())
	}
	if errors.Unwrap(wrapped) == nil {
		t.Error("WrappedError does not unwrap to its cause")
	}
}

func TestDecodeOCIManifest964_FillsTheMediaTypeFromTheRequest(t *testing.T) {
	const want = "application/vnd.docker.distribution.manifest.v2+json"
	m, err := decodeOCIManifest([]byte(`{"schemaVersion":2}`), want)
	if err != nil {
		t.Fatalf("decodeOCIManifest: %v", err)
	}
	if m.MediaType != want {
		t.Errorf("MediaType = %q, want %q", m.MediaType, want)
	}
}

func TestErrorMessages964(t *testing.T) {
	cause := errors.New("boom")
	tests := []struct {
		err  error
		want []string
	}{
		{ErrImageAlreadyExists{Reference: "apps/web:v1"}, []string{"already exists", "apps/web:v1"}},
		{ErrManifestSigningFailed{KeyID: "k1", Err: cause}, []string{"k1", "boom"}},
		{ErrSigningClientRequired{}, []string{"KMS and crypto clients"}},
		{ErrInvalidSigningRequest{Reason: "empty key ID"}, []string{"invalid signing request", "empty key ID"}},
		{ErrSigningKeyUnavailable{KeyID: "k2"}, []string{"k2", "not found"}},
		{ErrSigningKeyUnavailable{KeyID: "k3", Err: cause}, []string{"k3", "not available", "boom"}},
		{ErrSigningKeyUnsupported{KeyID: "k4", Reason: "RSA"}, []string{"k4", "RSA"}},
		{ErrKeyNotFoundLocal{KeyID: "k5"}, []string{"k5", "not found"}},
	}
	for _, tt := range tests {
		msg := tt.err.Error()
		for _, part := range tt.want {
			if !strings.Contains(msg, part) {
				t.Errorf("%T message %q does not contain %q", tt.err, msg, part)
			}
		}
	}
	if !errors.Is(ErrManifestSigningFailed{KeyID: "k1", Err: cause}, cause) {
		t.Error("ErrManifestSigningFailed does not unwrap to its cause")
	}
	if !errors.Is(ErrSigningKeyUnavailable{KeyID: "k3", Err: cause}, cause) {
		t.Error("ErrSigningKeyUnavailable does not unwrap to its cause")
	}
}

func TestLocalKMS964_GetKey(t *testing.T) {
	t.Run("generated key returns its recorded metadata", func(t *testing.T) {
		kms, keyID := newTestKMS(t)
		info, err := kms.GetKey(context.Background(), keyID)
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		if info.KeyID != keyID || info.Name != "test-key" || info.Algorithm != "AES-256-GCM" {
			t.Errorf("GetKey = %+v, want the generated key's metadata", info)
		}
	})
	t.Run("key without a metadata sidecar gets the defaults", func(t *testing.T) {
		kms, keyID := plantKey(t, bytes.Repeat([]byte{7}, 32))
		info, err := kms.GetKey(context.Background(), keyID)
		if err != nil {
			t.Fatalf("GetKey: %v", err)
		}
		if info.KeyID != keyID || info.Algorithm != "AES-256-GCM" || info.Version != 1 || len(info.Usage) != 4 {
			t.Errorf("GetKey = %+v, want the default AES-256-GCM metadata", info)
		}
	})
	t.Run("unknown key is ErrKeyNotFoundLocal", func(t *testing.T) {
		kms, _ := newTestKMS(t)
		var notFound ErrKeyNotFoundLocal
		if _, err := kms.GetKey(context.Background(), "local-missing"); !errors.As(err, &notFound) {
			t.Fatalf("GetKey error = %v, want ErrKeyNotFoundLocal", err)
		}
		if notFound.KeyID != "local-missing" {
			t.Errorf("KeyID = %q, want local-missing", notFound.KeyID)
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		kms, keyID := newTestKMS(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := kms.GetKey(ctx, keyID); !errors.Is(err, context.Canceled) {
			t.Fatalf("GetKey error = %v, want context.Canceled", err)
		}
	})
}

// storedSession marshals session into client the way SessionManager.Store
// would, bypassing the cache so Get must read storage.
func storedSession(t *testing.T, client *mockQuicBaaSClient, session *RegistrySession) {
	t.Helper()
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	client.data[sessionEntityType+":"+session.SessionID] = data
}

func TestSessionManager964_GetReadsStorage(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("valid stored session is returned and cached", func(t *testing.T) {
		client := newMockQuicBaaSClient()
		m := NewSessionManager(client, time.Hour)
		storedSession(t, client, &RegistrySession{SessionID: "s1", ClientID: "c1", ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)})
		got, err := m.Get(ctx, "s1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ClientID != "c1" {
			t.Errorf("ClientID = %q, want c1", got.ClientID)
		}
		if _, ok := m.cache.Load("s1"); !ok {
			t.Error("session read from storage was not cached")
		}
	})
	t.Run("expired stored session is deleted", func(t *testing.T) {
		client := newMockQuicBaaSClient()
		m := NewSessionManager(client, time.Hour)
		storedSession(t, client, &RegistrySession{SessionID: "s2", ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(-time.Hour)})
		if _, err := m.Get(ctx, "s2"); !errors.As(err, &ErrSessionExpired{}) {
			t.Fatalf("Get error = %v, want ErrSessionExpired", err)
		}
		if _, ok := client.data[sessionEntityType+":s2"]; ok {
			t.Error("expired session was left in storage")
		}
	})
	t.Run("expired cached session falls through to storage", func(t *testing.T) {
		client := newMockQuicBaaSClient()
		m := NewSessionManager(client, time.Hour)
		m.cache.Store("s3", &RegistrySession{SessionID: "s3", ValidFrom: now.Add(-2 * time.Hour), ValidUntil: now.Add(-time.Hour)})
		if _, err := m.Get(ctx, "s3"); !errors.As(err, &ErrSessionNotFound{}) {
			t.Fatalf("Get error = %v, want ErrSessionNotFound", err)
		}
		if _, ok := m.cache.Load("s3"); ok {
			t.Error("expired session was left in the cache")
		}
	})
	t.Run("corrupt stored session is a storage error", func(t *testing.T) {
		client := newMockQuicBaaSClient()
		m := NewSessionManager(client, time.Hour)
		client.data[sessionEntityType+":s4"] = []byte("{not json")
		var storageErr ErrStorageError
		if _, err := m.Get(ctx, "s4"); !errors.As(err, &storageErr) || storageErr.Operation != "unmarshal_session" {
			t.Fatalf("Get error = %v, want ErrStorageError unmarshal_session", err)
		}
	})
	t.Run("storage failure is a storage error", func(t *testing.T) {
		client := newMockQuicBaaSClient()
		client.getErr = errors.New("unreachable")
		m := NewSessionManager(client, time.Hour)
		var storageErr ErrStorageError
		if _, err := m.Get(ctx, "s5"); !errors.As(err, &storageErr) || storageErr.Operation != "get_session" {
			t.Fatalf("Get error = %v, want ErrStorageError get_session", err)
		}
	})
}

func TestSessionManager964_InputValidation(t *testing.T) {
	m := NewSessionManager(newMockQuicBaaSClient(), time.Hour)
	var nilCtx context.Context
	ctx := context.Background()
	tests := []struct {
		name string
		call func() error
		want error
	}{
		{"Get nil context", func() error { _, err := m.Get(nilCtx, "s"); return err }, ErrNilContext{Operation: "SessionManager.Get"}},
		{"Get empty ID", func() error { _, err := m.Get(ctx, ""); return err }, ErrInvalidSession{Reason: "session ID is empty"}},
		{"Delete nil context", func() error { return m.Delete(nilCtx, "s") }, ErrNilContext{Operation: "SessionManager.Delete"}},
		{"Delete empty ID", func() error { return m.Delete(ctx, "") }, ErrInvalidSession{Reason: "session ID is empty"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestSessionManager964_InvalidateRemovesTheSession(t *testing.T) {
	ctx := context.Background()
	client := newMockQuicBaaSClient()
	m := NewSessionManager(client, time.Hour)
	session := &RegistrySession{SessionID: "s1", ClientID: "c1", ValidFrom: time.Now().Add(-time.Minute), ValidUntil: time.Now().Add(time.Hour)}
	if err := m.Store(ctx, session); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := m.Invalidate(ctx, "s1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if _, err := m.Get(ctx, "s1"); !errors.As(err, &ErrSessionNotFound{}) {
		t.Fatalf("Get after Invalidate error = %v, want ErrSessionNotFound", err)
	}

	client.delErr = errors.New("unreachable")
	var storageErr ErrStorageError
	if err := m.Invalidate(ctx, "s1"); !errors.As(err, &storageErr) || storageErr.Operation != "delete_session" {
		t.Fatalf("Invalidate error = %v, want ErrStorageError delete_session", err)
	}
}
