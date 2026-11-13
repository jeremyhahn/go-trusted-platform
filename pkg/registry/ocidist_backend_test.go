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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// TestOCIDistBackend_BlobPutGet verifies the blob primitives the
// /v2/ router needs.
func TestOCIDistBackend_BlobPutGet(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	content := []byte("layer bytes")
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	if err := reg.PutBlob(ctx, digest, content); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	exists, err := reg.BlobExists(ctx, digest)
	if err != nil {
		t.Fatalf("BlobExists: %v", err)
	}
	if !exists {
		t.Fatal("expected blob to exist after PutBlob")
	}
	got, err := reg.GetBlob(ctx, digest)
	if err != nil {
		t.Fatalf("GetBlob: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("GetBlob = %q, want %q", got, content)
	}
}

// TestOCIDistBackend_ManifestRoundTrip verifies the manifest
// primitives + the dual-reference (tag + digest) storage so GET by
// digest works.
func TestOCIDistBackend_ManifestRoundTrip(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()

	manifest := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {
			"mediaType": "application/vnd.oci.image.config.v1+json",
			"digest": "sha256:` + repeat64("c") + `",
			"size": 4
		},
		"layers": []
	}`)
	digest, err := reg.PutManifest(ctx, "alpine", "3.20", "application/vnd.oci.image.manifest.v1+json", manifest)
	if err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	if digest == "" {
		t.Fatal("PutManifest returned empty digest")
	}

	// Tag lookup.
	mediaType, body, err := reg.GetManifest(ctx, "alpine", "3.20")
	if err != nil {
		t.Fatalf("GetManifest by tag: %v", err)
	}
	if mediaType == "" {
		t.Errorf("media type missing")
	}
	if len(body) == 0 {
		t.Errorf("manifest body empty")
	}

	// Digest lookup.
	_, _, err = reg.GetManifest(ctx, "alpine", digest)
	if err != nil {
		t.Fatalf("GetManifest by digest: %v", err)
	}
}

// TestOCIDistBackend_ListReposAndTags walks repositories and tags.
func TestOCIDistBackend_ListReposAndTags(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()
	m := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {"digest": "sha256:` + repeat64("c") + `", "size": 4},
		"layers": []
	}`)
	for _, ref := range []struct{ name, tag string }{
		{"alpine", "3.20"},
		{"alpine", "3.21"},
		{"distroless/static", "latest"},
	} {
		if _, err := reg.PutManifest(ctx, ref.name, ref.tag, "application/vnd.oci.image.manifest.v1+json", m); err != nil {
			t.Fatalf("PutManifest %s:%s: %v", ref.name, ref.tag, err)
		}
	}

	repos, err := reg.ListRepositories(ctx, 0)
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	wantRepos := map[string]bool{"alpine": true, "distroless/static": true}
	for _, r := range repos {
		delete(wantRepos, r)
	}
	if len(wantRepos) != 0 {
		t.Errorf("missing repos: %v (got %v)", wantRepos, repos)
	}

	tags, err := reg.ListTags(ctx, "alpine")
	if err != nil {
		t.Fatalf("ListTags: %v", err)
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 alpine tags, got %v", tags)
	}
}

// TestOCIDistBackend_ListTagsBeyondFirstPage puts more manifests than one
// storage page holds ahead of the target repository, so its tags only
// appear on a later page: ListTags must follow the storage cursor.
func TestOCIDistBackend_ListTagsBeyondFirstPage(t *testing.T) {
	reg := newTestRegistry(t)
	ctx := context.Background()
	m := []byte(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": {"digest": "sha256:` + repeat64("c") + `", "size": 4},
		"layers": []
	}`)
	const fillers = 520
	for i := 0; i < fillers; i++ {
		tag := fmt.Sprintf("t%04d", i)
		if _, err := reg.PutManifest(ctx, "aaa/filler", tag, "application/vnd.oci.image.manifest.v1+json", m); err != nil {
			t.Fatalf("PutManifest aaa/filler:%s: %v", tag, err)
		}
	}
	for _, tag := range []string{"3.20", "3.21"} {
		if _, err := reg.PutManifest(ctx, "alpine", tag, "application/vnd.oci.image.manifest.v1+json", m); err != nil {
			t.Fatalf("PutManifest alpine:%s: %v", tag, err)
		}
	}

	tags, err := reg.ListTags(ctx, "alpine")
	if err != nil {
		t.Fatalf("ListTags alpine: %v", err)
	}
	if len(tags) != 2 || tags[0] != "3.20" || tags[1] != "3.21" {
		t.Errorf("ListTags alpine = %v, want [3.20 3.21]", tags)
	}

	filler, err := reg.ListTags(ctx, "aaa/filler")
	if err != nil {
		t.Fatalf("ListTags aaa/filler: %v", err)
	}
	if len(filler) != fillers {
		t.Errorf("ListTags aaa/filler returned %d tags, want %d", len(filler), fillers)
	}
}
