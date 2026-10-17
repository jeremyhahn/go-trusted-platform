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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestWithOverwrite_MarksFreshMetadata pins the wire contract the registry
// server reads: the overwrite annotation set to "true".
func TestWithOverwrite_MarksFreshMetadata(t *testing.T) {
	metadata := WithOverwrite(NewPushMetadata("apps/web", "v1", 42))

	if got := metadata.GetAnnotations()[AnnotationOverwrite]; got != "true" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationOverwrite, got, "true")
	}
	if metadata.GetRepository() != "apps/web" || metadata.GetTag() != "v1" || metadata.GetTotalSize() != 42 {
		t.Fatalf("metadata fields changed: %+v", metadata)
	}
}

// TestWithOverwrite_KeepsExistingAnnotations guards against the helper
// replacing the caller's annotation map.
func TestWithOverwrite_KeepsExistingAnnotations(t *testing.T) {
	metadata := &platformv1.PushMetadata{
		Repository:  "apps/web",
		Annotations: map[string]string{"org.opencontainers.image.source": "git"},
	}

	WithOverwrite(metadata)

	if got := metadata.GetAnnotations()["org.opencontainers.image.source"]; got != "git" {
		t.Fatalf("existing annotation = %q, want %q", got, "git")
	}
	if got := metadata.GetAnnotations()[AnnotationOverwrite]; got != "true" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationOverwrite, got, "true")
	}
}

// TestWithEncryption_CarriesKeyID covers the --encrypt --key-id push: both
// travel as annotations next to the overwrite one.
func TestWithEncryption_CarriesKeyID(t *testing.T) {
	metadata := WithOverwrite(WithEncryption(NewPushMetadata("apps/web", "v1", 42), "apps-web-dek"))

	annotations := metadata.GetAnnotations()
	if annotations[AnnotationEncrypt] != "true" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationEncrypt, annotations[AnnotationEncrypt], "true")
	}
	if annotations[AnnotationKeyID] != "apps-web-dek" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationKeyID, annotations[AnnotationKeyID], "apps-web-dek")
	}
	if annotations[AnnotationOverwrite] != "true" {
		t.Fatalf("annotation %q lost: %v", AnnotationOverwrite, annotations)
	}
}

// TestWithEncryption_EmptyKeyIDSetsNoKeyAnnotation guards against an empty
// key-id annotation that a server would read as a key named "".
func TestWithEncryption_EmptyKeyIDSetsNoKeyAnnotation(t *testing.T) {
	metadata := WithEncryption(NewPushMetadata("apps/web", "v1", 0), "")

	if _, ok := metadata.GetAnnotations()[AnnotationKeyID]; ok {
		t.Fatalf("annotation %q set for an empty key ID: %v", AnnotationKeyID, metadata.GetAnnotations())
	}
}

// TestWithSigning_CarriesSigningKeyID covers the --sign --signing-key-id push.
func TestWithSigning_CarriesSigningKeyID(t *testing.T) {
	metadata := WithSigning(NewPushMetadata("apps/web", "v1", 42), "apps-web-signer")

	annotations := metadata.GetAnnotations()
	if annotations[AnnotationSign] != "true" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationSign, annotations[AnnotationSign], "true")
	}
	if annotations[AnnotationSigningKeyID] != "apps-web-signer" {
		t.Fatalf("annotation %q = %q, want %q", AnnotationSigningKeyID, annotations[AnnotationSigningKeyID], "apps-web-signer")
	}
}

// TestWithSigning_EmptyKeyIDLeavesKeyToRegistry covers --sign without
// --signing-key-id: the registry chooses the key.
func TestWithSigning_EmptyKeyIDLeavesKeyToRegistry(t *testing.T) {
	metadata := WithSigning(NewPushMetadata("apps/web", "v1", 0), "")

	if _, ok := metadata.GetAnnotations()[AnnotationSigningKeyID]; ok {
		t.Fatalf("annotation %q set for an empty key ID: %v", AnnotationSigningKeyID, metadata.GetAnnotations())
	}
}
