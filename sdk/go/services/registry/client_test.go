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
