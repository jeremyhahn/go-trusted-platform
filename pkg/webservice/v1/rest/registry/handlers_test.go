// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed under:
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package registry

import (
	"net/http"
	"testing"

	regsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/registry"
)

// TestPushAnnotationsOf_CarriesEveryPushHeader pins the REST push headers to
// the annotations the gRPC push carries: the encrypt header used to land under
// a key the registry never read, and key IDs and signing had no header.
func TestPushAnnotationsOf_CarriesEveryPushHeader(t *testing.T) {
	header := http.Header{}
	header.Set("X-Trusted-Platform-Encrypt", "true")
	header.Set("X-Trusted-Platform-Key-Id", "apps-api-dek")
	header.Set("X-Trusted-Platform-Sign", "true")
	header.Set("X-Trusted-Platform-Signing-Key-Id", "apps-api-signer")
	header.Set("X-Trusted-Platform-Overwrite", "true")

	want := map[string]string{
		regsvc.AnnotationEncrypt:      "true",
		regsvc.AnnotationKeyID:        "apps-api-dek",
		regsvc.AnnotationSign:         "true",
		regsvc.AnnotationSigningKeyID: "apps-api-signer",
		regsvc.AnnotationOverwrite:    "true",
	}
	got := pushAnnotationsOf(header)
	if len(got) != len(want) {
		t.Fatalf("annotations = %v, want %v", got, want)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("annotation %q = %q, want %q", key, got[key], value)
		}
	}
}

// TestPushAnnotationsOf_IgnoresUnrelatedHeaders guards a plain push: no push
// header means no annotation, whatever else the request carries.
func TestPushAnnotationsOf_IgnoresUnrelatedHeaders(t *testing.T) {
	header := http.Header{}
	header.Set("X-Trusted-Platform-Repository", "apps/api")
	header.Set("Content-Type", "application/x-trusted-platform-image")

	if got := pushAnnotationsOf(header); len(got) != 0 {
		t.Fatalf("annotations = %v, want none", got)
	}
}
