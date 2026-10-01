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

//go:build fips

package noise

import (
	"errors"
	"strings"
	"testing"
)

// TestNewServer_FIPSRefusesCurve25519 pins today's FIPS behaviour: the
// listener's only suite is Curve25519, which a fips build cannot generate,
// so construction fails with a typed key-generation error rather than
// serving an unapproved suite. Whether the FIPS build should offer the
// approved P-256 suite instead is the owner ruling tracked in #518.
func TestNewServer_FIPSRefusesCurve25519(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err == nil {
		t.Fatal("NewServer succeeded in a fips build; it must refuse the Curve25519 key")
	}
	if srv != nil {
		t.Error("NewServer returned a server alongside its error")
	}
	var keyErr *ErrKeyGenerationFailed
	if !errors.As(err, &keyErr) {
		t.Fatalf("error = %T %v, want *ErrKeyGenerationFailed", err, err)
	}
	if !strings.Contains(err.Error(), "FIPS") {
		t.Errorf("error %q does not name the FIPS restriction", err)
	}
}

// TestNewServer_FIPSValidatesBeforeKeyGeneration: a nil config is reported
// as such in a fips build too, not masked by the key-generation refusal.
func TestNewServer_FIPSValidatesBeforeKeyGeneration(t *testing.T) {
	if _, err := NewServer(nil, testBundlerWithData(), testLogger()); err == nil {
		t.Fatal("NewServer(nil config) succeeded")
	} else if errors.As(err, new(*ErrKeyGenerationFailed)) {
		t.Errorf("nil config reported as a key-generation failure: %v", err)
	}
}
