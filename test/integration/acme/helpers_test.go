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

//go:build integration

package acme

import "testing"

// The runner chooses platformd's REST port at run time (#997), so the ACME
// directory must follow the REST endpoint it exports, not a fixed port.
func TestACMEDirectoryURLFollowsRunnerRESTEndpoint(t *testing.T) {
	t.Setenv(EnvACMEDirectoryURL, "")
	t.Setenv(EnvPlatformAPIEndpoint, "https://localhost:40123")

	want := "https://localhost:40123/api/v1/acme/directory"
	if got := GetServiceEndpoints().ACMEDirectory; got != want {
		t.Fatalf("ACMEDirectory = %q, want %q", got, want)
	}
}

func TestACMEDirectoryURLPrefersExplicitURL(t *testing.T) {
	t.Setenv(EnvACMEDirectoryURL, "https://acme.example.test/directory")
	t.Setenv(EnvPlatformAPIEndpoint, "https://localhost:40123")

	want := "https://acme.example.test/directory"
	if got := GetServiceEndpoints().ACMEDirectory; got != want {
		t.Fatalf("ACMEDirectory = %q, want %q", got, want)
	}
}

func TestACMEDirectoryURLDefaultsWithoutRunner(t *testing.T) {
	t.Setenv(EnvACMEDirectoryURL, "")
	t.Setenv(EnvPlatformAPIEndpoint, "")

	if got := GetServiceEndpoints().ACMEDirectory; got != DefaultACMEDirectoryURL {
		t.Fatalf("ACMEDirectory = %q, want %q", got, DefaultACMEDirectoryURL)
	}
}
