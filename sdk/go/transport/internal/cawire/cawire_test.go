// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package cawire

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestStatus_MapsTheDaemonStrings(t *testing.T) {
	cases := map[string]platformv1.CertificateStatus{
		"VALID":         platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
		"NOT_YET_VALID": platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING,
		"EXPIRED":       platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
		"REVOKED":       platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
	}
	for in, want := range cases {
		if got := Status(in); got != want {
			t.Errorf("Status(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestStatus_UnknownIsUnspecified(t *testing.T) {
	for _, in := range []string{"", "valid", "SUSPENDED"} {
		if got := Status(in); got != platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED {
			t.Errorf("Status(%q) = %v, want UNSPECIFIED", in, got)
		}
	}
}

func TestKeyAlgorithm_MapsTheDaemonStrings(t *testing.T) {
	cases := map[string]platformv1.KeyAlgorithm{
		// The exact names a QUIC or MCP response carries (Codex 8200).
		"RSA-2048":   platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		"RSA-3072":   platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		"RSA-4096":   platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
		"ECDSA-P256": platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		"ECDSA-P384": platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		"ECDSA-P521": platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521,
		"ED25519":    platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519,
		// The bare family names an older daemon reported.
		"RSA":   platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		"ECDSA": platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
	}
	for in, want := range cases {
		if got := KeyAlgorithm(in); got != want {
			t.Errorf("KeyAlgorithm(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestKeyAlgorithm_UnknownIsUnspecified(t *testing.T) {
	for _, in := range []string{"", "UNKNOWN", "rsa", "rsa-4096", "RSA4096", "P384"} {
		if got := KeyAlgorithm(in); got != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
			t.Errorf("KeyAlgorithm(%q) = %v, want UNSPECIFIED", in, got)
		}
	}
}

func TestKeyAlgorithmName_NamesEachAlgorithmTheGRPCServiceAccepts(t *testing.T) {
	cases := map[platformv1.KeyAlgorithm]string{
		platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: "",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    "RSA-2048",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    "RSA-3072",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    "RSA-4096",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  "ECDSA-P256",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  "ECDSA-P384",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:  "ECDSA-P521",
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     "ED25519",
	}
	for in, want := range cases {
		got, err := KeyAlgorithmName(in)
		if err != nil || got != want {
			t.Errorf("KeyAlgorithmName(%v) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestKeyAlgorithmName_RefusesAnUnknownAlgorithm(t *testing.T) {
	_, err := KeyAlgorithmName(platformv1.KeyAlgorithm(99))
	var unknown ErrUnknownKeyAlgorithm
	if !errors.As(err, &unknown) || unknown.Algorithm != 99 {
		t.Fatalf("KeyAlgorithmName(99) error = %v, want ErrUnknownKeyAlgorithm{99}", err)
	}
}

// TestKeyAlgorithm_DecodesEveryNameItWrites pins that each name
// KeyAlgorithmName writes decodes back to the algorithm it named.
func TestKeyAlgorithm_DecodesEveryNameItWrites(t *testing.T) {
	for alg, name := range keyAlgorithmNames {
		if alg == platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
			continue
		}
		if got := KeyAlgorithm(name); got != alg {
			t.Errorf("KeyAlgorithm(%q) = %v, want %v", name, got, alg)
		}
	}
}

func TestTime_IsUnixSeconds(t *testing.T) {
	if got := Time(1791770595); got.GetSeconds() != 1791770595 || got.GetNanos() != 0 {
		t.Fatalf("Time = %v, want 1791770595s", got)
	}
	if got := Time(0); got.GetSeconds() != 0 {
		t.Fatalf("Time(0) = %v, want the epoch", got)
	}
}
