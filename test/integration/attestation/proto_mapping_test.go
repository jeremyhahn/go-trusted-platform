//go:build integration

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

package attestation

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestProtoMapping_ResponsesWithoutTheirMessageAreErrors covers the empty
// responses a daemon answers with when it has nothing to return: each mapping
// names the missing message instead of building a zero result.
func TestProtoMapping_ResponsesWithoutTheirMessageAreErrors(t *testing.T) {
	tests := []struct {
		name  string
		field string
		call  func() error
	}{
		{"vmQuoteResult", "attestation", func() error {
			_, err := vmQuoteResult(&platformv1.CollectVMAttestationResponse{})
			return err
		}},
		{"vmAttestationResult", "attestation", func() error {
			_, err := vmAttestationResult(&platformv1.CollectVMAttestationResponse{})
			return err
		}},
		{"buildManifestResult", "manifest", func() error {
			_, err := buildManifestResult(&platformv1.BuildManifestResponse{})
			return err
		}},
		{"storedManifest", "manifest", func() error {
			_, err := storedManifest(&platformv1.GetManifestResponse{})
			return err
		}},
		{"getManifestResult", "manifest", func() error {
			_, err := getManifestResult(&platformv1.GetManifestResponse{})
			return err
		}},
		{"verifyManifestResult", "verification result", func() error {
			_, err := verifyManifestResult(VerifyManifestOptions{}, &platformv1.HostManifest{}, &platformv1.VerifyManifestResponse{})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var missing ErrMissingResponseField
			if err := tt.call(); !errors.As(err, &missing) || missing.Field != tt.field {
				t.Errorf("err = %v, want ErrMissingResponseField{%q}", err, tt.field)
			}
		})
	}
}

func TestProtoMapping_VerifyManifestResultComparesTheHostID(t *testing.T) {
	resp := &platformv1.VerifyManifestResponse{Result: &platformv1.ManifestVerificationResult{
		Status: platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED,
	}}
	manifest := &platformv1.HostManifest{HostId: "host-1"}

	matched, err := verifyManifestResult(VerifyManifestOptions{ExpectedHostID: "host-1"}, manifest, resp)
	if err != nil || !matched.HostIDMatch || !matched.Valid {
		t.Errorf("matching host = %+v, %v; want a valid match", matched, err)
	}
	other, err := verifyManifestResult(VerifyManifestOptions{ExpectedHostID: "host-2"}, manifest, resp)
	if err != nil || other.HostIDMatch {
		t.Errorf("other host = %+v, %v; want HostIDMatch false", other, err)
	}
}

func TestProtoMapping_TimeFromProto(t *testing.T) {
	want := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	if got := timeFromProto(timestamppb.New(want)); !got.Equal(want) {
		t.Errorf("timeFromProto = %v, want %v", got, want)
	}
	if got := timeFromProto(nil); !got.IsZero() {
		t.Errorf("timeFromProto(nil) = %v, want the zero time, not the Unix epoch", got)
	}
}

func TestProtoMapping_HashAlgorithmNames(t *testing.T) {
	for _, name := range []string{"sha1", "sha256", "sha384", "sha512"} {
		if got := hashAlgorithmToString(hashAlgorithmFromString(name)); got != name {
			t.Errorf("round trip of %q = %q", name, got)
		}
	}
	if got := hashAlgorithmFromString("SHA256"); got != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256 {
		t.Errorf("hashAlgorithmFromString(SHA256) = %v, want SHA256", got)
	}
	if got := hashAlgorithmFromString("md5"); got != platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED {
		t.Errorf("hashAlgorithmFromString(md5) = %v, want UNSPECIFIED", got)
	}
	if got := hashAlgorithmToString(platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED); got != "" {
		t.Errorf("hashAlgorithmToString(UNSPECIFIED) = %q, want empty", got)
	}
}
