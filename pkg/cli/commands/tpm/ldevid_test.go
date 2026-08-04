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

package tpm

import (
	"os"
	"path/filepath"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestBuildCreateLDevIDRequest(t *testing.T) {
	t.Run("full request maps every flag", func(t *testing.T) {
		req, err := buildCreateLDevIDRequest(&ldevidCreateFlags{
			commonName:         "ldevid.example",
			organization:       "ATT",
			organizationalUnit: "Devices",
			country:            "US",
			state:              "FL",
			locality:           "Miami",
			algorithm:          "ECDSA-P384",
			handle:             "0x81010102",
			profile:            "tls-client",
			validityDays:       90,
			overwrite:          true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.GetAlgorithm() != platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384 {
			t.Errorf("algorithm = %v", req.GetAlgorithm())
		}
		if req.GetHandle() != 0x81010102 {
			t.Errorf("handle = 0x%08X", req.GetHandle())
		}
		if req.GetProfile() != "tls-client" || req.GetValidityDays() != 90 || !req.GetOverwrite() {
			t.Errorf("scalar mismatch: %+v", req)
		}
		tmpl := req.GetTemplate()
		if tmpl == nil || tmpl.GetCommonName() != "ldevid.example" || tmpl.GetOrganization() != "ATT" ||
			tmpl.GetOrganizationalUnit() != "Devices" || tmpl.GetCountry() != "US" ||
			tmpl.GetProvince() != "FL" || tmpl.GetLocality() != "Miami" {
			t.Errorf("template mismatch: %+v", tmpl)
		}
	})

	t.Run("no subject fields yields nil template", func(t *testing.T) {
		req, err := buildCreateLDevIDRequest(&ldevidCreateFlags{algorithm: "ECDSA-P256"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if req.GetTemplate() != nil {
			t.Errorf("expected nil template, got %+v", req.GetTemplate())
		}
	})

	t.Run("invalid algorithm is rejected", func(t *testing.T) {
		_, err := buildCreateLDevIDRequest(&ldevidCreateFlags{algorithm: "BADALG"})
		if _, ok := err.(ErrInvalidAlgorithm); !ok {
			t.Fatalf("expected ErrInvalidAlgorithm, got %v", err)
		}
	})

	t.Run("invalid handle is rejected", func(t *testing.T) {
		_, err := buildCreateLDevIDRequest(&ldevidCreateFlags{algorithm: "ECDSA-P256", handle: "notahandle"})
		if _, ok := err.(ErrInvalidTPMHandle); !ok {
			t.Fatalf("expected ErrInvalidTPMHandle, got %v", err)
		}
	})
}

func TestParseTPMHandle(t *testing.T) {
	cases := []struct {
		in      string
		want    uint32
		wantErr bool
	}{
		{"0x81010102", 0x81010102, false},
		{"0X81010102", 0x81010102, false},
		{"2164326658", 0x81010102, false},
		{"", 0, true},
		{"zzz", 0, true},
		{"0xZZZ", 0, true},
	}
	for _, tc := range cases {
		got, err := parseTPMHandle(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseTPMHandle(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseTPMHandle(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseTPMHandle(%q) = 0x%08X, want 0x%08X", tc.in, got, tc.want)
		}
	}
}

func TestWriteLDevIDArtifacts(t *testing.T) {
	t.Run("no out path is a no-op", func(t *testing.T) {
		if err := writeLDevIDArtifacts(&ldevidCreateFlags{}, "CSR", "CERT"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("writes cert and csr", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "ldevid.crt")
		if err := writeLDevIDArtifacts(&ldevidCreateFlags{out: out}, "CSRDATA", "CERTDATA"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cert, err := os.ReadFile(out)
		if err != nil || string(cert) != "CERTDATA" {
			t.Fatalf("cert = %q, err %v", cert, err)
		}
		csr, err := os.ReadFile(out + ".csr")
		if err != nil || string(csr) != "CSRDATA" {
			t.Fatalf("csr = %q, err %v", csr, err)
		}
	})
}
