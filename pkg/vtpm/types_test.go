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

package vtpm

import (
	"testing"
	"time"
)

func TestBundleMode_String(t *testing.T) {
	tests := []struct {
		mode     BundleMode
		expected string
	}{
		{BundleModeTemplate, "template"},
		{BundleModePreAssigned, "pre-assigned"},
		{BundleMode("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("BundleMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBundleMode_IsValid(t *testing.T) {
	tests := []struct {
		mode     BundleMode
		expected bool
	}{
		{BundleModeTemplate, true},
		{BundleModePreAssigned, true},
		{BundleMode("invalid"), false},
		{BundleMode(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.expected {
				t.Errorf("BundleMode.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEKAlgorithm_String(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected string
	}{
		{EKAlgorithmRSA, "RSA"},
		{EKAlgorithmECC, "ECC"},
		{EKAlgorithm("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.algo.String(); got != tt.expected {
				t.Errorf("EKAlgorithm.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEKAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected bool
	}{
		{EKAlgorithmRSA, true},
		{EKAlgorithmECC, true},
		{EKAlgorithm("DSA"), false},
		{EKAlgorithm(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := tt.algo.IsValid(); got != tt.expected {
				t.Errorf("EKAlgorithm.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEKAlgorithm_NVIndex(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected uint32
	}{
		{EKAlgorithmRSA, 0x01C00002},
		{EKAlgorithmECC, 0x01C0000A},
		{EKAlgorithm("unknown"), 0x01C00002}, // Default to RSA index
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := tt.algo.NVIndex(); got != tt.expected {
				t.Errorf("EKAlgorithm.NVIndex() = 0x%08X, want 0x%08X", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Manifest Tests
// =============================================================================

func TestManifest_VersionConstant(t *testing.T) {
	if ManifestVersion != "1.0" {
		t.Errorf("ManifestVersion = %v, want 1.0", ManifestVersion)
	}
}

func TestManifest_Fields(t *testing.T) {
	now := time.Now()
	manifest := &Manifest{
		Version:           ManifestVersion,
		ID:                "test-bundle-id",
		Mode:              BundleModePreAssigned,
		Hostname:          "test.example.com",
		EKAlgorithm:       EKAlgorithmRSA,
		SecureBootEnabled: true,
		CreatedAt:         now,
		ClonedFrom:        "template-id",
		Labels:            map[string]string{"env": "test"},
		Checksums:         map[string]string{"file.txt": "sha256:abc"},
	}

	if manifest.Version != ManifestVersion {
		t.Errorf("Version = %v, want %v", manifest.Version, ManifestVersion)
	}
	if manifest.ID != "test-bundle-id" {
		t.Errorf("ID = %v, want test-bundle-id", manifest.ID)
	}
	if manifest.Mode != BundleModePreAssigned {
		t.Errorf("Mode = %v, want pre-assigned", manifest.Mode)
	}
	if manifest.Hostname != "test.example.com" {
		t.Errorf("Hostname = %v, want test.example.com", manifest.Hostname)
	}
	if manifest.EKAlgorithm != EKAlgorithmRSA {
		t.Errorf("EKAlgorithm = %v, want RSA", manifest.EKAlgorithm)
	}
	if !manifest.SecureBootEnabled {
		t.Error("SecureBootEnabled should be true")
	}
	if !manifest.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", manifest.CreatedAt, now)
	}
	if manifest.ClonedFrom != "template-id" {
		t.Errorf("ClonedFrom = %v, want template-id", manifest.ClonedFrom)
	}
	if manifest.Labels["env"] != "test" {
		t.Errorf("Labels[env] = %v, want test", manifest.Labels["env"])
	}
	if manifest.Checksums["file.txt"] != "sha256:abc" {
		t.Errorf("Checksums[file.txt] = %v, want sha256:abc", manifest.Checksums["file.txt"])
	}
}

// =============================================================================
// EKCertInfo Tests
// =============================================================================

func TestEKCertInfo_Fields(t *testing.T) {
	now := time.Now()
	certInfo := &EKCertInfo{
		Fingerprint: "sha256:abc123",
		NotBefore:   now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		Issuer:      "Test CA",
	}

	if certInfo.Fingerprint != "sha256:abc123" {
		t.Errorf("Fingerprint = %v, want sha256:abc123", certInfo.Fingerprint)
	}
	if !certInfo.NotBefore.Equal(now) {
		t.Errorf("NotBefore = %v, want %v", certInfo.NotBefore, now)
	}
	if certInfo.Issuer != "Test CA" {
		t.Errorf("Issuer = %v, want Test CA", certInfo.Issuer)
	}
}

// =============================================================================
// SecureBootKeyInfo Tests
// =============================================================================

func TestSecureBootKeyInfo_Fields(t *testing.T) {
	keyInfo := &SecureBootKeyInfo{
		PKFingerprint:  "sha256:pk123",
		KEKFingerprint: "sha256:kek123",
		DBFingerprint:  "sha256:db123",
	}

	if keyInfo.PKFingerprint != "sha256:pk123" {
		t.Errorf("PKFingerprint = %v, want sha256:pk123", keyInfo.PKFingerprint)
	}
	if keyInfo.KEKFingerprint != "sha256:kek123" {
		t.Errorf("KEKFingerprint = %v, want sha256:kek123", keyInfo.KEKFingerprint)
	}
	if keyInfo.DBFingerprint != "sha256:db123" {
		t.Errorf("DBFingerprint = %v, want sha256:db123", keyInfo.DBFingerprint)
	}
}

// =============================================================================
// Bundle Tests
// =============================================================================

func TestBundle_Fields(t *testing.T) {
	now := time.Now()
	manifest := &Manifest{
		Version:   ManifestVersion,
		ID:        "test-bundle",
		CreatedAt: now,
	}

	bundle := &Bundle{
		ID:         "test-bundle",
		Manifest:   manifest,
		Mode:       BundleModePreAssigned,
		CreatedAt:  now,
		ClonedFrom: "template-id",
	}

	if bundle.ID != "test-bundle" {
		t.Errorf("ID = %v, want test-bundle", bundle.ID)
	}
	if bundle.Manifest != manifest {
		t.Error("Manifest should match")
	}
	if bundle.Mode != BundleModePreAssigned {
		t.Errorf("Mode = %v, want pre-assigned", bundle.Mode)
	}
	if !bundle.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", bundle.CreatedAt, now)
	}
	if bundle.ClonedFrom != "template-id" {
		t.Errorf("ClonedFrom = %v, want template-id", bundle.ClonedFrom)
	}
}

func TestBundle_SecureBootKeys(t *testing.T) {
	sbKeys := &SecureBootKeyPaths{
		PKKey:   "/path/to/PK.key",
		PKCert:  "/path/to/PK.crt",
		KEKKey:  "/path/to/KEK.key",
		KEKCert: "/path/to/KEK.crt",
		DBKey:   "/path/to/DB.key",
		DBCert:  "/path/to/DB.crt",
	}

	bundle := &Bundle{
		ID:             "sb-bundle",
		SecureBootKeys: sbKeys,
	}

	if bundle.SecureBootKeys.PKKey != "/path/to/PK.key" {
		t.Errorf("PKKey = %v, want /path/to/PK.key", bundle.SecureBootKeys.PKKey)
	}
	if bundle.SecureBootKeys.PKCert != "/path/to/PK.crt" {
		t.Errorf("PKCert = %v, want /path/to/PK.crt", bundle.SecureBootKeys.PKCert)
	}
	if bundle.SecureBootKeys.KEKKey != "/path/to/KEK.key" {
		t.Errorf("KEKKey = %v, want /path/to/KEK.key", bundle.SecureBootKeys.KEKKey)
	}
	if bundle.SecureBootKeys.KEKCert != "/path/to/KEK.crt" {
		t.Errorf("KEKCert = %v, want /path/to/KEK.crt", bundle.SecureBootKeys.KEKCert)
	}
	if bundle.SecureBootKeys.DBKey != "/path/to/DB.key" {
		t.Errorf("DBKey = %v, want /path/to/DB.key", bundle.SecureBootKeys.DBKey)
	}
	if bundle.SecureBootKeys.DBCert != "/path/to/DB.crt" {
		t.Errorf("DBCert = %v, want /path/to/DB.crt", bundle.SecureBootKeys.DBCert)
	}
}

// =============================================================================
// TPMState Tests
// =============================================================================

func TestTPMState_Fields(t *testing.T) {
	tpmState := &TPMState{
		StateDir:     "/var/lib/vtpm/bundles/test/tpm",
		PermallFile:  "/var/lib/vtpm/bundles/test/tpm/tpm2-00.permall",
		VolatileFile: "/var/lib/vtpm/bundles/test/tpm/tpm2-00.volatilestate",
	}

	if tpmState.StateDir != "/var/lib/vtpm/bundles/test/tpm" {
		t.Errorf("StateDir = %v, want /var/lib/vtpm/bundles/test/tpm", tpmState.StateDir)
	}
	if tpmState.PermallFile != "/var/lib/vtpm/bundles/test/tpm/tpm2-00.permall" {
		t.Errorf("PermallFile = %v, want /var/lib/vtpm/bundles/test/tpm/tpm2-00.permall", tpmState.PermallFile)
	}
	if tpmState.VolatileFile != "/var/lib/vtpm/bundles/test/tpm/tpm2-00.volatilestate" {
		t.Errorf("VolatileFile = %v, want /var/lib/vtpm/bundles/test/tpm/tpm2-00.volatilestate", tpmState.VolatileFile)
	}
}

// =============================================================================
// OVMFState Tests
// =============================================================================

func TestOVMFState_Fields(t *testing.T) {
	ovmfState := &OVMFState{
		NVRAMFile: "/var/lib/vtpm/bundles/test/ovmf/OVMF_VARS.fd",
	}

	if ovmfState.NVRAMFile != "/var/lib/vtpm/bundles/test/ovmf/OVMF_VARS.fd" {
		t.Errorf("NVRAMFile = %v, want /var/lib/vtpm/bundles/test/ovmf/OVMF_VARS.fd", ovmfState.NVRAMFile)
	}
}

// =============================================================================
// Template Tests
// =============================================================================

func TestTemplate_Fields(t *testing.T) {
	now := time.Now()
	template := &Template{
		ID:                "test-template",
		Description:       "Test template description",
		TPMStateDir:       "/var/lib/vtpm/templates/test-template/tpm",
		NVRAMPath:         "/var/lib/vtpm/templates/test-template/ovmf/OVMF_VARS.fd",
		SecureBootKeysDir: "/var/lib/vtpm/templates/test-template/secure-boot-keys",
		EKAlgorithm:       EKAlgorithmECC,
		SecureBootEnabled: true,
		CreatedAt:         now,
	}

	if template.ID != "test-template" {
		t.Errorf("ID = %v, want test-template", template.ID)
	}
	if template.Description != "Test template description" {
		t.Errorf("Description = %v, want Test template description", template.Description)
	}
	if template.TPMStateDir != "/var/lib/vtpm/templates/test-template/tpm" {
		t.Errorf("TPMStateDir = %v, want /var/lib/vtpm/templates/test-template/tpm", template.TPMStateDir)
	}
	if template.NVRAMPath != "/var/lib/vtpm/templates/test-template/ovmf/OVMF_VARS.fd" {
		t.Errorf("NVRAMPath = %v, want /var/lib/vtpm/templates/test-template/ovmf/OVMF_VARS.fd", template.NVRAMPath)
	}
	if !template.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt = %v, want %v", template.CreatedAt, now)
	}
	if template.EKAlgorithm != EKAlgorithmECC {
		t.Errorf("EKAlgorithm = %v, want ECC", template.EKAlgorithm)
	}
	if !template.SecureBootEnabled {
		t.Error("SecureBootEnabled should be true")
	}
}

// =============================================================================
// CreateBundleOptions Tests
// =============================================================================

func TestCreateBundleOptions_Fields(t *testing.T) {
	opts := &CreateBundleOptions{
		Hostname:          "new-host.example.com",
		Mode:              BundleModePreAssigned,
		EKAlgorithm:       EKAlgorithmRSA,
		SecureBootEnabled: true,
		Labels:            map[string]string{"env": "prod"},
	}

	if opts.Hostname != "new-host.example.com" {
		t.Errorf("Hostname = %v, want new-host.example.com", opts.Hostname)
	}
	if opts.Mode != BundleModePreAssigned {
		t.Errorf("Mode = %v, want pre-assigned", opts.Mode)
	}
	if opts.EKAlgorithm != EKAlgorithmRSA {
		t.Errorf("EKAlgorithm = %v, want RSA", opts.EKAlgorithm)
	}
	if !opts.SecureBootEnabled {
		t.Error("SecureBootEnabled should be true")
	}
	if opts.Labels["env"] != "prod" {
		t.Errorf("Labels[env] = %v, want prod", opts.Labels["env"])
	}
}

// =============================================================================
// CreateTemplateOptions Tests
// =============================================================================

func TestCreateTemplateOptions_Fields(t *testing.T) {
	opts := &CreateTemplateOptions{
		ID:                "my-template",
		Description:       "My template",
		EKAlgorithm:       EKAlgorithmECC,
		SecureBootEnabled: true,
	}

	if opts.ID != "my-template" {
		t.Errorf("ID = %v, want my-template", opts.ID)
	}
	if opts.Description != "My template" {
		t.Errorf("Description = %v, want My template", opts.Description)
	}
	if opts.EKAlgorithm != EKAlgorithmECC {
		t.Errorf("EKAlgorithm = %v, want ECC", opts.EKAlgorithm)
	}
	if !opts.SecureBootEnabled {
		t.Error("SecureBootEnabled should be true")
	}
}

// =============================================================================
// CloneOptions Tests
// =============================================================================

func TestCloneOptions_Fields(t *testing.T) {
	opts := &CloneOptions{
		TemplateID: "base-template",
		Hostname:   "cloned-host.example.com",
		Labels:     map[string]string{"tier": "frontend"},
	}

	if opts.TemplateID != "base-template" {
		t.Errorf("TemplateID = %v, want base-template", opts.TemplateID)
	}
	if opts.Hostname != "cloned-host.example.com" {
		t.Errorf("Hostname = %v, want cloned-host.example.com", opts.Hostname)
	}
	if opts.Labels["tier"] != "frontend" {
		t.Errorf("Labels[tier] = %v, want frontend", opts.Labels["tier"])
	}
}

// =============================================================================
// ListOptions Tests
// =============================================================================

func TestListOptions_Fields(t *testing.T) {
	opts := &ListOptions{
		Mode:   BundleModePreAssigned,
		Labels: map[string]string{"env": "staging"},
		Offset: 10,
		Limit:  25,
	}

	if opts.Mode != BundleModePreAssigned {
		t.Errorf("Mode = %v, want pre-assigned", opts.Mode)
	}
	if opts.Labels["env"] != "staging" {
		t.Errorf("Labels[env] = %v, want staging", opts.Labels["env"])
	}
	if opts.Offset != 10 {
		t.Errorf("Offset = %v, want 10", opts.Offset)
	}
	if opts.Limit != 25 {
		t.Errorf("Limit = %v, want 25", opts.Limit)
	}
}

// =============================================================================
// QuoteResult Tests
// =============================================================================

func TestQuoteResult_Fields(t *testing.T) {
	result := &QuoteResult{
		Quote:     []byte("quote-data"),
		Signature: []byte("signature-data"),
		PCRValues: map[int][]byte{
			0: []byte("pcr0"),
			7: []byte("pcr7"),
		},
		HashAlgorithm: "SHA-256",
	}

	if string(result.Quote) != "quote-data" {
		t.Errorf("Quote = %v, want quote-data", string(result.Quote))
	}
	if string(result.Signature) != "signature-data" {
		t.Errorf("Signature = %v, want signature-data", string(result.Signature))
	}
	if string(result.PCRValues[0]) != "pcr0" {
		t.Errorf("PCRValues[0] = %v, want pcr0", string(result.PCRValues[0]))
	}
	if string(result.PCRValues[7]) != "pcr7" {
		t.Errorf("PCRValues[7] = %v, want pcr7", string(result.PCRValues[7]))
	}
	if result.HashAlgorithm != "SHA-256" {
		t.Errorf("HashAlgorithm = %v, want SHA-256", result.HashAlgorithm)
	}
}

// =============================================================================
// SealOptions Tests
// =============================================================================

func TestSealOptions_Fields(t *testing.T) {
	opts := &SealOptions{
		PCRs:      []int{0, 1, 7},
		AuthValue: "secret-auth-value",
	}

	if len(opts.PCRs) != 3 {
		t.Errorf("len(PCRs) = %v, want 3", len(opts.PCRs))
	}
	if opts.PCRs[0] != 0 || opts.PCRs[1] != 1 || opts.PCRs[2] != 7 {
		t.Errorf("PCRs = %v, want [0, 1, 7]", opts.PCRs)
	}
	if opts.AuthValue != "secret-auth-value" {
		t.Errorf("AuthValue = %v, want secret-auth-value", opts.AuthValue)
	}
}

// =============================================================================
// Constants Tests
// =============================================================================

func TestBundleModeConstants(t *testing.T) {
	if BundleModeTemplate != "template" {
		t.Errorf("BundleModeTemplate = %v, want template", BundleModeTemplate)
	}
	if BundleModePreAssigned != "pre-assigned" {
		t.Errorf("BundleModePreAssigned = %v, want pre-assigned", BundleModePreAssigned)
	}
}

func TestEKAlgorithmConstants(t *testing.T) {
	if EKAlgorithmRSA != "RSA" {
		t.Errorf("EKAlgorithmRSA = %v, want RSA", EKAlgorithmRSA)
	}
	if EKAlgorithmECC != "ECC" {
		t.Errorf("EKAlgorithmECC = %v, want ECC", EKAlgorithmECC)
	}
}
