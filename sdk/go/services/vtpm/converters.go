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
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// String-to-domain enum maps

// StringToEKAlgorithm maps user-facing algorithm strings to domain EKAlgorithm.
var StringToEKAlgorithm = map[string]EKAlgorithm{
	"RSA": EKAlgorithmRSA,
	"ECC": EKAlgorithmECC,
}

// StringToBundleMode maps user-facing mode strings to domain BundleMode.
var StringToBundleMode = map[string]BundleMode{
	"template":     BundleModeTemplate,
	"pre-assigned": BundleModePreAssigned,
	"preassigned":  BundleModePreAssigned,
}

// ParseEKAlgorithm parses a user-facing algorithm string to a domain EKAlgorithm.
func ParseEKAlgorithm(s string) (EKAlgorithm, bool) {
	alg, ok := StringToEKAlgorithm[strings.ToUpper(strings.TrimSpace(s))]
	return alg, ok
}

// ParseBundleMode parses a user-facing mode string to a domain BundleMode.
func ParseBundleMode(s string) (BundleMode, bool) {
	mode, ok := StringToBundleMode[strings.ToLower(strings.TrimSpace(s))]
	return mode, ok
}

// Domain-to-proto enum maps

var ekAlgorithmToProto = map[EKAlgorithm]platformv1.EKAlgorithm{
	EKAlgorithmUnspecified: platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED,
	EKAlgorithmRSA:         platformv1.EKAlgorithm_EK_ALGORITHM_RSA,
	EKAlgorithmECC:         platformv1.EKAlgorithm_EK_ALGORITHM_ECC,
}

var protoToEKAlgorithm = map[platformv1.EKAlgorithm]EKAlgorithm{
	platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED: EKAlgorithmUnspecified,
	platformv1.EKAlgorithm_EK_ALGORITHM_RSA:         EKAlgorithmRSA,
	platformv1.EKAlgorithm_EK_ALGORITHM_ECC:         EKAlgorithmECC,
}

var bundleModeToProto = map[BundleMode]platformv1.BundleMode{
	BundleModeUnspecified: platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED,
	BundleModeTemplate:    platformv1.BundleMode_BUNDLE_MODE_TEMPLATE,
	BundleModePreAssigned: platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED,
}

var protoToBundleMode = map[platformv1.BundleMode]BundleMode{
	platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED:  BundleModeUnspecified,
	platformv1.BundleMode_BUNDLE_MODE_TEMPLATE:     BundleModeTemplate,
	platformv1.BundleMode_BUNDLE_MODE_PRE_ASSIGNED: BundleModePreAssigned,
}

// EKAlgorithmToProto converts a domain EKAlgorithm to a proto EKAlgorithm.
func EKAlgorithmToProto(alg EKAlgorithm) platformv1.EKAlgorithm {
	p, ok := ekAlgorithmToProto[alg]
	if !ok {
		return platformv1.EKAlgorithm_EK_ALGORITHM_UNSPECIFIED
	}
	return p
}

// EKAlgorithmFromProto converts a proto EKAlgorithm to a domain EKAlgorithm.
func EKAlgorithmFromProto(alg platformv1.EKAlgorithm) EKAlgorithm {
	d, ok := protoToEKAlgorithm[alg]
	if !ok {
		return EKAlgorithmUnspecified
	}
	return d
}

// BundleModeToProto converts a domain BundleMode to a proto BundleMode.
func BundleModeToProto(mode BundleMode) platformv1.BundleMode {
	p, ok := bundleModeToProto[mode]
	if !ok {
		return platformv1.BundleMode_BUNDLE_MODE_UNSPECIFIED
	}
	return p
}

// BundleModeFromProto converts a proto BundleMode to a domain BundleMode.
func BundleModeFromProto(mode platformv1.BundleMode) BundleMode {
	d, ok := protoToBundleMode[mode]
	if !ok {
		return BundleModeUnspecified
	}
	return d
}

// StatusFromProto converts a proto Status to a domain Status.
func StatusFromProto(s *platformv1.Status) *Status {
	if s == nil {
		return nil
	}
	return &Status{
		Success: s.Success,
		Message: s.Message,
	}
}

// BundleFromProto converts a proto Bundle to a domain Bundle.
func BundleFromProto(b *platformv1.Bundle) *Bundle {
	if b == nil {
		return nil
	}
	result := &Bundle{
		ID:         b.Id,
		Mode:       BundleModeFromProto(b.Mode),
		ClonedFrom: b.ClonedFrom,
	}
	if b.CreatedAt != nil {
		t := b.CreatedAt.AsTime()
		result.CreatedAt = &t
	}
	if b.Manifest != nil {
		result.Manifest = BundleManifestFromProto(b.Manifest)
	}
	if b.TpmState != nil {
		result.TPMState = &TPMState{
			StateDir:     b.TpmState.StateDir,
			PermallFile:  b.TpmState.PermallFile,
			VolatileFile: b.TpmState.VolatileFile,
		}
	}
	if b.OvmfState != nil {
		result.OVMFState = &OVMFState{
			NVRAMFile: b.OvmfState.NvramFile,
		}
	}
	if b.SecureBootKeys != nil {
		result.SecureBootKeys = &SecureBootKeys{
			Dir:     b.SecureBootKeys.Dir,
			PKKey:   b.SecureBootKeys.PkKey,
			PKCert:  b.SecureBootKeys.PkCrt,
			KEKKey:  b.SecureBootKeys.KekKey,
			KEKCert: b.SecureBootKeys.KekCrt,
			DBKey:   b.SecureBootKeys.DbKey,
			DBCert:  b.SecureBootKeys.DbCrt,
		}
	}
	return result
}

// BundleManifestFromProto converts a proto BundleManifest to a domain BundleManifest.
func BundleManifestFromProto(m *platformv1.Manifest) *BundleManifest {
	if m == nil {
		return nil
	}
	result := &BundleManifest{
		Hostname:          m.Hostname,
		EKAlgorithm:       EKAlgorithmFromProto(m.EkAlgorithm),
		SecureBootEnabled: m.SecureBootEnabled,
		ClonedFrom:        m.ClonedFrom,
		Labels:            m.Labels,
		Checksums:         m.Checksums,
	}
	if m.CreatedAt != nil {
		t := m.CreatedAt.AsTime()
		result.CreatedAt = &t
	}
	if m.EkCertificate != nil && m.EkCertificate.Fingerprint != "" {
		result.EKCertificate = &EKCertificateInfo{
			Fingerprint: m.EkCertificate.Fingerprint,
		}
	}
	return result
}

// TemplateFromProto converts a proto Template to a domain Template.
func TemplateFromProto(t *platformv1.Template) *Template {
	if t == nil {
		return nil
	}
	result := &Template{
		ID:                t.Id,
		Description:       t.Description,
		EKAlgorithm:       EKAlgorithmFromProto(t.EkAlgorithm),
		SecureBootEnabled: t.SecureBootEnabled,
		TPMStateDir:       t.TpmStateDir,
		NVRAMPath:         t.NvramPath,
		SecureBootKeysDir: t.SecureBootKeysDir,
	}
	if t.CreatedAt != nil {
		ct := t.CreatedAt.AsTime()
		result.CreatedAt = &ct
	}
	return result
}

// BundlesFromProto converts a slice of proto Bundles to domain Bundles.
func BundlesFromProto(bundles []*platformv1.Bundle) []*Bundle {
	if bundles == nil {
		return nil
	}
	result := make([]*Bundle, len(bundles))
	for i, b := range bundles {
		result[i] = BundleFromProto(b)
	}
	return result
}

// TemplatesFromProto converts a slice of proto Templates to domain Templates.
func TemplatesFromProto(templates []*platformv1.Template) []*Template {
	if templates == nil {
		return nil
	}
	result := make([]*Template, len(templates))
	for i, t := range templates {
		result[i] = TemplateFromProto(t)
	}
	return result
}
