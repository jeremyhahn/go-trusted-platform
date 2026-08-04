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

package idevid

import (
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// algorithmFromProtoMap maps proto DeviceKeyAlgorithm to domain DeviceKeyAlgorithm.
var algorithmFromProtoMap = map[platformv1.DeviceKeyAlgorithm]DeviceKeyAlgorithm{
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256: AlgorithmECDSAP256,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384: AlgorithmECDSAP384,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048:   AlgorithmRSA2048,
	platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072:   AlgorithmRSA3072,
}

// AlgorithmFromProto converts a proto DeviceKeyAlgorithm to a domain DeviceKeyAlgorithm.
func AlgorithmFromProto(a platformv1.DeviceKeyAlgorithm) DeviceKeyAlgorithm {
	if v, ok := algorithmFromProtoMap[a]; ok {
		return v
	}
	return AlgorithmUnspecified
}

// algorithmToProtoMap maps algorithm strings to proto DeviceKeyAlgorithm.
var algorithmToProtoMap = map[string]platformv1.DeviceKeyAlgorithm{
	"ECDSA-P256": platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	"ECDSAP256":  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	"EC-P256":    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	"P256":       platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
	"ECDSA-P384": platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
	"ECDSAP384":  platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
	"EC-P384":    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
	"P384":       platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
	"RSA-2048":   platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
	"RSA2048":    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_2048,
	"RSA-3072":   platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
	"RSA3072":    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_RSA_3072,
}

// AlgorithmToProto converts an algorithm string to a proto DeviceKeyAlgorithm.
// Returns DEVICE_KEY_ALGORITHM_UNSPECIFIED and false if not recognized.
func AlgorithmToProto(s string) (platformv1.DeviceKeyAlgorithm, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(s))
	if v, ok := algorithmToProtoMap[normalized]; ok {
		return v, true
	}
	return platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_UNSPECIFIED, false
}

// DeviceKeyInfoFromProto converts a proto DeviceKeyInfo to a domain DeviceKeyInfo.
func DeviceKeyInfoFromProto(info *platformv1.DeviceKeyInfo) *DeviceKeyInfo {
	if info == nil {
		return nil
	}
	dki := &DeviceKeyInfo{
		Handle:         info.Handle,
		Algorithm:      AlgorithmFromProto(info.Algorithm),
		PublicKeyPEM:   string(info.PublicKeyPem),
		HasCertificate: info.HasCertificate,
	}
	if info.CreatedAt != nil {
		dki.CreatedAt = info.CreatedAt.Seconds
	}
	if info.CertificateInfo != nil {
		dki.CertInfo = certInfoFromDeviceIdentityCert(info.CertificateInfo)
	}
	return dki
}

// certInfoFromDeviceIdentityCert extracts CertificateInfo from a DeviceIdentityCertificate.
func certInfoFromDeviceIdentityCert(cert *platformv1.DeviceIdentityCertificate) *CertificateInfo {
	if cert == nil {
		return nil
	}
	ci := &CertificateInfo{
		SubjectCN:          cert.SubjectCn,
		IssuerCN:           cert.IssuerCn,
		SerialNumber:       cert.SerialNumber,
		Fingerprint:        cert.Fingerprint,
		KeyAlgorithm:       cert.KeyAlgorithm,
		SignatureAlgorithm: cert.SignatureAlgorithm,
		KeySize:            cert.KeySize,
	}
	if cert.IssuedAt != nil {
		ci.IssuedAt = cert.IssuedAt.Seconds
	}
	if cert.ExpiresAt != nil {
		ci.ExpiresAt = cert.ExpiresAt.Seconds
	}
	return ci
}

// DeviceIdentityCertificateFromProto converts a proto DeviceIdentityCertificate to a domain type.
func DeviceIdentityCertificateFromProto(cert *platformv1.DeviceIdentityCertificate) *DeviceIdentityCertificate {
	if cert == nil {
		return nil
	}
	dic := &DeviceIdentityCertificate{
		PEM:                string(cert.Pem),
		SubjectCN:          cert.SubjectCn,
		IssuerCN:           cert.IssuerCn,
		SerialNumber:       cert.SerialNumber,
		Fingerprint:        cert.Fingerprint,
		KeyAlgorithm:       cert.KeyAlgorithm,
		SignatureAlgorithm: cert.SignatureAlgorithm,
	}
	if cert.IssuedAt != nil {
		dic.IssuedAt = cert.IssuedAt.Seconds
	}
	if cert.ExpiresAt != nil {
		dic.ExpiresAt = cert.ExpiresAt.Seconds
	}
	return dic
}

// CSRTemplateToProto converts a domain CSRTemplate to a proto CSRTemplate.
func CSRTemplateToProto(t *CSRTemplate) *platformv1.CSRTemplate {
	if t == nil {
		return nil
	}
	return &platformv1.CSRTemplate{
		CommonName:         t.CommonName,
		Organization:       t.Organization,
		Country:            t.Country,
		Province:           t.Province,
		Locality:           t.Locality,
		OrganizationalUnit: t.OrganizationalUnit,
	}
}

// DeviceAttributesFromProto converts a proto TCGDeviceAttributes to a domain DeviceAttributes.
func DeviceAttributesFromProto(attrs *platformv1.TCGDeviceAttributes) *DeviceAttributes {
	if attrs == nil {
		return nil
	}
	return &DeviceAttributes{
		TPMManufacturer:      attrs.GetTpmManufacturer(),
		TPMModel:             attrs.GetTpmModel(),
		TPMVersion:           attrs.GetTpmVersion(),
		PlatformManufacturer: attrs.GetPlatformManufacturer(),
		PlatformModel:        attrs.GetPlatformModel(),
		PlatformVersion:      attrs.GetPlatformVersion(),
		PlatformSerial:       attrs.GetPlatformSerial(),
	}
}
