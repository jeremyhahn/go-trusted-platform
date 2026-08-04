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

// DeviceKeyAlgorithm represents a device key algorithm.
type DeviceKeyAlgorithm string

const (
	AlgorithmUnspecified DeviceKeyAlgorithm = "UNSPECIFIED"
	AlgorithmECDSAP256   DeviceKeyAlgorithm = "ECDSA-P256"
	AlgorithmECDSAP384   DeviceKeyAlgorithm = "ECDSA-P384"
	AlgorithmRSA2048     DeviceKeyAlgorithm = "RSA-2048"
	AlgorithmRSA3072     DeviceKeyAlgorithm = "RSA-3072"
)

// DeviceKeyInfo contains information about a device key.
type DeviceKeyInfo struct {
	Handle         uint32             `json:"handle" yaml:"handle"`
	Algorithm      DeviceKeyAlgorithm `json:"algorithm" yaml:"algorithm"`
	PublicKeyPEM   string             `json:"public_key_pem" yaml:"public_key_pem"`
	CreatedAt      int64              `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	HasCertificate bool               `json:"has_certificate" yaml:"has_certificate"`
	CertInfo       *CertificateInfo   `json:"certificate_info,omitempty" yaml:"certificate_info,omitempty"`
}

// CertificateInfo contains certificate metadata.
type CertificateInfo struct {
	SubjectCN          string `json:"subject_cn" yaml:"subject_cn"`
	IssuerCN           string `json:"issuer_cn" yaml:"issuer_cn"`
	SerialNumber       string `json:"serial_number" yaml:"serial_number"`
	Fingerprint        string `json:"fingerprint" yaml:"fingerprint"`
	KeyAlgorithm       string `json:"key_algorithm" yaml:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm" yaml:"signature_algorithm"`
	KeySize            uint32 `json:"key_size" yaml:"key_size"`
	IssuedAt           int64  `json:"issued_at,omitempty" yaml:"issued_at,omitempty"`
	ExpiresAt          int64  `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// DeviceIdentityCertificate contains a device identity certificate.
type DeviceIdentityCertificate struct {
	PEM                string `json:"certificate_pem" yaml:"certificate_pem"`
	SubjectCN          string `json:"subject" yaml:"subject"`
	IssuerCN           string `json:"issuer" yaml:"issuer"`
	SerialNumber       string `json:"serial_number" yaml:"serial_number"`
	Fingerprint        string `json:"fingerprint" yaml:"fingerprint"`
	KeyAlgorithm       string `json:"key_algorithm" yaml:"key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm" yaml:"signature_algorithm"`
	IssuedAt           int64  `json:"not_before,omitempty" yaml:"not_before,omitempty"`
	ExpiresAt          int64  `json:"not_after,omitempty" yaml:"not_after,omitempty"`
}

// CSRTemplate contains the subject fields for a certificate signing request.
type CSRTemplate struct {
	CommonName         string `json:"common_name" yaml:"common_name"`
	Organization       string `json:"organization,omitempty" yaml:"organization,omitempty"`
	Country            string `json:"country,omitempty" yaml:"country,omitempty"`
	Province           string `json:"province,omitempty" yaml:"province,omitempty"`
	Locality           string `json:"locality,omitempty" yaml:"locality,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty" yaml:"organizational_unit,omitempty"`
}

// DeviceAttributes contains TCG device attributes from TPM and platform.
type DeviceAttributes struct {
	TPMManufacturer      string `json:"manufacturer" yaml:"manufacturer"`
	TPMModel             string `json:"model" yaml:"model"`
	TPMVersion           string `json:"version" yaml:"version"`
	PlatformManufacturer string `json:"platform_manufacturer" yaml:"platform_manufacturer"`
	PlatformModel        string `json:"platform_model" yaml:"platform_model"`
	PlatformVersion      string `json:"platform_version" yaml:"platform_version"`
	PlatformSerial       string `json:"platform_serial" yaml:"platform_serial"`
}
