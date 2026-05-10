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

import "time"

// KeyAlgorithm represents a TPM key algorithm.
type KeyAlgorithm string

const (
	// KeyAlgorithmUnspecified indicates no algorithm is set.
	KeyAlgorithmUnspecified KeyAlgorithm = "UNSPECIFIED"
	// KeyAlgorithmRSA2048 indicates RSA-2048.
	KeyAlgorithmRSA2048 KeyAlgorithm = "RSA-2048"
	// KeyAlgorithmRSA3072 indicates RSA-3072.
	KeyAlgorithmRSA3072 KeyAlgorithm = "RSA-3072"
	// KeyAlgorithmRSA4096 indicates RSA-4096.
	KeyAlgorithmRSA4096 KeyAlgorithm = "RSA-4096"
	// KeyAlgorithmECDSAP256 indicates ECDSA-P256.
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ECDSA-P256"
	// KeyAlgorithmECDSAP384 indicates ECDSA-P384.
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ECDSA-P384"
	// KeyAlgorithmECDSAP521 indicates ECDSA-P521.
	KeyAlgorithmECDSAP521 KeyAlgorithm = "ECDSA-P521"
)

// PCRBank represents a TPM PCR bank algorithm.
type PCRBank string

const (
	// PCRBankSHA1 indicates SHA-1 PCR bank.
	PCRBankSHA1 PCRBank = "sha1"
	// PCRBankSHA256 indicates SHA-256 PCR bank.
	PCRBankSHA256 PCRBank = "sha256"
	// PCRBankSHA384 indicates SHA-384 PCR bank.
	PCRBankSHA384 PCRBank = "sha384"
	// PCRBankSHA512 indicates SHA-512 PCR bank.
	PCRBankSHA512 PCRBank = "sha512"
	// PCRBankSM3256 indicates SM3-256 PCR bank.
	PCRBankSM3256 PCRBank = "sm3_256"
)

// DeviceKeyAlgorithm represents a device identity key algorithm.
type DeviceKeyAlgorithm string

const (
	// DeviceKeyAlgorithmUnspecified indicates no algorithm is set.
	DeviceKeyAlgorithmUnspecified DeviceKeyAlgorithm = "UNSPECIFIED"
	// DeviceKeyAlgorithmECDSAP256 indicates ECDSA-P256.
	DeviceKeyAlgorithmECDSAP256 DeviceKeyAlgorithm = "ECDSA-P256"
	// DeviceKeyAlgorithmECDSAP384 indicates ECDSA-P384.
	DeviceKeyAlgorithmECDSAP384 DeviceKeyAlgorithm = "ECDSA-P384"
	// DeviceKeyAlgorithmRSA2048 indicates RSA-2048.
	DeviceKeyAlgorithmRSA2048 DeviceKeyAlgorithm = "RSA-2048"
	// DeviceKeyAlgorithmRSA3072 indicates RSA-3072.
	DeviceKeyAlgorithmRSA3072 DeviceKeyAlgorithm = "RSA-3072"
)

// Status holds the result of a TPM operation.
type Status struct {
	// Success indicates whether the operation succeeded.
	Success bool `json:"success"`
	// Message provides additional status details.
	Message string `json:"message,omitempty"`
}

// KeyAttributes describes attributes for a TPM key.
type KeyAttributes struct {
	// Algorithm is the key algorithm.
	Algorithm KeyAlgorithm `json:"algorithm"`
}

// InfoResponse holds TPM device information.
type InfoResponse struct {
	// Properties contains key-value TPM properties.
	Properties map[string]string `json:"properties,omitempty"`
	// IsSimulator indicates if the TPM is a simulator.
	IsSimulator bool `json:"is_simulator"`
}

// ProvisionRequest holds parameters for provisioning the TPM.
type ProvisionRequest struct {
	// CreateEK indicates whether to create an Endorsement Key.
	CreateEK bool `json:"create_ek"`
	// CreateSRK indicates whether to create a Storage Root Key.
	CreateSRK bool `json:"create_srk"`
	// CreateAK indicates whether to create an Attestation Key.
	CreateAK bool `json:"create_ak"`
	// OwnerPassword is the TPM owner hierarchy password.
	OwnerPassword string `json:"owner_password,omitempty"`
	// EndorsementPassword is the TPM endorsement hierarchy password.
	EndorsementPassword string `json:"endorsement_password,omitempty"`
}

// ProvisionResponse holds the result of TPM provisioning.
type ProvisionResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
	// EKPublic is the EK public key (if created).
	EKPublic []byte `json:"ek_public,omitempty"`
	// SRKPublic is the SRK public key (if created).
	SRKPublic []byte `json:"srk_public,omitempty"`
	// AKPublic is the AK public key (if created).
	AKPublic []byte `json:"ak_public,omitempty"`
}

// ClearResponse holds the result of TPM clear.
type ClearResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// CreateKeyResponse holds the result of creating a TPM key (EK, SRK, or AK).
type CreateKeyResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
	// Handle is the TPM handle for the key.
	Handle uint32 `json:"handle"`
	// PublicKey is the raw public key bytes.
	PublicKey []byte `json:"public_key,omitempty"`
}

// KeyInfoResponse holds information about a TPM key.
type KeyInfoResponse struct {
	// Handle is the TPM handle.
	Handle uint32 `json:"handle"`
	// Algorithm is the key algorithm.
	Algorithm KeyAlgorithm `json:"algorithm"`
	// PublicKey is the raw public key bytes.
	PublicKey []byte `json:"public_key,omitempty"`
}

// DeleteKeyResponse holds the result of deleting a TPM key.
type DeleteKeyResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// EKCertificateResponse holds an EK certificate.
type EKCertificateResponse struct {
	// Certificate is the raw certificate data.
	Certificate []byte `json:"certificate,omitempty"`
	// Format is the certificate format.
	Format string `json:"format"`
}

// SealRequest holds parameters for sealing data to the TPM.
type SealRequest struct {
	// CN is the common name for the sealed object.
	CN string `json:"cn"`
	// Data is the data to seal.
	Data []byte `json:"data"`
	// Password is the password for the sealed object.
	Password string `json:"password,omitempty"`
	// ParentHandle is the parent SRK handle.
	ParentHandle uint32 `json:"parent_handle"`
	// ParentPassword is the parent key password.
	ParentPassword string `json:"parent_password,omitempty"`
	// PCRIndices are PCR indices to bind to.
	PCRIndices []uint32 `json:"pcr_indices,omitempty"`
	// PCRBank is the PCR bank algorithm.
	PCRBank PCRBank `json:"pcr_bank"`
	// Overwrite indicates whether to overwrite existing sealed data.
	Overwrite bool `json:"overwrite"`
}

// SealResponse holds the result of sealing data.
type SealResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// UnsealRequest holds parameters for unsealing data from the TPM.
type UnsealRequest struct {
	// CN is the common name for the sealed object.
	CN string `json:"cn"`
	// Password is the password for the sealed object.
	Password string `json:"password,omitempty"`
	// ParentHandle is the parent SRK handle.
	ParentHandle uint32 `json:"parent_handle"`
	// ParentPassword is the parent key password.
	ParentPassword string `json:"parent_password,omitempty"`
	// PCRIndices are PCR indices.
	PCRIndices []uint32 `json:"pcr_indices,omitempty"`
	// PCRBank is the PCR bank algorithm.
	PCRBank PCRBank `json:"pcr_bank"`
}

// UnsealResponse holds the result of unsealing data.
type UnsealResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
	// Data is the unsealed data.
	Data []byte `json:"data"`
}

// EventLogResponse holds TPM event log data.
type EventLogResponse struct {
	// Format is the event log format.
	Format string `json:"format"`
	// EventCount is the number of events.
	EventCount uint64 `json:"event_count"`
	// EventLog is the raw event log data.
	EventLog []byte `json:"event_log"`
}

// PCRValue holds a single PCR value.
type PCRValue struct {
	// Index is the PCR index.
	Index uint32 `json:"index"`
	// Value is the PCR hash value.
	Value []byte `json:"value"`
	// Bank is the PCR bank.
	Bank PCRBank `json:"bank"`
}

// NVRAMDefineResponse holds the result of defining NVRAM.
type NVRAMDefineResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// NVRAMWriteResponse holds the result of writing NVRAM.
type NVRAMWriteResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// NVRAMReadResponse holds data read from NVRAM.
type NVRAMReadResponse struct {
	// Data is the raw data.
	Data []byte `json:"data"`
}

// NVRAMUndefineResponse holds the result of undefining NVRAM.
type NVRAMUndefineResponse struct {
	// Status is the operation status.
	Status *Status `json:"status"`
}

// QuoteResponse holds a TPM quote result.
type QuoteResponse struct {
	// Quote is the quote data.
	Quote []byte `json:"quote"`
	// Signature is the quote signature.
	Signature []byte `json:"signature"`
	// PCRValues are the PCR values included in the quote.
	PCRValues []*PCRValue `json:"pcr_values,omitempty"`
}

// VerifyQuoteResponse holds the result of verifying a quote.
type VerifyQuoteResponse struct {
	// Valid indicates whether the quote is valid.
	Valid bool `json:"valid"`
	// Message provides additional verification details.
	Message string `json:"message,omitempty"`
}

// DeviceKeyInfo holds information about a device identity key (IDevID/IAK).
type DeviceKeyInfo struct {
	// Handle is the TPM handle.
	Handle uint32 `json:"handle"`
	// Algorithm is the device key algorithm.
	Algorithm DeviceKeyAlgorithm `json:"algorithm"`
	// PublicKeyPEM is the PEM-encoded public key.
	PublicKeyPEM []byte `json:"public_key_pem,omitempty"`
	// CreatedAt is the creation timestamp.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// HasCertificate indicates if a certificate is installed.
	HasCertificate bool `json:"has_certificate"`
	// CertificateInfo holds certificate metadata.
	CertificateInfo *DeviceKeyCertificateInfo `json:"certificate_info,omitempty"`
}

// DeviceKeyCertificateInfo holds certificate metadata for a device key.
type DeviceKeyCertificateInfo struct {
	// SubjectCN is the certificate subject common name.
	SubjectCN string `json:"subject_cn"`
	// IssuerCN is the certificate issuer common name.
	IssuerCN string `json:"issuer_cn"`
	// SerialNumber is the certificate serial number.
	SerialNumber string `json:"serial_number"`
	// Fingerprint is the certificate fingerprint.
	Fingerprint string `json:"fingerprint"`
	// KeyAlgorithm is the key algorithm string.
	KeyAlgorithm string `json:"key_algorithm"`
	// SignatureAlgorithm is the signature algorithm string.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// KeySize is the key size in bits.
	KeySize            uint32 `json:"key_size"`
	// IssuedAt is the certificate issue timestamp.
	IssuedAt *time.Time `json:"issued_at,omitempty"`
	// ExpiresAt is the certificate expiry timestamp.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// DeviceIdentityCertificate holds a device identity certificate.
type DeviceIdentityCertificate struct {
	// PEM is the PEM-encoded certificate.
	PEM []byte `json:"pem"`
	// SubjectCN is the subject common name.
	SubjectCN string `json:"subject_cn"`
	// IssuerCN is the issuer common name.
	IssuerCN string `json:"issuer_cn"`
	// SerialNumber is the serial number.
	SerialNumber string `json:"serial_number"`
	// Fingerprint is the certificate fingerprint.
	Fingerprint string `json:"fingerprint"`
	// KeyAlgorithm is the key algorithm string.
	KeyAlgorithm string `json:"key_algorithm"`
	// SignatureAlgorithm is the signature algorithm string.
	SignatureAlgorithm string `json:"signature_algorithm"`
	// IssuedAt is the certificate issue timestamp.
	IssuedAt *time.Time `json:"issued_at,omitempty"`
	// ExpiresAt is the certificate expiry timestamp.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CSRTemplate holds a certificate signing request template.
type CSRTemplate struct {
	// CommonName is the subject common name.
	CommonName string `json:"common_name"`
	// Organization is the subject organization.
	Organization string `json:"organization,omitempty"`
	// Country is the subject country.
	Country string `json:"country,omitempty"`
	// Province is the subject state/province.
	Province string `json:"province,omitempty"`
	// Locality is the subject city/locality.
	Locality string `json:"locality,omitempty"`
	// OrganizationalUnit is the subject organizational unit.
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
}

// DeviceAttributes holds TPM device attributes.
type DeviceAttributes struct {
	// TPMManufacturer is the TPM manufacturer.
	TPMManufacturer string `json:"tpm_manufacturer"`
	// TPMModel is the TPM model.
	TPMModel string `json:"tpm_model"`
	// TPMVersion is the TPM version.
	TPMVersion string `json:"tpm_version"`
	// PlatformManufacturer is the platform manufacturer.
	PlatformManufacturer string `json:"platform_manufacturer"`
	// PlatformModel is the platform model.
	PlatformModel string `json:"platform_model"`
	// PlatformVersion is the platform version.
	PlatformVersion string `json:"platform_version"`
	// PlatformSerial is the platform serial number.
	PlatformSerial string `json:"platform_serial"`
}
