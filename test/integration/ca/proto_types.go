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

package ca

import (
	"encoding/base64"
	"encoding/json"
	"time"
)

// =============================================================================
// Protobuf JSON Types
//
// These types are used by adapters (MCP) that receive responses encoded as
// protobuf messages serialized with encoding/json (NOT domain types and NOT
// protojson). In this encoding, timestamps are {"seconds": N, "nanos": N},
// enums are integers, and bytes fields are base64 strings.
//
// The CLI adapter uses domain types (sdk/go/services/ca) where timestamps are
// RFC3339 strings and enums are strings — see cli_adapter.go for those types.
// =============================================================================

// protoTimestamp represents a protobuf Timestamp serialized via encoding/json.
type protoTimestamp struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

// toTime converts a protoTimestamp to a Go time.Time.
func (t *protoTimestamp) toTime() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Unix(t.Seconds, int64(t.Nanos))
}

// protoSubject represents a protobuf Subject message serialized via encoding/json.
type protoSubject struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizational_unit"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
	Address            string `json:"address"`
	PostalCode         string `json:"postal_code"`
}

// protoSANs represents protobuf SubjectAlternativeNames serialized via encoding/json.
type protoSANs struct {
	DNSNames       []string `json:"dns_names"`
	IPAddresses    []string `json:"ip_addresses"`
	EmailAddresses []string `json:"email_addresses"`
	URIs           []string `json:"uris"`
}

// protoStatus represents a protobuf Status message serialized via encoding/json.
type protoStatus struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// protoCertSummary represents a protobuf CertificateSummary serialized via encoding/json.
type protoCertSummary struct {
	Serial       string          `json:"serial"`
	CommonName   string          `json:"common_name"`
	Issuer       string          `json:"issuer"`
	NotBefore    *protoTimestamp `json:"not_before"`
	NotAfter     *protoTimestamp `json:"not_after"`
	Status       int32           `json:"status"`
	KeyAlgorithm int32           `json:"key_algorithm"`
}

// protoCertificate represents a protobuf Certificate serialized via encoding/json.
type protoCertificate struct {
	Serial             string          `json:"serial"`
	Subject            *protoSubject   `json:"subject"`
	Issuer             string          `json:"issuer"`
	NotBefore          *protoTimestamp `json:"not_before"`
	NotAfter           *protoTimestamp `json:"not_after"`
	Status             int32           `json:"status"`
	KeyAlgorithm       int32           `json:"key_algorithm"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	IsCA               bool            `json:"is_ca"`
	MaxPathLen         int32           `json:"max_path_len"`
	Sans               *protoSANs      `json:"sans"`
	KeyUsage           []string        `json:"key_usage"`
	ExtKeyUsage        []string        `json:"ext_key_usage"`
	PEM                json.RawMessage `json:"pem"`
	DER                json.RawMessage `json:"der"`
	FingerprintSHA256  string          `json:"fingerprint_sha256"`
}

// protoKeyStoreInfo represents a protobuf KeyStoreInfo serialized via encoding/json.
type protoKeyStoreInfo struct {
	Type         string   `json:"type"`
	Available    bool     `json:"available"`
	Capabilities []string `json:"capabilities"`
}

// =============================================================================
// Protobuf Enum Conversion
// =============================================================================

// protoCertStatusMap converts protobuf CertificateStatus enum integers to CertificateStatus.
var protoCertStatusMap = map[int32]CertificateStatus{
	0: CertificateStatusUnspecified,
	1: CertificateStatusValid,
	2: CertificateStatusRevoked,
	3: CertificateStatusExpired,
	4: CertificateStatusPending,
}

// protoKeyAlgorithmMap converts protobuf KeyAlgorithm enum integers to string names.
var protoKeyAlgorithmMap = map[int32]string{
	0:  "KEY_ALGORITHM_UNSPECIFIED",
	1:  "RSA-2048",
	2:  "RSA-3072",
	3:  "RSA-4096",
	4:  "ECDSA-P256",
	5:  "ECDSA-P384",
	6:  "ECDSA-P521",
	7:  "ED25519",
	8:  "DILITHIUM2",
	9:  "DILITHIUM3",
	10: "DILITHIUM5",
}

// protoRevocationReasonMap converts protobuf RevocationReason enum integers to RevocationReason.
var protoRevocationReasonMap = map[int32]RevocationReason{
	0:  RevocationReasonUnspecified,
	1:  RevocationReasonKeyCompromise,
	2:  RevocationReasonCACompromise,
	3:  RevocationReasonAffiliationChanged,
	4:  RevocationReasonSuperseded,
	5:  RevocationReasonCessationOfOperation,
	6:  RevocationReasonCertificateHold,
	8:  RevocationReasonRemoveFromCRL,
	9:  RevocationReasonPrivilegeWithdrawn,
	10: RevocationReasonAACompromise,
}

// parseCertStatusEnum converts a protobuf CertificateStatus enum int to CertificateStatus.
func parseCertStatusEnum(status int32) CertificateStatus {
	if s, ok := protoCertStatusMap[status]; ok {
		return s
	}
	return CertificateStatusUnspecified
}

// parseKeyAlgorithmEnum converts a protobuf KeyAlgorithm enum int to a human-readable string.
func parseKeyAlgorithmEnum(alg int32) string {
	if name, ok := protoKeyAlgorithmMap[alg]; ok {
		return name
	}
	return "UNKNOWN"
}

// parseRevocationReasonEnum converts a protobuf RevocationReason enum int to RevocationReason.
func parseRevocationReasonEnum(reason int32) RevocationReason {
	if r, ok := protoRevocationReasonMap[reason]; ok {
		return r
	}
	return RevocationReasonUnspecified
}

// decodePEMBytes decodes the PEM field from protobuf JSON. Protobuf bytes fields
// are serialized as base64 strings by encoding/json.
func decodePEMBytes(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var b64 string
	if err := json.Unmarshal(raw, &b64); err != nil {
		return nil
	}
	if b64 == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Might already be raw PEM text
		return []byte(b64)
	}
	return decoded
}

// convertProtoCertificate converts a protobuf Certificate JSON representation
// to the common test Certificate type.
func convertProtoCertificate(pc *protoCertificate) *Certificate {
	if pc == nil {
		return nil
	}

	cert := &Certificate{
		Serial:             pc.Serial,
		Issuer:             pc.Issuer,
		Status:             parseCertStatusEnum(pc.Status),
		KeyAlgorithm:       parseKeyAlgorithmEnum(pc.KeyAlgorithm),
		SignatureAlgorithm: pc.SignatureAlgorithm,
		IsCA:               pc.IsCA,
		MaxPathLen:         pc.MaxPathLen,
		KeyUsage:           pc.KeyUsage,
		ExtKeyUsage:        pc.ExtKeyUsage,
		FingerprintSHA256:  pc.FingerprintSHA256,
		PEM:                decodePEMBytes(pc.PEM),
		DER:                decodePEMBytes(pc.DER),
	}

	if pc.NotBefore != nil {
		cert.NotBefore = pc.NotBefore.toTime()
	}
	if pc.NotAfter != nil {
		cert.NotAfter = pc.NotAfter.toTime()
	}

	if pc.Subject != nil {
		cert.Subject = Subject{
			CommonName:         pc.Subject.CommonName,
			Organization:       pc.Subject.Organization,
			OrganizationalUnit: pc.Subject.OrganizationalUnit,
			Country:            pc.Subject.Country,
			Province:           pc.Subject.Province,
			Locality:           pc.Subject.Locality,
			Address:            pc.Subject.Address,
			PostalCode:         pc.Subject.PostalCode,
		}
	}

	if pc.Sans != nil {
		cert.SANsDNS = pc.Sans.DNSNames
		cert.SANsIPs = pc.Sans.IPAddresses
		cert.SANsEmail = pc.Sans.EmailAddresses
		cert.SANsURIs = pc.Sans.URIs
	}

	return cert
}
