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

package ca

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// Proto-to-domain enum maps

var protoKeyAlgorithmToAlgorithm = map[platformv1.KeyAlgorithm]KeyAlgorithm{
	platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED: KeyAlgorithmUnspecified,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:    KeyAlgorithmRSA2048,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:    KeyAlgorithmRSA3072,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:    KeyAlgorithmRSA4096,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:  KeyAlgorithmECDSAP256,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:  KeyAlgorithmECDSAP384,
	platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:     KeyAlgorithmEd25519,
}

var protoCertStatusToStatus = map[platformv1.CertificateStatus]CertificateStatus{
	platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED: CertificateStatusUnspecified,
	platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID:       CertificateStatusValid,
	platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED:     CertificateStatusRevoked,
	platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED:     CertificateStatusExpired,
	platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING:     CertificateStatusPending,
}

var protoRevocationReasonToReason = map[platformv1.RevocationReason]RevocationReason{
	platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED:          RevocationReasonUnspecified,
	platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE:       RevocationReasonKeyCompromise,
	platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE:        RevocationReasonCACompromise,
	platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED:  RevocationReasonAffiliationChanged,
	platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED:           RevocationReasonSuperseded,
	platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION: RevocationReasonCessationOfOperation,
	platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD:     RevocationReasonCertificateHold,
	platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN:  RevocationReasonPrivilegeWithdrawn,
}

// Domain-to-proto enum maps

var algorithmToProto = map[KeyAlgorithm]platformv1.KeyAlgorithm{
	KeyAlgorithmUnspecified: platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED,
	KeyAlgorithmRSA2048:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
	KeyAlgorithmRSA3072:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
	KeyAlgorithmRSA4096:    platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096,
	KeyAlgorithmECDSAP256:  platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
	KeyAlgorithmECDSAP384:  platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
	KeyAlgorithmEd25519:    platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519,
}

var statusToProto = map[CertificateStatus]platformv1.CertificateStatus{
	CertificateStatusUnspecified: platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED,
	CertificateStatusValid:       platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
	CertificateStatusRevoked:     platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
	CertificateStatusExpired:     platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
	CertificateStatusPending:     platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING,
}

var reasonToProto = map[RevocationReason]platformv1.RevocationReason{
	RevocationReasonUnspecified:          platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
	RevocationReasonKeyCompromise:        platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
	RevocationReasonCACompromise:         platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE,
	RevocationReasonAffiliationChanged:   platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED,
	RevocationReasonSuperseded:           platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED,
	RevocationReasonCessationOfOperation: platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION,
	RevocationReasonCertificateHold:      platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD,
	RevocationReasonPrivilegeWithdrawn:   platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN,
}

// String-to-domain enum maps (for CLI input parsing)

// StringToKeyAlgorithm maps user-facing key algorithm strings to domain KeyAlgorithm.
var StringToKeyAlgorithm = map[string]KeyAlgorithm{
	"RSA-2048":   KeyAlgorithmRSA2048,
	"RSA-3072":   KeyAlgorithmRSA3072,
	"RSA-4096":   KeyAlgorithmRSA4096,
	"ECDSA-P256": KeyAlgorithmECDSAP256,
	"EC-P256":    KeyAlgorithmECDSAP256,
	"ECDSA-P384": KeyAlgorithmECDSAP384,
	"EC-P384":    KeyAlgorithmECDSAP384,
	"ED25519":    KeyAlgorithmEd25519,
}

// StringToCertificateStatus maps user-facing status strings to domain CertificateStatus.
var StringToCertificateStatus = map[string]CertificateStatus{
	"valid":   CertificateStatusValid,
	"active":  CertificateStatusValid,
	"revoked": CertificateStatusRevoked,
	"expired": CertificateStatusExpired,
	"pending": CertificateStatusPending,
}

// StringToRevocationReason maps user-facing reason strings to domain RevocationReason.
var StringToRevocationReason = map[string]RevocationReason{
	"unspecified":          RevocationReasonUnspecified,
	"key-compromise":       RevocationReasonKeyCompromise,
	"keycompromise":        RevocationReasonKeyCompromise,
	"ca-compromise":        RevocationReasonCACompromise,
	"cacompromise":         RevocationReasonCACompromise,
	"affiliation-changed":  RevocationReasonAffiliationChanged,
	"affiliationchanged":   RevocationReasonAffiliationChanged,
	"superseded":           RevocationReasonSuperseded,
	"cessation":            RevocationReasonCessationOfOperation,
	"cessation-of-operation": RevocationReasonCessationOfOperation,
	"hold":                 RevocationReasonCertificateHold,
	"certificate-hold":     RevocationReasonCertificateHold,
	"privilege-withdrawn":  RevocationReasonPrivilegeWithdrawn,
	"privilegewithdrawn":   RevocationReasonPrivilegeWithdrawn,
}

// ParseKeyAlgorithm parses a user-facing algorithm string to a domain KeyAlgorithm.
// Returns the KeyAlgorithm and true if found, or KeyAlgorithmUnspecified and false otherwise.
func ParseKeyAlgorithm(algorithm string) (KeyAlgorithm, bool) {
	a, ok := StringToKeyAlgorithm[strings.ToUpper(strings.TrimSpace(algorithm))]
	return a, ok
}

// ParseCertificateStatus parses a user-facing status string to a domain CertificateStatus.
// Returns CertificateStatusUnspecified for "all" or empty string.
func ParseCertificateStatus(status string) (CertificateStatus, bool) {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "all" || s == "" {
		return CertificateStatusUnspecified, true
	}
	cs, ok := StringToCertificateStatus[s]
	return cs, ok
}

// ParseRevocationReason parses a user-facing reason string to a domain RevocationReason.
// Returns RevocationReasonUnspecified for empty string.
func ParseRevocationReason(reason string) (RevocationReason, bool) {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return RevocationReasonUnspecified, true
	}
	rr, ok := StringToRevocationReason[r]
	return rr, ok
}

// Proto-to-domain enum converters

// KeyAlgorithmFromProto converts a proto KeyAlgorithm to a domain KeyAlgorithm.
func KeyAlgorithmFromProto(a platformv1.KeyAlgorithm) KeyAlgorithm {
	if ka, ok := protoKeyAlgorithmToAlgorithm[a]; ok {
		return ka
	}
	return KeyAlgorithmUnspecified
}

// CertificateStatusFromProto converts a proto CertificateStatus to a domain CertificateStatus.
func CertificateStatusFromProto(s platformv1.CertificateStatus) CertificateStatus {
	if cs, ok := protoCertStatusToStatus[s]; ok {
		return cs
	}
	return CertificateStatusUnspecified
}

// RevocationReasonFromProto converts a proto RevocationReason to a domain RevocationReason.
func RevocationReasonFromProto(r platformv1.RevocationReason) RevocationReason {
	if rr, ok := protoRevocationReasonToReason[r]; ok {
		return rr
	}
	return RevocationReasonUnspecified
}

// Domain-to-proto enum converters

// KeyAlgorithmToProto converts a domain KeyAlgorithm to a proto KeyAlgorithm.
func KeyAlgorithmToProto(a KeyAlgorithm) platformv1.KeyAlgorithm {
	if pa, ok := algorithmToProto[a]; ok {
		return pa
	}
	return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
}

// CertificateStatusToProto converts a domain CertificateStatus to a proto CertificateStatus.
func CertificateStatusToProto(s CertificateStatus) platformv1.CertificateStatus {
	if ps, ok := statusToProto[s]; ok {
		return ps
	}
	return platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED
}

// RevocationReasonToProto converts a domain RevocationReason to a proto RevocationReason.
func RevocationReasonToProto(r RevocationReason) platformv1.RevocationReason {
	if pr, ok := reasonToProto[r]; ok {
		return pr
	}
	return platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED
}

// Proto-to-domain struct converters

// CAInfoFromProto converts a platformv1.CAInfo to a domain CAInfo.
func CAInfoFromProto(p *platformv1.CAInfo) *CAInfo {
	if p == nil {
		return nil
	}
	info := &CAInfo{
		IsInitialized:    p.IsInitialized,
		CommonName:       p.CommonName,
		IsIntermediate:   p.IsIntermediate,
		DefaultAlgorithm: p.DefaultAlgorithm,
		DefaultValidityDays: p.DefaultValidityDays,
	}
	if p.RootCert != nil {
		info.RootCert = CertificateSummaryFromProto(p.RootCert)
	}
	if len(p.Intermediates) > 0 {
		info.Intermediates = make([]*CertificateSummary, len(p.Intermediates))
		for i, c := range p.Intermediates {
			info.Intermediates[i] = CertificateSummaryFromProto(c)
		}
	}
	if len(p.KeyStores) > 0 {
		info.KeyStores = make([]*KeyStoreInfo, len(p.KeyStores))
		for i, ks := range p.KeyStores {
			info.KeyStores[i] = KeyStoreInfoFromProto(ks)
		}
	}
	return info
}

// CertificateSummaryFromProto converts a platformv1.CertificateSummary to a domain CertificateSummary.
func CertificateSummaryFromProto(p *platformv1.CertificateSummary) *CertificateSummary {
	if p == nil {
		return nil
	}
	return &CertificateSummary{
		Serial:       p.Serial,
		CommonName:   p.CommonName,
		Issuer:       p.Issuer,
		NotBefore:    timestampToTime(p.NotBefore),
		NotAfter:     timestampToTime(p.NotAfter),
		Status:       CertificateStatusFromProto(p.Status),
		KeyAlgorithm: KeyAlgorithmFromProto(p.KeyAlgorithm),
	}
}

// CertificateFromProto converts a platformv1.Certificate to a domain Certificate.
func CertificateFromProto(p *platformv1.Certificate) *Certificate {
	if p == nil {
		return nil
	}
	cert := &Certificate{
		Serial:             p.Serial,
		Issuer:             p.Issuer,
		NotBefore:          timestampToTime(p.NotBefore),
		NotAfter:           timestampToTime(p.NotAfter),
		Status:             CertificateStatusFromProto(p.Status),
		KeyAlgorithm:       KeyAlgorithmFromProto(p.KeyAlgorithm),
		SignatureAlgorithm: p.SignatureAlgorithm,
		IsCa:               p.IsCa,
		FingerprintSha256:  p.FingerprintSha256,
		Pem:                p.Pem,
		Der:                p.Der,
	}
	if p.Subject != nil {
		cert.Subject = &Subject{
			CommonName:   p.Subject.CommonName,
			Organization: p.Subject.Organization,
		}
	}
	return cert
}

// KeyStoreInfoFromProto converts a platformv1.KeyStoreInfo to a domain KeyStoreInfo.
func KeyStoreInfoFromProto(p *platformv1.KeyStoreInfo) *KeyStoreInfo {
	if p == nil {
		return nil
	}
	return &KeyStoreInfo{
		Type:         p.Type,
		Available:    p.Available,
		Capabilities: p.Capabilities,
	}
}

// CRLFromProto converts a platformv1.CRL to a domain CRL.
func CRLFromProto(p *platformv1.CRL) *CRL {
	if p == nil {
		return nil
	}
	crl := &CRL{
		LastUpdate:   timestampToTime(p.LastUpdate),
		NextUpdate:   timestampToTime(p.NextUpdate),
		RevokedCount: p.RevokedCount,
		Data:         p.Data,
	}
	if len(p.RevokedCerts) > 0 {
		crl.RevokedCerts = make([]*RevokedCertEntry, len(p.RevokedCerts))
		for i, e := range p.RevokedCerts {
			crl.RevokedCerts[i] = RevokedCertEntryFromProto(e)
		}
	}
	return crl
}

// RevokedCertEntryFromProto converts a platformv1.RevokedCertEntry to a domain RevokedCertEntry.
func RevokedCertEntryFromProto(p *platformv1.RevokedCertEntry) *RevokedCertEntry {
	if p == nil {
		return nil
	}
	return &RevokedCertEntry{
		Serial:         p.Serial,
		RevocationTime: timestampToTime(p.RevocationTime),
		Reason:         RevocationReasonFromProto(p.Reason),
	}
}

// CABundleFromProto converts a platformv1.CABundle to a domain CABundle.
func CABundleFromProto(p *platformv1.CABundle) *CABundle {
	if p == nil {
		return nil
	}
	bundle := &CABundle{
		Pem:       p.Pem,
		CertCount: p.CertCount,
	}
	if len(p.Certificates) > 0 {
		bundle.Certificates = make([]*CertificateSummary, len(p.Certificates))
		for i, c := range p.Certificates {
			bundle.Certificates[i] = CertificateSummaryFromProto(c)
		}
	}
	return bundle
}

// VerifyCertificateResultFromProto converts a platformv1.VerifyCertificateResponse to a domain VerifyCertificateResult.
func VerifyCertificateResultFromProto(p *platformv1.VerifyCertificateResponse) *VerifyCertificateResult {
	if p == nil {
		return nil
	}
	return &VerifyCertificateResult{
		Valid:    p.Valid,
		Chain:    p.Chain,
		Errors:   p.Errors,
		Warnings: p.Warnings,
	}
}

// Domain-to-proto struct converters

// issueParamsToProto converts IssueCertificateParams to a platformv1.IssueCertificateRequest.
func issueParamsToProto(params *IssueCertificateParams) *platformv1.IssueCertificateRequest {
	certReq := &platformv1.CertificateRequest{
		KeyAlgorithm: KeyAlgorithmToProto(params.KeyAlgorithm),
		StoreType:    params.StoreType,
		ValidDays:    params.ValidDays,
		KeyUsage:     params.KeyUsage,
		ExtKeyUsage:  params.ExtKeyUsage,
	}
	if params.Subject != nil {
		certReq.Subject = &platformv1.Subject{
			CommonName:   params.Subject.CommonName,
			Organization: params.Subject.Organization,
		}
	}
	if params.SANs != nil {
		certReq.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       params.SANs.DNSNames,
			IpAddresses:    params.SANs.IPAddresses,
			EmailAddresses: params.SANs.EmailAddresses,
		}
	}
	return &platformv1.IssueCertificateRequest{Request: certReq}
}

// revokeParamsToProto converts RevokeCertificateParams to a platformv1.RevokeCertificateRequest.
func revokeParamsToProto(params *RevokeCertificateParams) *platformv1.RevokeCertificateRequest {
	return &platformv1.RevokeCertificateRequest{
		Serial:     params.Serial,
		Reason:     RevocationReasonToProto(params.Reason),
		DeleteKeys: params.DeleteKeys,
	}
}

// renewParamsToProto converts RenewCertificateParams to a platformv1.RenewCertificateRequest.
func renewParamsToProto(params *RenewCertificateParams) *platformv1.RenewCertificateRequest {
	req := &platformv1.RenewCertificateRequest{
		Serial:       params.Serial,
		ValidDays:    params.ValidDays,
		PreserveSans: params.PreserveSANs,
	}
	if params.NewSANs != nil {
		req.NewSans = &platformv1.SubjectAlternativeNames{
			DnsNames:       params.NewSANs.DNSNames,
			IpAddresses:    params.NewSANs.IPAddresses,
			EmailAddresses: params.NewSANs.EmailAddresses,
		}
	}
	return req
}

// verifyParamsToProto converts VerifyCertificateParams to a platformv1.VerifyCertificateRequest.
func verifyParamsToProto(params *VerifyCertificateParams) *platformv1.VerifyCertificateRequest {
	return &platformv1.VerifyCertificateRequest{
		CertificatePem:   params.CertificatePEM,
		VerifyRevocation: params.VerifyRevocation,
		VerifyExpiration: params.VerifyExpiration,
	}
}

// listParamsToProto converts ListCertificatesParams to a platformv1.ListCertificatesRequest.
func listParamsToProto(params *ListCertificatesParams) *platformv1.ListCertificatesRequest {
	return &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     params.Page,
			PageSize: params.PageSize,
		},
		StatusFilter: CertificateStatusToProto(params.StatusFilter),
		IssuerFilter: params.IssuerFilter,
	}
}

// timestampToTime converts a protobuf Timestamp to time.Time.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}
