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

// PaginationParams contains common pagination parameters
type PaginationParams struct {
	Limit  int32  `json:"limit"`
	Cursor string `json:"cursor,omitempty"`
}

// PaginatedResponse contains common pagination response fields
type PaginatedResponse struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
	TotalCount int32  `json:"total_count,omitempty"`
}

// SubjectRequest contains certificate subject information
type SubjectRequest struct {
	CommonName         string `json:"common_name"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Address            string `json:"address,omitempty"`
	PostalCode         string `json:"postal_code,omitempty"`
}

// SANsRequest contains Subject Alternative Names
type SANsRequest struct {
	DNS   []string `json:"dns,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	Email []string `json:"email,omitempty"`
	URIs  []string `json:"uris,omitempty"`
}

// CertificateIssueRequest is the request body for issuing a certificate
type CertificateIssueRequest struct {
	Subject      SubjectRequest `json:"subject"`
	SANs         *SANsRequest   `json:"sans,omitempty"`
	ValidDays    int            `json:"valid_days,omitempty"`
	KeyAlgorithm string         `json:"key_algorithm,omitempty"`
	StoreType    string         `json:"store_type,omitempty"`
	KeyUsage     []string       `json:"key_usage,omitempty"`
	ExtKeyUsage  []string       `json:"ext_key_usage,omitempty"`
	IsCA         bool           `json:"is_ca,omitempty"`
	MaxPathLen   int            `json:"max_path_len,omitempty"`
}

// CertificateRevokeRequest is the request body for revoking a certificate
type CertificateRevokeRequest struct {
	Reason     int  `json:"reason,omitempty"`
	DeleteKeys bool `json:"delete_keys,omitempty"`
}

// CertificateResponse represents a certificate in responses.
//
// Timestamps are RFC3339Nano strings rather than Unix-seconds integers so
// that the protojson-based Go SDK (which decodes responses into proto
// types whose timestamp fields are google.protobuf.Timestamp) and the
// WebUI's `new Date(...)` parser both accept them as-is.
type CertificateResponse struct {
	Serial             string         `json:"serial"`
	Subject            SubjectRequest `json:"subject"`
	Issuer             string         `json:"issuer"`
	NotBefore          string         `json:"not_before"`
	NotAfter           string         `json:"not_after"`
	Status             string         `json:"status"`
	KeyAlgorithm       string         `json:"key_algorithm"`
	SignatureAlgorithm string         `json:"signature_algorithm"`
	IsCA               bool           `json:"is_ca"`
	PEM                string         `json:"pem,omitempty"`
}

// CertificateSummary contains a summary of a certificate for list responses.
// Timestamps are RFC3339Nano strings — see CertificateResponse for rationale.
type CertificateSummary struct {
	Serial       string `json:"serial"`
	CommonName   string `json:"common_name"`
	Issuer       string `json:"issuer"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Status       string `json:"status"`
	KeyAlgorithm string `json:"key_algorithm"`
}

// CertificateListResponse is the response for listing certificates
type CertificateListResponse struct {
	PaginatedResponse
	Certificates []CertificateSummary `json:"certificates"`
	Timestamp    string               `json:"timestamp"`
}

// GetCertificateResponse is the response for getting a certificate
type GetCertificateResponse struct {
	Certificate *CertificateResponse `json:"certificate"`
	Timestamp   string               `json:"timestamp"`
}

// IssueCertificateResponse is the response for issuing a certificate
type IssueCertificateResponse struct {
	Certificate *CertificateResponse `json:"certificate"`
	Timestamp   string               `json:"timestamp"`
}

// RevokeCertificateResponse is the response for revoking a certificate
type RevokeCertificateResponse struct {
	Serial    string `json:"serial"`
	Status    string `json:"status"`
	RevokedAt string `json:"revoked_at"`
	Reason    int    `json:"reason"`
	Timestamp string `json:"timestamp"`
}

// KeyStoreInfo contains information about a key store
type KeyStoreInfo struct {
	Type         string   `json:"type"`
	Available    bool     `json:"available"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// CAInfoResponse contains CA information
type CAInfoResponse struct {
	CommonName       string               `json:"common_name"`
	IsInitialized    bool                 `json:"is_initialized"`
	IsIntermediate   bool                 `json:"is_intermediate"`
	RootCert         *CertificateSummary  `json:"root_cert,omitempty"`
	Intermediates    []CertificateSummary `json:"intermediates,omitempty"`
	KeyStores        []KeyStoreInfo       `json:"key_stores,omitempty"`
	DefaultAlgorithm string               `json:"default_algorithm,omitempty"`
	DefaultValidity  int                  `json:"default_validity_days,omitempty"`
	Timestamp        string               `json:"timestamp"`
}

// RevokedCertEntry represents a revoked certificate entry
type RevokedCertEntry struct {
	Serial         string `json:"serial"`
	RevocationTime string `json:"revocation_time"`
	Reason         int    `json:"reason"`
}

// CRLResponse contains CRL information
type CRLResponse struct {
	CRL          []byte             `json:"crl"`
	LastUpdate   string             `json:"last_update"`
	NextUpdate   string             `json:"next_update"`
	RevokedCount int                `json:"revoked_count"`
	RevokedCerts []RevokedCertEntry `json:"revoked_certs,omitempty"`
	Timestamp    string             `json:"timestamp"`
}

// BundleResponse contains CA bundle information
type BundleResponse struct {
	Bundle       []byte               `json:"bundle"`
	Certificates []CertificateSummary `json:"certificates,omitempty"`
	CertCount    int                  `json:"cert_count"`
	Timestamp    string               `json:"timestamp"`
}

// SuccessResponse is a generic success response
type SuccessResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}
