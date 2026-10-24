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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	defaultLimit  int32 = 50
	maxLimit      int32 = 1000
	defaultCursor       = ""

	// contentTypePEM is the MIME type for PEM certificate chains.
	contentTypePEM = "application/pem-certificate-chain"
)

// CAHandlers provides REST handlers for CA operations
type CAHandlers struct {
	logger     *logging.Logger
	ca         quicbaasca.CACertificateAuthority
	respWriter response.HttpWriter
	kms        issuance.KMS
	service    platformv1.CAServiceServer
}

// SignCSRScope is the scope that authorizes certifying a CSR.
// certs:generate, which issues ordinary certificates, does not grant it.
const SignCSRScope = issuance.SignCSRScope

// Scopes the certificate item routes require of a platform token (#452).
// Renewing issues a certificate, so it takes the issuing scope.
const (
	RenewScope  = "certs:generate"
	RevokeScope = "certs:revoke"
	VerifyScope = "certs:read"
)

// NewCAHandlers creates a new CAHandlers instance.
func NewCAHandlers(
	logger *logging.Logger,
	ca quicbaasca.CACertificateAuthority,
	respWriter response.HttpWriter,
) *CAHandlers {
	return &CAHandlers{
		logger:     logger,
		ca:         ca,
		respWriter: respWriter,
	}
}

// WithKMS sets the KMS whose keys SignCSR certifies. Without one,
// POST /api/v1/ca/sign-csr refuses every request.
func (h *CAHandlers) WithKMS(kms issuance.KMS) *CAHandlers {
	h.kms = kms
	return h
}

// WithService sets the CA service that renew and verify call: the one the
// gRPC, Unix and MCP transports serve. Without it those routes answer 503.
func (h *CAHandlers) WithService(service platformv1.CAServiceServer) *CAHandlers {
	h.service = service
	return h
}

// Helper methods

func (h *CAHandlers) getSerial(r *http.Request) string {
	return mux.Vars(r)["serial"]
}

// maxSerialHexDigits bounds a serial in the path: RFC 5280 §4.1.2.2 caps a
// serial number at 20 octets, which is 40 hex digits.
const maxSerialHexDigits = 40

// pathSerial returns the {serial} path variable of an item route, refusing
// one that is empty or is not a hex serial as this CA writes them.
func (h *CAHandlers) pathSerial(r *http.Request) (string, error) {
	serial := h.getSerial(r)
	if serial == "" {
		return "", ErrInvalidSerialNumber{Reason: "serial number is required"}
	}
	if len(serial) > maxSerialHexDigits {
		return "", ErrInvalidSerialNumber{Serial: serial, Reason: "longer than 20 octets"}
	}
	for _, c := range serial {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return "", ErrInvalidSerialNumber{Serial: serial, Reason: "not a hexadecimal serial"}
		}
	}
	return serial, nil
}

func (h *CAHandlers) getPaginationParams(r *http.Request) (int32, string) {
	limit := defaultLimit
	cursor := defaultCursor

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor = c
	}

	return limit, cursor
}

// Algorithm conversion helpers

func (h *CAHandlers) parseKeyAlgorithm(s string) (x509.PublicKeyAlgorithm, error) {
	switch strings.ToUpper(s) {
	case "RSA", "RSA2048", "RSA-2048", "RSA3072", "RSA-3072", "RSA4096", "RSA-4096":
		return x509.RSA, nil
	case "ECDSA", "EC", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "P256", "P384", "P521":
		return x509.ECDSA, nil
	case "ED25519":
		return x509.Ed25519, nil
	case "":
		return x509.ECDSA, nil // Default
	default:
		return 0, ErrInvalidKeyAlgorithm{Algorithm: s}
	}
}

func (h *CAHandlers) keyAlgorithmToString(alg x509.PublicKeyAlgorithm) string {
	switch alg {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

func (h *CAHandlers) signatureAlgorithmToString(alg x509.SignatureAlgorithm) string {
	return alg.String()
}

func (h *CAHandlers) parseStoreType(s string) xkmssdk.StoreType {
	return xkmssdk.ParseStoreType(s)
}

func (h *CAHandlers) parseKeyUsage(usages []string) x509.KeyUsage {
	var keyUsage x509.KeyUsage
	for _, u := range usages {
		switch strings.ToUpper(u) {
		case "DIGITALSIGNATURE", "DIGITAL_SIGNATURE":
			keyUsage |= x509.KeyUsageDigitalSignature
		case "CONTENTCOMMITMENT", "CONTENT_COMMITMENT":
			keyUsage |= x509.KeyUsageContentCommitment
		case "KEYENCIPHERMENT", "KEY_ENCIPHERMENT":
			keyUsage |= x509.KeyUsageKeyEncipherment
		case "DATAENCIPHERMENT", "DATA_ENCIPHERMENT":
			keyUsage |= x509.KeyUsageDataEncipherment
		case "KEYAGREEMENT", "KEY_AGREEMENT":
			keyUsage |= x509.KeyUsageKeyAgreement
		case "CERTSIGN", "CERT_SIGN":
			keyUsage |= x509.KeyUsageCertSign
		case "CRLSIGN", "CRL_SIGN":
			keyUsage |= x509.KeyUsageCRLSign
		case "ENCIPHERONLY", "ENCIPHER_ONLY":
			keyUsage |= x509.KeyUsageEncipherOnly
		case "DECIPHERONLY", "DECIPHER_ONLY":
			keyUsage |= x509.KeyUsageDecipherOnly
		}
	}
	return keyUsage
}

func (h *CAHandlers) parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
	var extKeyUsage []x509.ExtKeyUsage
	for _, u := range usages {
		switch strings.ToUpper(u) {
		case "ANY":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageAny)
		case "SERVERAUTH", "SERVER_AUTH":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
		case "CLIENTAUTH", "CLIENT_AUTH":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
		case "CODESIGNING", "CODE_SIGNING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageCodeSigning)
		case "EMAILPROTECTION", "EMAIL_PROTECTION":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
		case "TIMESTAMPING", "TIME_STAMPING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageTimeStamping)
		case "OCSPSIGNING", "OCSP_SIGNING":
			extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageOCSPSigning)
		}
	}
	return extKeyUsage
}

// keyUsageToStrings serialises a KeyUsage bitmask to the canonical
// SCREAMING_SNAKE_CASE form expected by the proto Certificate.key_usage
// field. Mirrors CAGRPCService.keyUsageToStrings so REST and gRPC
// surfaces emit identical wire shapes.
func (h *CAHandlers) keyUsageToStrings(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DIGITAL_SIGNATURE")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "CONTENT_COMMITMENT")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KEY_ENCIPHERMENT")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DATA_ENCIPHERMENT")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KEY_AGREEMENT")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CERT_SIGN")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL_SIGN")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "ENCIPHER_ONLY")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DECIPHER_ONLY")
	}
	return usages
}

// extKeyUsageToStrings serialises x509 extended key usages to the
// SCREAMING_SNAKE_CASE form expected by the proto Certificate.ext_key_usage
// field. Mirrors CAGRPCService.extKeyUsageToStrings.
func (h *CAHandlers) extKeyUsageToStrings(usages []x509.ExtKeyUsage) []string {
	var result []string
	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageAny:
			result = append(result, "ANY")
		case x509.ExtKeyUsageServerAuth:
			result = append(result, "SERVER_AUTH")
		case x509.ExtKeyUsageClientAuth:
			result = append(result, "CLIENT_AUTH")
		case x509.ExtKeyUsageCodeSigning:
			result = append(result, "CODE_SIGNING")
		case x509.ExtKeyUsageEmailProtection:
			result = append(result, "EMAIL_PROTECTION")
		case x509.ExtKeyUsageTimeStamping:
			result = append(result, "TIME_STAMPING")
		case x509.ExtKeyUsageOCSPSigning:
			result = append(result, "OCSP_SIGNING")
		}
	}
	return result
}

// formatTime renders a time.Time as RFC3339Nano UTC, the wire format
// expected by both protojson (google.protobuf.Timestamp) and the WebUI's
// new Date(...) parser. Zero times render as the empty string so they
// don't confuse downstream consumers that look for a populated value.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// certToSummaryProto mirrors certToSummary but returns the protobuf
// CertificateSummary so handlers that emit protojson responses (GetInfo,
// future GetRoot/GetIntermediate migrations) can reuse the conversion.
func (h *CAHandlers) certToSummaryProto(cert *x509.Certificate) *platformv1.CertificateSummary {
	if cert == nil {
		return nil
	}
	status := platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID
	now := time.Now()
	switch {
	case now.Before(cert.NotBefore):
		status = platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING
	case now.After(cert.NotAfter):
		status = platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	}
	return &platformv1.CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    timestamppb.New(cert.NotBefore),
		NotAfter:     timestamppb.New(cert.NotAfter),
		Status:       status,
		KeyAlgorithm: h.keyAlgorithmToProto(cert.PublicKeyAlgorithm),
	}
}

// keyAlgorithmToProto maps an x509 public-key algorithm to the proto
// KeyAlgorithm enum. The proto enum is keyed by both algorithm and key
// size, but the x509 type only carries the algorithm; we map RSA to its
// most common 2048-bit form and ECDSA to P-256 to match the platform's
// default issuance profile (see CertToSummaryProto callers).
func (h *CAHandlers) keyAlgorithmToProto(alg x509.PublicKeyAlgorithm) platformv1.KeyAlgorithm {
	switch alg {
	case x509.RSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	case x509.ECDSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case x509.Ed25519:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	}
	return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
}

// certStatusToProto computes the proto CertificateStatus based on the
// certificate's validity window. Mirrors CAGRPCService.certStatusToProto.
func (h *CAHandlers) certStatusToProto(cert *x509.Certificate) platformv1.CertificateStatus {
	now := time.Now()
	switch {
	case now.Before(cert.NotBefore):
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING
	case now.After(cert.NotAfter):
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	default:
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID
	}
}

// revocationReasonToProto maps an x509 RFC 5280 reason code to the
// proto RevocationReason enum. Mirrors CAGRPCService.revocationReasonToProto.
func (h *CAHandlers) revocationReasonToProto(reason int) platformv1.RevocationReason {
	switch reason {
	case 1:
		return platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE
	case 2:
		return platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE
	case 3:
		return platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED
	case 4:
		return platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED
	case 5:
		return platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION
	case 6:
		return platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD
	case 8:
		return platformv1.RevocationReason_REVOCATION_REASON_REMOVE_FROM_CRL
	case 9:
		return platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN
	case 10:
		return platformv1.RevocationReason_REVOCATION_REASON_AA_COMPROMISE
	default:
		return platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED
	}
}

// certToProto returns the full proto Certificate representation. Mirrors
// CAGRPCService.certToProto so the REST and gRPC surfaces emit identical
// wire shapes for /api/v1/ca/certificates/* endpoints.
func (h *CAHandlers) certToProto(cert *x509.Certificate, includePEM, includeDER bool) *platformv1.Certificate {
	if cert == nil {
		return nil
	}

	fingerprint := sha256.Sum256(cert.Raw)

	out := &platformv1.Certificate{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: &platformv1.Subject{
			CommonName:         cert.Subject.CommonName,
			Organization:       firstOrEmpty(cert.Subject.Organization),
			OrganizationalUnit: firstOrEmpty(cert.Subject.OrganizationalUnit),
			Country:            firstOrEmpty(cert.Subject.Country),
			Province:           firstOrEmpty(cert.Subject.Province),
			Locality:           firstOrEmpty(cert.Subject.Locality),
			Address:            firstOrEmpty(cert.Subject.StreetAddress),
			PostalCode:         firstOrEmpty(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		Status:             h.certStatusToProto(cert),
		KeyAlgorithm:       h.keyAlgorithmToProto(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCa:               cert.IsCA,
		MaxPathLen:         int32(cert.MaxPathLen),
		KeyUsage:           h.keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        h.extKeyUsageToStrings(cert.ExtKeyUsage),
		FingerprintSha256:  hex.EncodeToString(fingerprint[:]),
	}

	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		out.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
		for _, ip := range cert.IPAddresses {
			out.Sans.IpAddresses = append(out.Sans.IpAddresses, ip.String())
		}
		for _, uri := range cert.URIs {
			out.Sans.Uris = append(out.Sans.Uris, uri.String())
		}
	}

	if includePEM && len(cert.Raw) > 0 {
		out.Pem = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
	if includeDER {
		out.Der = cert.Raw
	}
	return out
}

// Response conversion helpers (legacy flat REST DTOs)

func (h *CAHandlers) certToResponse(cert *x509.Certificate) *CertificateResponse {
	if cert == nil {
		return nil
	}

	status := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		status = "EXPIRED"
	}

	return &CertificateResponse{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: SubjectRequest{
			CommonName:         cert.Subject.CommonName,
			Organization:       firstOrEmpty(cert.Subject.Organization),
			OrganizationalUnit: firstOrEmpty(cert.Subject.OrganizationalUnit),
			Country:            firstOrEmpty(cert.Subject.Country),
			Province:           firstOrEmpty(cert.Subject.Province),
			Locality:           firstOrEmpty(cert.Subject.Locality),
			Address:            firstOrEmpty(cert.Subject.StreetAddress),
			PostalCode:         firstOrEmpty(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          formatTime(cert.NotBefore),
		NotAfter:           formatTime(cert.NotAfter),
		Status:             status,
		KeyAlgorithm:       h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: h.signatureAlgorithmToString(cert.SignatureAlgorithm),
		IsCA:               cert.IsCA,
	}
}

func (h *CAHandlers) certToSummary(cert *x509.Certificate) CertificateSummary {
	if cert == nil {
		return CertificateSummary{}
	}

	status := "VALID"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status = "NOT_YET_VALID"
	} else if now.After(cert.NotAfter) {
		status = "EXPIRED"
	}

	return CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    formatTime(cert.NotBefore),
		NotAfter:     formatTime(cert.NotAfter),
		Status:       status,
		KeyAlgorithm: h.keyAlgorithmToString(cert.PublicKeyAlgorithm),
	}
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// =============================================================================
// CA Information Handlers
// =============================================================================

// GetInfo handles GET /api/v1/ca/info.
//
// The body is the protojson encoding of platformv1.GetCAInfoResponse so
// the Go SDK (which decodes REST responses into proto types) and the JS
// SDK (whose TS types match the proto jsonName form) agree on a single
// wire shape: `{"caInfo": {...}, "timestamp": "RFC3339"}`. The earlier
// flat snake_case Unix-int shape broke the protojson decoder with
// "unexpected token 1778342023" on Timestamp fields and silently dropped
// every other field as unknown.
func (h *CAHandlers) GetInfo(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	caInfo := &platformv1.CAInfo{
		IsInitialized: h.ca.IsInitialized(),
	}

	if h.ca.IsInitialized() {
		caInfo.CommonName = h.ca.Identity()
		caInfo.DefaultAlgorithm = h.keyAlgorithmToString(h.ca.DefaultKeyAlgorithm())
		caInfo.DefaultValidityDays = int32(h.ca.DefaultValidityPeriod())

		if rootCert, err := h.ca.TrustedRoot(); err == nil && rootCert != nil {
			caInfo.RootCert = h.certToSummaryProto(rootCert)
		}

		if intermediateCert, err := h.ca.TrustedIntermediate(); err == nil && intermediateCert != nil {
			caInfo.IsIntermediate = true
			caInfo.Intermediates = append(caInfo.Intermediates, h.certToSummaryProto(intermediateCert))
		}
	}

	protorest.WriteSuccess(w, r, h.respWriter, &platformv1.GetCAInfoResponse{
		CaInfo:    caInfo,
		Timestamp: timestamppb.Now(),
	})
}

// GetRoot handles GET /api/v1/ca/root. Returns the root CA's certificate
// summary as a *platformv1.CertificateSummary.
//
// Note: there is no dedicated GetRoot RPC in ca.proto, so this endpoint
// emits a bare CertificateSummary protojson body. SDK callers that want
// the wrapping envelope can use /api/v1/ca/info instead and read the
// caInfo.rootCert field.
func (h *CAHandlers) GetRoot(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}
	rootCert, err := h.ca.TrustedRoot()
	if err != nil || rootCert == nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.NotFound, ErrCANotInitialized{}.Error()))
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, h.certToSummaryProto(rootCert))
}

// GetIntermediate handles GET /api/v1/ca/intermediate. Returns the
// active intermediate CA's certificate summary as a
// *platformv1.CertificateSummary.
//
// Note: there is no dedicated GetIntermediate RPC in ca.proto, so this
// endpoint emits a bare CertificateSummary protojson body. SDK callers
// that want the wrapping envelope can use /api/v1/ca/info instead.
func (h *CAHandlers) GetIntermediate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}
	intermediateCert, err := h.ca.TrustedIntermediate()
	if err != nil || intermediateCert == nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.NotFound, ErrCANotInitialized{}.Error()))
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, h.certToSummaryProto(intermediateCert))
}

// =============================================================================
// Certificate Management Handlers
// =============================================================================

// ListCertificates handles GET /api/v1/ca/certificates.
//
// Emits platformv1.ListCertificatesResponse so the Go SDK can decode the
// response into proto types without tripping on Timestamp string-vs-int
// mismatches. The certificate slice always includes the trust anchors
// (root + intermediate) at the top and then enumerates everything in the
// CA's certificate store.
func (h *CAHandlers) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	limit, _ := h.getPaginationParams(r)

	certStore := h.ca.CertStore()
	if certStore == nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.FailedPrecondition, "certificate store not available"))
		return
	}

	var certificates []*platformv1.CertificateSummary
	seen := make(map[string]struct{})

	addCert := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		key := hex.EncodeToString(c.SerialNumber.Bytes())
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		certificates = append(certificates, h.certToSummaryProto(c))
	}

	if rootCert, err := h.ca.TrustedRoot(); err == nil {
		addCert(rootCert)
	}
	if intermediateCert, err := h.ca.TrustedIntermediate(); err == nil {
		addCert(intermediateCert)
	}

	// Fan out to the underlying certificate store for issued leaf certs.
	type listAll interface {
		ListCertificates() ([]*x509.Certificate, error)
	}
	if l, ok := certStore.(listAll); ok {
		if all, err := l.ListCertificates(); err == nil {
			for _, c := range all {
				addCert(c)
			}
		}
	}

	totalItems := uint64(len(certificates))
	if int32(len(certificates)) > limit {
		certificates = certificates[:limit]
	}
	pageSize := uint32(limit)
	totalPages := uint32(0)
	if pageSize > 0 {
		totalPages = uint32((totalItems + uint64(pageSize) - 1) / uint64(pageSize))
	}

	protorest.WriteSuccess(w, r, h.respWriter, &platformv1.ListCertificatesResponse{
		Certificates: certificates,
		Pagination: &platformv1.PaginationResponse{
			Page:       1,
			PageSize:   pageSize,
			TotalPages: totalPages,
			TotalItems: totalItems,
		},
		Timestamp: timestamppb.Now(),
	})
}

// GetCertificate handles GET /api/v1/ca/certificates/{serial}.
//
// Emits platformv1.GetCertificateResponse with proto Timestamp fields.
// The optional ?include_pem=true / ?include_der=true query parameters
// hydrate the corresponding bytes fields on the embedded Certificate.
func (h *CAHandlers) GetCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	serial := h.getSerial(r)
	if serial == "" {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.InvalidArgument, ErrInvalidSerialNumber{Reason: "serial number is required"}.Error()))
		return
	}

	includePEM, err := protorest.QueryBool(r, "include_pem")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	includeDER, err := protorest.QueryBool(r, "include_der")
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	respond := func(cert *x509.Certificate) {
		protorest.WriteSuccess(w, r, h.respWriter, &platformv1.GetCertificateResponse{
			Certificate: h.certToProto(cert, includePEM, includeDER),
			Timestamp:   timestamppb.Now(),
		})
	}

	if rootCert, rerr := h.ca.TrustedRoot(); rerr == nil && rootCert != nil {
		if hex.EncodeToString(rootCert.SerialNumber.Bytes()) == serial {
			respond(rootCert)
			return
		}
	}

	if intermediateCert, ierr := h.ca.TrustedIntermediate(); ierr == nil && intermediateCert != nil {
		if hex.EncodeToString(intermediateCert.SerialNumber.Bytes()) == serial {
			respond(intermediateCert)
			return
		}
	}

	if certStore := h.ca.CertStore(); certStore != nil {
		if cert, lookupErr := certStore.GetCertificate(serial); lookupErr == nil && cert != nil {
			respond(cert)
			return
		}
	}

	protorest.WriteError(w, r, h.respWriter,
		status.Error(codes.NotFound, ErrCertificateNotFound{Serial: serial}.Error()))
}

// IssueCertificate handles POST /api/v1/ca/certificates.
//
// Decodes platformv1.IssueCertificateRequest and emits
// platformv1.IssueCertificateResponse. Status is 201 Created on success.
//
// TODO: the proto IssueCertificateRequest does not yet carry an explicit
// `is_ca` -> CertificateType mapping for path-len constraints; the legacy
// REST DTO accepted is_ca / max_path_len directly. Both representations
// are still supported by the handler because the proto CertificateRequest
// includes is_ca + max_path_len fields.
func (h *CAHandlers) IssueCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	req := &platformv1.IssueCertificateRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	certReq := req.GetRequest()
	if certReq == nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.InvalidArgument, "certificate request is required"))
		return
	}
	subject := certReq.GetSubject()
	if subject == nil || subject.GetCommonName() == "" {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.InvalidArgument, ErrMissingCommonName{}.Error()))
		return
	}

	keyAlg, err := h.protoKeyAlgorithmToX509(certReq.GetKeyAlgorithm())
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.InvalidArgument, err.Error()))
		return
	}

	caReq := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:         subject.GetCommonName(),
			Organization:       subject.GetOrganization(),
			OrganizationalUnit: subject.GetOrganizationalUnit(),
			Country:            subject.GetCountry(),
			Province:           subject.GetProvince(),
			Locality:           subject.GetLocality(),
			Address:            subject.GetAddress(),
			PostalCode:         subject.GetPostalCode(),
		},
		Valid:       int(certReq.GetValidDays()),
		IsCA:        certReq.GetIsCa(),
		MaxPathLen:  int(certReq.GetMaxPathLen()),
		KeyUsage:    h.parseKeyUsage(certReq.GetKeyUsage()),
		ExtKeyUsage: h.parseExtKeyUsage(certReq.GetExtKeyUsage()),
	}

	if sans := certReq.GetSans(); sans != nil {
		caReq.SANS = &quicbaasca.CASubjectAlternativeNames{
			DNS:   sans.GetDnsNames(),
			IPs:   sans.GetIpAddresses(),
			Email: sans.GetEmailAddresses(),
			URIs:  sans.GetUris(),
		}
	}

	storeType, err := issuance.StoreType(certReq.GetStoreType())
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.InvalidArgument, err.Error()))
		return
	}

	caReq.KeyAttributes = &xkmssdk.KeyAttributes{
		CN:           subject.GetCommonName(),
		KeyAlgorithm: keyAlg,
		StoreType:    storeType,
		KeyType:      xkmssdk.KeyTypeTLS,
	}

	issued, err := h.ca.IssueCertificate(r.Context(), caReq)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.Internal, ErrInvalidCertificateRequest{Reason: err.Error()}.Error()))
		return
	}
	h.writeIssued(w, r, issued.Certificate)
}

// SignCSR handles POST /api/v1/ca/sign-csr. It certifies, for code signing
// only, the KMS key a CSR names — a key the CA never holds.
//
// The route is admin-gated like the rest of /ca/certificates, and the
// handler additionally requires a platform token carrying ca:sign-csr: a
// session with no token scopes, or a token holding only ca:write, is
// refused before the request body is read.
func (h *CAHandlers) SignCSR(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}
	if err := requireSignCSRScope(r); err != nil {
		h.respWriter.Error403(w, r, err, nil)
		return
	}

	req := &platformv1.SignCSRRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	cert, err := issuance.SignCSR(r.Context(), h.ca, h.kms, &issuance.CSR{
		PEM:       []byte(req.GetCsrPem()),
		ValidDays: int(req.GetValidDays()),
	})
	if err != nil {
		code := codes.Internal
		if issuance.IsInvalidRequest(err) {
			code = codes.InvalidArgument
		}
		protorest.WriteError(w, r, h.respWriter, status.Error(code, err.Error()))
		return
	}
	h.writeIssued(w, r, cert)
}

// requireSignCSRScope requires that the request carries a platform token
// granted SignCSRScope.
func requireSignCSRScope(r *http.Request) error {
	authCtx, ok := iammw.AuthorizedContextFromRequest(r)
	if !ok {
		return ErrSignCSRScopeRequired{}
	}
	if err := authCtx.RequireScope(SignCSRScope); err != nil {
		return ErrSignCSRScopeRequired{Cause: err}
	}
	return nil
}

// writeIssued answers a request with the certificate it issued.
func (h *CAHandlers) writeIssued(w http.ResponseWriter, r *http.Request, cert *x509.Certificate) {
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, &platformv1.IssueCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate issued successfully",
		},
		Certificate: h.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	})
}

// protoKeyAlgorithmToX509 converts the proto KeyAlgorithm enum back to
// an x509 PublicKeyAlgorithm. UNSPECIFIED defaults to ECDSA to match the
// CA's default issuance profile.
func (h *CAHandlers) protoKeyAlgorithmToX509(alg platformv1.KeyAlgorithm) (x509.PublicKeyAlgorithm, error) {
	switch alg {
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED:
		return x509.ECDSA, nil
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_3072,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:
		return x509.RSA, nil
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:
		return x509.ECDSA, nil
	case platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519:
		return x509.Ed25519, nil
	default:
		return 0, ErrInvalidKeyAlgorithm{Algorithm: alg.String()}
	}
}

// RevokeCertificate handles DELETE /api/v1/ca/certificates/{serial}.
//
// Decodes platformv1.RevokeCertificateRequest from the optional body
// (the serial is taken from the URL path and overrides any value in the
// body) and emits platformv1.RevokeCertificateResponse on success.
func (h *CAHandlers) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	serial, err := h.pathSerial(r)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, status.Error(codes.InvalidArgument, err.Error()))
		return
	}

	req := &platformv1.RevokeCertificateRequest{}
	if r.Body != nil && r.ContentLength > 0 {
		if err := protorest.DecodeRequest(r, req); err != nil {
			h.respWriter.Error400(w, r, err)
			return
		}
	}
	req.Serial = serial

	var cert *x509.Certificate
	if certStore := h.ca.CertStore(); certStore != nil {
		if foundCert, err := certStore.GetCertificate(serial); err == nil {
			cert = foundCert
		}
	}
	if cert == nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.NotFound, ErrCertificateNotFound{Serial: serial}.Error()))
		return
	}

	if err := h.ca.RevokeCert(r.Context(), cert, quicbaasca.RevokeOptions{DeleteKeys: req.GetDeleteKeys()}); err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.Internal, err.Error()))
		return
	}

	now := timestamppb.Now()
	protorest.WriteSuccess(w, r, h.respWriter, &platformv1.RevokeCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate revoked successfully",
		},
		Serial:            serial,
		CertificateStatus: platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		RevokedAt:         now,
		Reason:            req.GetReason(),
		Timestamp:         now,
	})
}

// RenewCertificate handles POST /api/v1/ca/certificates/{serial}/renew.
// The serial comes from the path; valid_days, preserve_sans and new_sans
// from the RenewCertificateRequest body. The CA service does the work.
func (h *CAHandlers) RenewCertificate(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	serial, err := h.pathSerial(r)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, status.Error(codes.InvalidArgument, err.Error()))
		return
	}

	req := &platformv1.RenewCertificateRequest{}
	if r.Body != nil && r.ContentLength > 0 {
		if err := protorest.DecodeRequest(r, req); err != nil {
			protorest.WriteError(w, r, h.respWriter, status.Error(codes.InvalidArgument, err.Error()))
			return
		}
	}
	req.Serial = serial

	resp, err := h.service.RenewCertificate(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// VerifyCertificate handles POST /api/v1/ca/certificates/verify. The
// certificate travels in the VerifyCertificateRequest body as PEM or DER;
// there is no serial, since the certificate need not be one this CA issued.
func (h *CAHandlers) VerifyCertificate(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	req := &platformv1.VerifyCertificateRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		protorest.WriteError(w, r, h.respWriter, status.Error(codes.InvalidArgument, err.Error()))
		return
	}

	resp, err := h.service.VerifyCertificate(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// =============================================================================
// CA Bundle Handlers
// =============================================================================

// GetBundle handles GET /api/v1/ca/bundle.
//
// Emits platformv1.GetCABundleResponse with the PEM bundle bytes plus a
// list of CertificateSummary entries. The optional ?store_type / ?algorithm
// query parameters delegate to CABundleFiltered() when either is set;
// otherwise the unfiltered CABundle() is used to avoid an upstream issue
// where CABundleFiltered() returns "no certificates match filter" when
// both filters are zero-valued.
func (h *CAHandlers) GetBundle(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	storeTypeStr := r.URL.Query().Get("store_type")
	algorithmStr := r.URL.Query().Get("algorithm")

	storeType := xkmssdk.StoreUnknown
	if storeTypeStr != "" {
		storeType = h.parseStoreType(storeTypeStr)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if algorithmStr != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(algorithmStr)
		if err != nil {
			protorest.WriteError(w, r, h.respWriter,
				status.Error(codes.InvalidArgument, err.Error()))
			return
		}
	}

	var bundle []byte
	var err error
	if (storeType == "" || storeType == xkmssdk.StoreUnknown) && keyAlg == x509.UnknownPublicKeyAlgorithm {
		bundle, err = h.ca.CABundle()
	} else {
		bundle, err = h.ca.CABundleFiltered(storeType, keyAlg)
	}
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.Internal, err.Error()))
		return
	}
	if len(bundle) == 0 {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.NotFound, ErrBundleNotFound{}.Error()))
		return
	}

	var certificates []*platformv1.CertificateSummary
	if certs, perr := h.ca.ParseBundle(bundle); perr == nil {
		for _, cert := range certs {
			certificates = append(certificates, h.certToSummaryProto(cert))
		}
	}

	protorest.WriteSuccess(w, r, h.respWriter, &platformv1.GetCABundleResponse{
		Bundle: &platformv1.CABundle{
			Pem:          bundle,
			Certificates: certificates,
			CertCount:    int32(len(certificates)),
		},
		Timestamp: timestamppb.Now(),
	})
}

// =============================================================================
// Bootstrap Handlers
// =============================================================================

// GetBootstrapBundle handles GET /api/v1/ca/bootstrap. It returns the CA
// certificate bundle as raw PEM text for unauthenticated trust bootstrapping.
// Optional query parameters store_type and algorithm filter the bundle.
//
// This endpoint intentionally bypasses the protorest envelope: the body is
// raw PEM bytes (Content-Type: application/pem-certificate-chain) so the
// installer can pipe it directly into a trust store without JSON parsing.
func (h *CAHandlers) GetBootstrapBundle(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		http.Error(w, ErrCANotInitialized{}.Error(), http.StatusServiceUnavailable)
		return
	}

	storeTypeStr := r.URL.Query().Get("store_type")
	algorithmStr := r.URL.Query().Get("algorithm")

	storeType := xkmssdk.StoreUnknown
	if storeTypeStr != "" {
		storeType = h.parseStoreType(storeTypeStr)
	}

	var keyAlg x509.PublicKeyAlgorithm
	if algorithmStr != "" {
		var err error
		keyAlg, err = h.parseKeyAlgorithm(algorithmStr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	var bundle []byte
	var err error
	if (storeType == "" || storeType == xkmssdk.StoreUnknown) && keyAlg == x509.UnknownPublicKeyAlgorithm {
		bundle, err = h.ca.CABundle()
	} else {
		bundle, err = h.ca.CABundleFiltered(storeType, keyAlg)
	}
	if err != nil {
		http.Error(w, ErrBootstrapBundleFailed{Cause: err}.Error(), http.StatusInternalServerError)
		return
	}

	if len(bundle) == 0 {
		http.Error(w, ErrBundleNotFound{}.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", contentTypePEM)
	w.WriteHeader(http.StatusOK)
	w.Write(bundle) // #nosec G705 -- PEM certificate data, not HTML; Content-Type prevents browser rendering
}

// =============================================================================
// CRL Handlers
// =============================================================================

// GetCRL handles GET /api/v1/ca/crl.
//
// Emits platformv1.GetCRLResponse on success. CRL generation is part of the
// quicbaasca.CACertificateAuthority surface (via TrustedCA.GenerateCRL), so
// the handler invokes it directly and returns HTTP 500 on failure.
func (h *CAHandlers) GetCRL(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		protorest.WriteError(w, r, h.respWriter,
			&protorest.ErrServiceUnavailable{Service: "ca"})
		return
	}

	crlDER, err := h.ca.GenerateCRL(r.Context())
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.Internal, ErrCRLGenerationFailed{Reason: err.Error()}.Error()))
		return
	}

	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter,
			status.Error(codes.Internal, ErrCRLGenerationFailed{Reason: err.Error()}.Error()))
		return
	}

	revokedCerts := make([]*platformv1.RevokedCertEntry, 0, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		revokedCerts = append(revokedCerts, &platformv1.RevokedCertEntry{
			Serial:         hex.EncodeToString(entry.SerialNumber.Bytes()),
			RevocationTime: timestamppb.New(entry.RevocationTime),
			Reason:         h.revocationReasonToProto(entry.ReasonCode),
		})
	}

	protorest.WriteSuccess(w, r, h.respWriter, &platformv1.GetCRLResponse{
		Crl: &platformv1.CRL{
			Data:         crlDER,
			LastUpdate:   timestamppb.New(crl.ThisUpdate),
			NextUpdate:   timestamppb.New(crl.NextUpdate),
			RevokedCount: int32(len(crl.RevokedCertificateEntries)),
			RevokedCerts: revokedCerts,
		},
		Timestamp: timestamppb.Now(),
	})
}
