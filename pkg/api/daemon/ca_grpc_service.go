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

package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	caDefaultPageSize uint32 = 50
	caMaxPageSize     uint32 = 1000
)

// ErrCANotInitialized is the FailedPrecondition every CA call answers when
// the node has no certificate authority loaded.
type ErrCANotInitialized struct{}

// Error implements the error interface.
func (ErrCANotInitialized) Error() string {
	return "certificate authority not initialized"
}

// CAGRPCService implements the CA gRPC service for certificate authority operations.
type CAGRPCService struct {
	platformv1.UnimplementedCAServiceServer

	logger     *logging.Logger
	ca         quicbaasca.CACertificateAuthority
	objStorage objectstorage.Client
	// kms holds the keys SignCSR certifies; without it SignCSR fails closed.
	kms issuance.KMS
}

// WithKMS sets the KMS whose keys SignCSR certifies, and returns s.
func (s *CAGRPCService) WithKMS(kms issuance.KMS) *CAGRPCService {
	s.kms = kms
	return s
}

// TrustAnchor exposes the CA behind this service as the trust anchor for
// device attestation certificates. It returns nil when no CA is wired so the
// verifier fails closed instead of chaining against nothing.
func (s *CAGRPCService) TrustAnchor() AKTrustAnchor {
	if s == nil || s.ca == nil {
		return nil
	}
	return s.ca
}

// NewCAGRPCService creates a new CA gRPC service instance.
func NewCAGRPCService(logger *logging.Logger, ca quicbaasca.CACertificateAuthority, objStorage objectstorage.Client) *CAGRPCService {
	return &CAGRPCService{
		logger:     logger,
		ca:         ca,
		objStorage: objStorage,
	}
}

// GetCAInfo returns CA certificate information.
func (s *CAGRPCService) GetCAInfo(ctx context.Context, req *platformv1.GetCAInfoRequest) (*platformv1.GetCAInfoResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	now := timestamppb.Now()

	caInfo := &platformv1.CAInfo{
		IsInitialized: s.ca.IsInitialized(),
	}

	if s.ca.IsInitialized() {
		caInfo.CommonName = s.ca.Identity()
		caInfo.DefaultAlgorithm = s.keyAlgorithmToString(s.ca.DefaultKeyAlgorithm())
		caInfo.DefaultValidityDays = int32(s.ca.DefaultValidityPeriod())

		// Get root certificate info
		rootCert, err := s.ca.TrustedRoot()
		if err == nil && rootCert != nil {
			caInfo.RootCert = s.certToSummaryProto(rootCert)
		}

		// Get intermediate certificate info
		intermediateCert, err := s.ca.TrustedIntermediate()
		if err == nil && intermediateCert != nil {
			caInfo.IsIntermediate = true
			caInfo.Intermediates = append(caInfo.Intermediates, s.certToSummaryProto(intermediateCert))
		}
	}

	return &platformv1.GetCAInfoResponse{
		CaInfo:    caInfo,
		Timestamp: now,
	}, nil
}

// IssueCertificate issues a new certificate.
func (s *CAGRPCService) IssueCertificate(ctx context.Context, req *platformv1.IssueCertificateRequest) (*platformv1.IssueCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	certReq := req.GetRequest()
	if certReq == nil {
		return nil, status.Error(codes.InvalidArgument, "certificate request is required")
	}

	subject := certReq.GetSubject()
	if subject == nil || subject.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, "common name is required")
	}

	// Build certificate request
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
		KeyUsage:    s.parseKeyUsage(certReq.GetKeyUsage()),
		ExtKeyUsage: s.parseExtKeyUsage(certReq.GetExtKeyUsage()),
	}

	// Add SANs if provided
	sans := certReq.GetSans()
	if sans != nil {
		caReq.SANS = &quicbaasca.CASubjectAlternativeNames{
			DNS:   sans.GetDnsNames(),
			IPs:   sans.GetIpAddresses(),
			Email: sans.GetEmailAddresses(),
			URIs:  sans.GetUris(),
		}
	}

	// Set key attributes
	storeType, err := issuance.StoreType(certReq.GetStoreType())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	caReq.KeyAttributes, err = issuance.KeyAttributes(certReq.GetKeyAlgorithm(), subject.GetCommonName(), storeType)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Issue the certificate
	issued, err := s.ca.IssueCertificate(ctx, caReq)
	if err != nil {
		s.logger.Error(err, "failed to issue certificate")
		return nil, status.Error(codes.Internal, "failed to issue certificate: "+err.Error())
	}

	cert := issued.Certificate
	return &platformv1.IssueCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate issued successfully",
		},
		Certificate: s.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// SignCSR certifies a KMS key for code signing from a CSR the KMS signed.
// The method is authorized by its own scope, ca:sign-csr, which ca:write
// does not grant; issuance.SignCSR decides which CSRs are certified.
func (s *CAGRPCService) SignCSR(ctx context.Context, req *platformv1.SignCSRRequest) (*platformv1.IssueCertificateResponse, error) {
	if err := grpcapi.AuthorizeSignCSR(ctx); err != nil {
		return nil, err
	}
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}
	cert, err := issuance.SignCSR(ctx, s.ca, s.kms, &issuance.CSR{
		PEM:       []byte(req.GetCsrPem()),
		ValidDays: int(req.GetValidDays()),
	})
	if err != nil {
		if issuance.IsInvalidRequest(err) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		s.logger.Error(err, "failed to sign CSR")
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &platformv1.IssueCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate issued successfully",
		},
		Certificate: s.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// GetCertificate retrieves a certificate by serial number or common name.
// The serial field accepts either a hex-encoded serial number or a common name.
func (s *CAGRPCService) GetCertificate(ctx context.Context, req *platformv1.GetCertificateRequest) (*platformv1.GetCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	identifier := req.GetSerial()
	if identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	cert := s.findCertByIdentifier(identifier)
	if cert != nil {
		return &platformv1.GetCertificateResponse{
			Certificate: s.certToProto(cert, req.GetIncludePem(), req.GetIncludeDer()),
			Timestamp:   timestamppb.Now(),
		}, nil
	}

	return nil, status.Error(codes.NotFound, "certificate not found: "+identifier)
}

// ListCertificates lists certificates with pagination.
func (s *CAGRPCService) ListCertificates(ctx context.Context, req *platformv1.ListCertificatesRequest) (*platformv1.ListCertificatesResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	pagination := req.GetPagination()
	pageSize := caDefaultPageSize
	if pagination != nil && pagination.GetPageSize() > 0 {
		pageSize = pagination.GetPageSize()
	}
	if pageSize > caMaxPageSize {
		pageSize = caMaxPageSize
	}

	certStore := s.ca.CertStore()
	if certStore == nil {
		return nil, status.Error(codes.FailedPrecondition, "certificate store not available")
	}

	// Collect certificates (root and intermediate for now)
	var certificates []*platformv1.CertificateSummary

	rootCert, err := s.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		certificates = append(certificates, s.certToSummaryProto(rootCert))
	}

	intermediateCert, err := s.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		certificates = append(certificates, s.certToSummaryProto(intermediateCert))
	}

	// Get certificates from cert store
	certs, listErr := certStore.ListCertificates()
	if listErr == nil {
		for _, cert := range certs {
			certificates = append(certificates, s.certToSummaryProto(cert))
		}
	}

	// Apply pagination
	totalItems := uint64(len(certificates))
	totalPages := uint32((totalItems + uint64(pageSize) - 1) / uint64(pageSize))
	if uint32(len(certificates)) > pageSize {
		certificates = certificates[:pageSize]
	}

	return &platformv1.ListCertificatesResponse{
		Certificates: certificates,
		Pagination: &platformv1.PaginationResponse{
			Page:       1,
			PageSize:   pageSize,
			TotalPages: totalPages,
			TotalItems: totalItems,
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// RevokeCertificate revokes a certificate.
func (s *CAGRPCService) RevokeCertificate(ctx context.Context, req *platformv1.RevokeCertificateRequest) (*platformv1.RevokeCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	serial := req.GetSerial()
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}
	if err := issuance.ValidateRevocationReason(int(req.GetReason())); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Find the certificate by serial or common name
	cert := s.findCertByIdentifier(serial)
	if cert == nil {
		return nil, status.Error(codes.NotFound, "certificate not found: "+serial)
	}

	// Set up key attributes for deletion if requested
	var keyAttrs *xkmssdk.KeyAttributes
	if req.GetDeleteKeys() {
		keyAttrs = &xkmssdk.KeyAttributes{
			CN: cert.Subject.CommonName,
		}
	}

	// Revoke the certificate
	if err := s.ca.RevokeCert(ctx, cert, quicbaasca.RevokeOptions{Reason: int(req.GetReason()), DeleteKeys: keyAttrs != nil}); err != nil {
		s.logger.Error(err, "failed to revoke certificate")
		return nil, status.Error(codes.Internal, "failed to revoke certificate: "+err.Error())
	}

	now := timestamppb.Now()
	return &platformv1.RevokeCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate revoked successfully",
		},
		Serial:            serial,
		CertificateStatus: platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		RevokedAt:         now,
		Reason:            req.GetReason(),
		Timestamp:         now,
	}, nil
}

// RenewCertificate renews an existing certificate with extended validity.
func (s *CAGRPCService) RenewCertificate(ctx context.Context, req *platformv1.RenewCertificateRequest) (*platformv1.RenewCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	serial := req.GetSerial()
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument, "serial number is required")
	}

	validDays := req.GetValidDays()
	if validDays <= 0 {
		return nil, status.Error(codes.InvalidArgument, "valid_days must be positive")
	}

	// Find the existing certificate by serial or common name
	existingCert := s.findCertByIdentifier(serial)
	if existingCert == nil {
		return nil, status.Error(codes.NotFound, "certificate not found: "+serial)
	}

	renewOpts := issuance.RenewOptions{
		ValidDays:    int(validDays),
		PreserveSANs: req.GetPreserveSans(),
	}
	if newSans := req.GetNewSans(); newSans != nil {
		renewOpts.NewSANs = &quicbaasca.CASubjectAlternativeNames{
			DNS:   newSans.GetDnsNames(),
			IPs:   newSans.GetIpAddresses(),
			Email: newSans.GetEmailAddresses(),
			URIs:  newSans.GetUris(),
		}
	}

	newCert, err := issuance.Renew(ctx, s.ca, existingCert, renewOpts)
	if err != nil {
		s.logger.Error(err, "failed to renew certificate")
		var storesErr *issuance.RenewStoresUnavailableError
		if errors.As(err, &storesErr) {
			return nil, status.Error(codes.FailedPrecondition, "failed to renew certificate: "+err.Error())
		}
		return nil, status.Error(codes.Internal, "failed to renew certificate: "+err.Error())
	}

	return &platformv1.RenewCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "certificate renewed successfully",
		},
		OldCertificate: s.certToProto(existingCert, false, false),
		NewCertificate: s.certToProto(newCert, true, false),
		Timestamp:      timestamppb.Now(),
	}, nil
}

// VerifyCertificate verifies a certificate against the CA bundle.
func (s *CAGRPCService) VerifyCertificate(ctx context.Context, req *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	certPem := req.GetCertificatePem()
	certDer := req.GetCertificateDer()
	if len(certPem) == 0 && len(certDer) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate (PEM or DER) is required")
	}

	// Parse the certificate to verify
	var cert *x509.Certificate
	var err error

	if len(certDer) > 0 {
		cert, err = x509.ParseCertificate(certDer)
	} else {
		block, _ := pem.Decode(certPem)
		if block == nil {
			return nil, status.Error(codes.InvalidArgument, "failed to decode PEM certificate")
		}
		cert, err = x509.ParseCertificate(block.Bytes)
	}

	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "failed to parse certificate: "+err.Error())
	}

	// Build verification pool from CA bundle
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	rootCert, err := s.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		roots.AddCert(rootCert)
	}

	intermediateCert, err := s.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		intermediates.AddCert(intermediateCert)
	}

	// Add any additional trusted roots from request
	for _, rootDER := range req.GetTrustedRoots() {
		extraRoot, err := x509.ParseCertificate(rootDER)
		if err == nil {
			roots.AddCert(extraRoot)
		}
	}

	// Verify the certificate chain
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	chains, verifyErr := cert.Verify(opts)

	var errors []string
	var warnings []string

	if verifyErr != nil {
		errors = append(errors, verifyErr.Error())
	}

	// Check certificate validity period if requested
	now := time.Now()
	if req.GetVerifyExpiration() {
		if now.Before(cert.NotBefore) {
			warnings = append(warnings, "certificate is not yet valid")
		} else if now.After(cert.NotAfter) {
			errors = append(errors, "certificate has expired")
		}
	}

	// Check CRL revocation status if requested
	var revoked bool
	if req.GetVerifyRevocation() {
		revoked, _ = s.ca.IsRevoked(cert.SerialNumber)
		// Workaround: go-trusted-ca's IsRevoked() delegates to go-xkms's
		// in-memory map which is not updated by Revoke(). Check the object store
		// directly using the same key pattern that Revoke() uses to persist
		// revocation information.
		if !revoked {
			revoked = s.checkRevocationViaObjectStore(cert)
		}
		if revoked {
			errors = append(errors, "certificate has been revoked")
		}
	}

	// Build chain response as serial numbers
	var chainSerials []string
	if len(chains) > 0 {
		for _, c := range chains[0] {
			chainSerials = append(chainSerials, hex.EncodeToString(c.SerialNumber.Bytes()))
		}
	}

	valid := len(errors) == 0 && verifyErr == nil

	return &platformv1.VerifyCertificateResponse{
		Status: &platformv1.Status{
			Success: valid,
			Message: s.buildVerifyStatusMessage(valid, errors),
		},
		Valid:     valid,
		Chain:     chainSerials,
		Errors:    errors,
		Warnings:  warnings,
		Revoked:   revoked,
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetCRL returns the Certificate Revocation List.
func (s *CAGRPCService) GetCRL(ctx context.Context, req *platformv1.GetCRLRequest) (*platformv1.GetCRLResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	// Try to generate CRL if the CA supports it
	type crlGenerator interface {
		GenerateCRL(ctx context.Context) ([]byte, error)
	}

	var crlDER []byte
	var err error

	if gen, ok := s.ca.(crlGenerator); ok {
		crlDER, err = gen.GenerateCRL(ctx)
		if err != nil {
			s.logger.Error(err, "failed to generate CRL")
			// Check if CRL generation is not supported by this CA
			if strings.Contains(err.Error(), "not supported") {
				return nil, status.Error(codes.Unimplemented, "CRL generation not supported")
			}
			return nil, status.Error(codes.Internal, "failed to generate CRL: "+err.Error())
		}
	} else {
		return nil, status.Error(codes.Unimplemented, "CRL generation not supported")
	}

	// Parse the CRL to get metadata
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		s.logger.Error(err, "failed to parse CRL")
		return nil, status.Error(codes.Internal, "failed to parse CRL: "+err.Error())
	}

	// Build revoked certificates list if requested
	var revokedCerts []*platformv1.RevokedCertEntry
	if req.GetIncludeEntries() {
		for _, entry := range crl.RevokedCertificateEntries {
			revokedCerts = append(revokedCerts, &platformv1.RevokedCertEntry{
				Serial:         hex.EncodeToString(entry.SerialNumber.Bytes()),
				RevocationTime: timestamppb.New(entry.RevocationTime),
				Reason:         s.revocationReasonToProto(entry.ReasonCode),
			})
		}
	}

	return &platformv1.GetCRLResponse{
		Crl: &platformv1.CRL{
			Data:         crlDER,
			LastUpdate:   timestamppb.New(crl.ThisUpdate),
			NextUpdate:   timestamppb.New(crl.NextUpdate),
			RevokedCount: int32(len(crl.RevokedCertificateEntries)),
			RevokedCerts: revokedCerts,
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetCABundle returns the CA bundle (certificate chain).
//
// Mirrors the REST handler workaround in pkg/webservice/v1/rest/ca/handlers.go
// for an upstream issue in CABundleFiltered() that returns
// "no certificates match filter" when storeType is StoreUnknown and keyAlg is
// the zero value (x509.UnknownPublicKeyAlgorithm). The gRPC API doesn't yet
// take store-type / key-algorithm filters in the request, so we always take
// the unfiltered path.
func (s *CAGRPCService) GetCABundle(ctx context.Context, req *platformv1.GetCABundleRequest) (*platformv1.GetCABundleResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCANotInitialized{}.Error())
	}

	bundle, err := s.ca.CABundle()
	if err != nil {
		s.logger.Error(err, "failed to get CA bundle")
		return nil, status.Error(codes.Internal, "failed to get CA bundle: "+err.Error())
	}

	if len(bundle) == 0 {
		return nil, status.Error(codes.NotFound, "CA bundle not found")
	}

	// Parse bundle to get certificate summaries
	var certificates []*platformv1.CertificateSummary
	certs, err := s.ca.ParseBundle(bundle)
	if err == nil {
		for _, cert := range certs {
			// Skip intermediates if not requested
			if !req.GetIncludeIntermediates() && !cert.IsCA {
				continue
			}
			certificates = append(certificates, s.certToSummaryProto(cert))
		}
	}

	return &platformv1.GetCABundleResponse{
		Bundle: &platformv1.CABundle{
			Pem:          bundle,
			Certificates: certificates,
			CertCount:    int32(len(certificates)),
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// =============================================================================
// Certificate Lookup Helpers
// =============================================================================

// certMatchesIdentifier checks if a certificate matches the given identifier,
// which can be either a hex-encoded serial number or a common name.
func (s *CAGRPCService) certMatchesIdentifier(cert *x509.Certificate, identifier string) bool {
	// Match by hex-encoded serial number
	if hex.EncodeToString(cert.SerialNumber.Bytes()) == identifier {
		return true
	}
	// Match by common name (case-insensitive)
	if strings.EqualFold(cert.Subject.CommonName, identifier) {
		return true
	}
	return false
}

// findCertByIdentifier searches for a certificate matching the given identifier.
// The identifier can be a hex-encoded serial number or a common name.
// It checks root and intermediate CA certificates first, then the certificate store.
// For the cert store, it tries a direct CN-based lookup first (fast path), then
// falls back to iterating all certificates and matching by hex-encoded serial.
func (s *CAGRPCService) findCertByIdentifier(identifier string) *x509.Certificate {
	// Check root certificate
	rootCert, err := s.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if s.certMatchesIdentifier(rootCert, identifier) {
			return rootCert
		}
	}

	// Check intermediate certificate
	intermediateCert, err := s.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if s.certMatchesIdentifier(intermediateCert, identifier) {
			return intermediateCert
		}
	}

	// Try cert store lookup
	certStore := s.ca.CertStore()
	if certStore == nil {
		return nil
	}

	// Try direct CN-based lookup first (cert store uses CN as key)
	cert, err := certStore.GetCertificate(identifier)
	if err == nil && cert != nil {
		return cert
	}

	// Fall back to listing all certificates and matching by serial number
	certs, listErr := certStore.ListCertificates()
	if listErr != nil {
		return nil
	}

	for _, c := range certs {
		if hex.EncodeToString(c.SerialNumber.Bytes()) == identifier {
			return c
		}
	}

	return nil
}

// =============================================================================
// Revocation Helpers
// =============================================================================

// checkRevocationViaObjectStore checks if a certificate has been revoked by
// querying the QuicBaaS ObjectStorage directly. Revocation records are written
// by go-xkms CA at "revocations/<serial-decimal>.json".
func (s *CAGRPCService) checkRevocationViaObjectStore(cert *x509.Certificate) bool {
	if s.objStorage == nil {
		return false
	}
	key := fmt.Sprintf("revocations/%s.json", cert.SerialNumber.Text(10))
	_, err := s.objStorage.GetObject(context.Background(), &objectstorage.GetObjectRequest{Key: key})
	return err == nil
}

// Helper functions

func (s *CAGRPCService) keyAlgorithmToString(alg x509.PublicKeyAlgorithm) string {
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

func (s *CAGRPCService) x509KeyAlgorithmToProto(alg x509.PublicKeyAlgorithm) platformv1.KeyAlgorithm {
	switch alg {
	case x509.RSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048 // Default to 2048
	case x509.ECDSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256 // Default to P256
	case x509.Ed25519:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

func (s *CAGRPCService) certStatusToProto(cert *x509.Certificate) platformv1.CertificateStatus {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING
	} else if now.After(cert.NotAfter) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	}
	return platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID
}

func (s *CAGRPCService) revocationReasonToProto(reason int) platformv1.RevocationReason {
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

func (s *CAGRPCService) parseKeyUsage(usages []string) x509.KeyUsage {
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

func (s *CAGRPCService) parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
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

func (s *CAGRPCService) keyUsageToStrings(usage x509.KeyUsage) []string {
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

func (s *CAGRPCService) extKeyUsageToStrings(usages []x509.ExtKeyUsage) []string {
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

func (s *CAGRPCService) certToProto(cert *x509.Certificate, includePEM, includeDER bool) *platformv1.Certificate {
	if cert == nil {
		return nil
	}

	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	proto := &platformv1.Certificate{
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
		Status:             s.certStatusToProto(cert),
		KeyAlgorithm:       s.x509KeyAlgorithmToProto(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCa:               cert.IsCA,
		MaxPathLen:         int32(cert.MaxPathLen),
		KeyUsage:           s.keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        s.extKeyUsageToStrings(cert.ExtKeyUsage),
		FingerprintSha256:  hex.EncodeToString(fingerprint[:]),
	}

	// Add SANs if present
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		proto.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}
		for _, ip := range cert.IPAddresses {
			proto.Sans.IpAddresses = append(proto.Sans.IpAddresses, ip.String())
		}
		for _, uri := range cert.URIs {
			proto.Sans.Uris = append(proto.Sans.Uris, uri.String())
		}
	}

	if includePEM {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		proto.Pem = pemBlock
	}

	if includeDER {
		proto.Der = cert.Raw
	}

	return proto
}

func (s *CAGRPCService) certToSummaryProto(cert *x509.Certificate) *platformv1.CertificateSummary {
	if cert == nil {
		return nil
	}

	return &platformv1.CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    timestamppb.New(cert.NotBefore),
		NotAfter:     timestamppb.New(cert.NotAfter),
		Status:       s.certStatusToProto(cert),
		KeyAlgorithm: s.x509KeyAlgorithmToProto(cert.PublicKeyAlgorithm),
	}
}

func (s *CAGRPCService) buildVerifyStatusMessage(valid bool, errors []string) string {
	if valid {
		return "certificate verification successful"
	}
	if len(errors) > 0 {
		return "certificate verification failed: " + errors[0]
	}
	return "certificate verification failed"
}

// firstOrEmpty returns the first element of a slice or empty string.
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}
