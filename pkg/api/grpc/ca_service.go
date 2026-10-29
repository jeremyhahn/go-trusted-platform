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

package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util/peercred"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CA gRPC service error types.

// ErrNilCAService is returned when the CA service is nil.
type ErrNilCAService struct{}

func (e ErrNilCAService) Error() string {
	return "ca service is nil"
}

// ErrSignCSRNotRoot is a SignCSR call over the Unix socket from a user
// other than root.
type ErrSignCSRNotRoot struct {
	UID uint32
}

func (e ErrSignCSRNotRoot) Error() string {
	return "signing a CSR over the Unix socket requires root, but the caller is uid " + strconv.FormatUint(uint64(e.UID), 10)
}

// ErrMissingSerial is returned when a serial number is required but not provided.
type ErrMissingSerial struct{}

func (e ErrMissingSerial) Error() string {
	return "serial number is required"
}

// ErrMissingCertificateRequest is returned when a certificate request is required but not provided.
type ErrMissingCertificateRequest struct{}

func (e ErrMissingCertificateRequest) Error() string {
	return "certificate request is required"
}

// ErrMissingSubject is returned when a subject is required but not provided.
type ErrMissingSubject struct{}

func (e ErrMissingSubject) Error() string {
	return "subject is required"
}

// ErrMissingCommonName is returned when a common name is required but not provided.
type ErrMissingCommonName struct{}

func (e ErrMissingCommonName) Error() string {
	return "common name is required"
}

// ErrMissingCertificate is returned when certificate data is required but not provided.
type ErrMissingCertificate struct{}

func (e ErrMissingCertificate) Error() string {
	return "certificate (PEM or DER) is required"
}

// ErrMissingValidDays is returned when valid_days is required but not provided.
type ErrMissingValidDays struct{}

func (e ErrMissingValidDays) Error() string {
	return "valid_days must be positive"
}

// ErrCAOperationFailed is returned when a CA operation fails.
type ErrCAOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrCAOperationFailed) Error() string {
	return "CA operation " + e.Operation + " failed: " + e.Reason
}

// ErrCertificateNotFoundGRPC is returned when a certificate cannot be found.
type ErrCertificateNotFoundGRPC struct {
	Serial string
}

func (e ErrCertificateNotFoundGRPC) Error() string {
	return "certificate not found: " + e.Serial
}

const (
	caGRPCDefaultPageSize uint32 = 50
	caGRPCMaxPageSize     uint32 = 1000
)

// CAGRPCService implements the gRPC CAService server interface.
// It wraps the quicbaasca.CACertificateAuthority interface to provide gRPC access to CA operations.
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

// NewCAGRPCService creates a new CAGRPCService instance.
// Kept with no caller: docs/ca names this file as the CAService surface the daemon's InitCA/Install/Uninstall stubs still shadow.
func NewCAGRPCService(
	logger *logging.Logger,
	ca quicbaasca.CACertificateAuthority,
	objStorage objectstorage.Client,
) *CAGRPCService {
	return &CAGRPCService{
		logger:     logger,
		ca:         ca,
		objStorage: objStorage,
	}
}

// GetCAInfo returns information about the Certificate Authority.
func (s *CAGRPCService) GetCAInfo(
	ctx context.Context,
	req *platformv1.GetCAInfoRequest,
) (*platformv1.GetCAInfoResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

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
			caInfo.RootCert = s.certToSummary(rootCert)
		}

		// Get intermediate certificate info
		intermediateCert, err := s.ca.TrustedIntermediate()
		if err == nil && intermediateCert != nil {
			caInfo.IsIntermediate = true
			caInfo.Intermediates = append(caInfo.Intermediates, s.certToSummary(intermediateCert))
		}
	}

	return &platformv1.GetCAInfoResponse{
		CaInfo:    caInfo,
		Timestamp: timestamppb.Now(),
	}, nil
}

// IssueCertificate issues a new certificate.
func (s *CAGRPCService) IssueCertificate(
	ctx context.Context,
	req *platformv1.IssueCertificateRequest,
) (*platformv1.IssueCertificateResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	certReq := req.GetRequest()
	if certReq == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCertificateRequest{}.Error())
	}

	subject := certReq.GetSubject()
	if subject == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSubject{}.Error())
	}

	if subject.GetCommonName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCommonName{}.Error())
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
		return nil, status.Errorf(codes.Internal, "failed to issue certificate: %v", err)
	}

	cert := issued.Certificate
	return &platformv1.IssueCertificateResponse{
		Status:      caSuccessStatusGRPC("certificate issued successfully"),
		Certificate: s.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// SignCSR certifies a KMS key for code signing from a CSR the KMS signed.
// The method is authorized by its own scope, ca:sign-csr, which ca:write
// does not grant; issuance.SignCSR decides which CSRs are certified.
func (s *CAGRPCService) SignCSR(ctx context.Context, req *platformv1.SignCSRRequest) (*platformv1.IssueCertificateResponse, error) {
	if err := AuthorizeSignCSR(ctx); err != nil {
		return nil, err
	}
	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
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
		Status:      caSuccessStatusGRPC("certificate issued successfully"),
		Certificate: s.certToProto(cert, true, false),
		Timestamp:   timestamppb.Now(),
	}, nil
}

// AuthorizeSignCSR admits a SignCSR call from the platform admin only: a
// platform token granting ca:sign-csr, or root on the daemon's Unix socket,
// whose peer credentials the kernel vouches for. A caller authenticated any
// other way (an mTLS certificate, a legacy token validator) carries no
// scopes and is refused, so certifying a code-signing key never rides on
// authentication alone. Every gRPC CA service calls it.
func AuthorizeSignCSR(ctx context.Context) error {
	if authCtx, ok := AuthorizedContextFromContext(ctx); ok {
		if err := issuance.AuthorizeSignCSR(authCtx); err != nil {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		return nil
	}
	if creds, ok := peercred.UnixCredentialsFromContext(ctx); ok {
		if !creds.IsRoot() {
			return status.Error(codes.PermissionDenied, ErrSignCSRNotRoot{UID: creds.UID}.Error())
		}
		return nil
	}
	return status.Error(codes.PermissionDenied, issuance.AuthorizeSignCSR(nil).Error())
}

// GetCertificate retrieves a certificate by serial number or common name.
// The serial field accepts either a hex-encoded serial number or a common name.
func (s *CAGRPCService) GetCertificate(
	ctx context.Context,
	req *platformv1.GetCertificateRequest,
) (*platformv1.GetCertificateResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	identifier := req.GetSerial()
	if identifier == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSerial{}.Error())
	}

	// Check root certificate
	rootCert, err := s.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if s.certMatchesIdentifier(rootCert, identifier) {
			return &platformv1.GetCertificateResponse{
				Certificate: s.certToProto(rootCert, req.GetIncludePem(), req.GetIncludeDer()),
				Timestamp:   timestamppb.Now(),
			}, nil
		}
	}

	// Check intermediate certificate
	intermediateCert, err := s.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if s.certMatchesIdentifier(intermediateCert, identifier) {
			return &platformv1.GetCertificateResponse{
				Certificate: s.certToProto(intermediateCert, req.GetIncludePem(), req.GetIncludeDer()),
				Timestamp:   timestamppb.Now(),
			}, nil
		}
	}

	// Try cert store lookup
	cert := s.findCertByIdentifier(identifier)
	if cert != nil {
		return &platformv1.GetCertificateResponse{
			Certificate: s.certToProto(cert, req.GetIncludePem(), req.GetIncludeDer()),
			Timestamp:   timestamppb.Now(),
		}, nil
	}

	return nil, status.Error(codes.NotFound, ErrCertificateNotFoundGRPC{Serial: identifier}.Error())
}

// ListCertificates returns a paginated list of certificates.
func (s *CAGRPCService) ListCertificates(
	ctx context.Context,
	req *platformv1.ListCertificatesRequest,
) (*platformv1.ListCertificatesResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	pagination := req.GetPagination()
	pageSize := caGRPCDefaultPageSize
	page := uint32(1)

	if pagination != nil {
		if pagination.GetPageSize() > 0 {
			pageSize = pagination.GetPageSize()
		}
		if pagination.GetPage() > 0 {
			page = pagination.GetPage()
		}
	}

	if pageSize > caGRPCMaxPageSize {
		pageSize = caGRPCMaxPageSize
	}

	// Collect certificates
	var certificates []*platformv1.CertificateSummary

	rootCert, err := s.ca.TrustedRoot()
	if err == nil && rootCert != nil {
		if s.matchesCertFilter(rootCert, req) {
			certificates = append(certificates, s.certToSummary(rootCert))
		}
	}

	intermediateCert, err := s.ca.TrustedIntermediate()
	if err == nil && intermediateCert != nil {
		if s.matchesCertFilter(intermediateCert, req) {
			certificates = append(certificates, s.certToSummary(intermediateCert))
		}
	}

	// Get certificates from cert store if available
	certStore := s.ca.CertStore()
	if certStore != nil {
		certs, listErr := certStore.ListCertificates()
		if listErr == nil {
			for _, cert := range certs {
				if s.matchesCertFilter(cert, req) {
					certificates = append(certificates, s.certToSummary(cert))
				}
			}
		}
	}

	// Apply pagination
	totalItems := uint64(len(certificates))
	totalPages := uint32((totalItems + uint64(pageSize) - 1) / uint64(pageSize))

	// Calculate slice bounds for pagination
	start := (page - 1) * pageSize
	end := start + pageSize

	switch {
	case uint64(start) >= totalItems:
		certificates = []*platformv1.CertificateSummary{}
	case uint64(end) > totalItems:
		certificates = certificates[start:]
	default:
		certificates = certificates[start:end]
	}

	return &platformv1.ListCertificatesResponse{
		Certificates: certificates,
		Pagination: &platformv1.PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			TotalPages: totalPages,
			TotalItems: totalItems,
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

// RevokeCertificate revokes a certificate.
func (s *CAGRPCService) RevokeCertificate(
	ctx context.Context,
	req *platformv1.RevokeCertificateRequest,
) (*platformv1.RevokeCertificateResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	serial := req.GetSerial()
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSerial{}.Error())
	}
	if err := issuance.ValidateRevocationReason(int(req.GetReason())); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Find the certificate by serial or common name
	cert := s.findCertByIdentifier(serial)
	if cert == nil {
		return nil, status.Error(codes.NotFound, ErrCertificateNotFoundGRPC{Serial: serial}.Error())
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
		return nil, status.Errorf(codes.Internal, "failed to revoke certificate: %v", err)
	}

	now := timestamppb.Now()
	return &platformv1.RevokeCertificateResponse{
		Status:            caSuccessStatusGRPC("certificate revoked successfully"),
		Serial:            serial,
		CertificateStatus: platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED,
		RevokedAt:         now,
		Reason:            req.GetReason(),
		Timestamp:         now,
	}, nil
}

// RenewCertificate renews an existing certificate.
func (s *CAGRPCService) RenewCertificate(
	ctx context.Context,
	req *platformv1.RenewCertificateRequest,
) (*platformv1.RenewCertificateResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	serial := req.GetSerial()
	if serial == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSerial{}.Error())
	}

	validDays := req.GetValidDays()
	if validDays <= 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingValidDays{}.Error())
	}

	// Find the existing certificate by serial or common name
	existingCert := s.findCertByIdentifier(serial)
	if existingCert == nil {
		return nil, status.Error(codes.NotFound, ErrCertificateNotFoundGRPC{Serial: serial}.Error())
	}

	// Build a new certificate request based on the existing certificate
	caReq := &quicbaasca.CACertificateRequest{
		Subject: quicbaasca.CASubject{
			CommonName:         existingCert.Subject.CommonName,
			Organization:       firstOrEmptyGRPC(existingCert.Subject.Organization),
			OrganizationalUnit: firstOrEmptyGRPC(existingCert.Subject.OrganizationalUnit),
			Country:            firstOrEmptyGRPC(existingCert.Subject.Country),
			Province:           firstOrEmptyGRPC(existingCert.Subject.Province),
			Locality:           firstOrEmptyGRPC(existingCert.Subject.Locality),
			Address:            firstOrEmptyGRPC(existingCert.Subject.StreetAddress),
			PostalCode:         firstOrEmptyGRPC(existingCert.Subject.PostalCode),
		},
		Valid:       int(validDays),
		IsCA:        existingCert.IsCA,
		MaxPathLen:  existingCert.MaxPathLen,
		KeyUsage:    existingCert.KeyUsage,
		ExtKeyUsage: existingCert.ExtKeyUsage,
	}

	// Handle SANs based on request flags
	if req.GetPreserveSans() {
		if len(existingCert.DNSNames) > 0 || len(existingCert.IPAddresses) > 0 ||
			len(existingCert.EmailAddresses) > 0 || len(existingCert.URIs) > 0 {
			caReq.SANS = &quicbaasca.CASubjectAlternativeNames{
				DNS:   existingCert.DNSNames,
				Email: existingCert.EmailAddresses,
			}
			for _, ip := range existingCert.IPAddresses {
				caReq.SANS.IPs = append(caReq.SANS.IPs, ip.String())
			}
			for _, uri := range existingCert.URIs {
				caReq.SANS.URIs = append(caReq.SANS.URIs, uri.String())
			}
		}
	}

	// Apply new SANs if provided
	newSans := req.GetNewSans()
	if newSans != nil {
		caReq.SANS = &quicbaasca.CASubjectAlternativeNames{
			DNS:   newSans.GetDnsNames(),
			IPs:   newSans.GetIpAddresses(),
			Email: newSans.GetEmailAddresses(),
			URIs:  newSans.GetUris(),
		}
	}

	// Set key attributes
	caReq.KeyAttributes = &xkmssdk.KeyAttributes{
		CN:           existingCert.Subject.CommonName,
		KeyAlgorithm: existingCert.PublicKeyAlgorithm,
		StoreType:    xkmssdk.StoreSoftware,
		KeyType:      xkmssdk.KeyTypeTLS,
	}

	// Issue the renewed certificate
	issuedRenew, err := s.ca.IssueCertificate(ctx, caReq)
	if err != nil {
		s.logger.Error(err, "failed to renew certificate")
		return nil, status.Errorf(codes.Internal, "failed to renew certificate: %v", err)
	}

	newCert := issuedRenew.Certificate
	return &platformv1.RenewCertificateResponse{
		Status:         caSuccessStatusGRPC("certificate renewed successfully"),
		OldCertificate: s.certToProto(existingCert, false, false),
		NewCertificate: s.certToProto(newCert, true, false),
		Timestamp:      timestamppb.Now(),
	}, nil
}

// VerifyCertificate verifies a certificate chain.
func (s *CAGRPCService) VerifyCertificate(
	ctx context.Context,
	req *platformv1.VerifyCertificateRequest,
) (*platformv1.VerifyCertificateResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	if len(req.GetCertificatePem()) == 0 && len(req.GetCertificateDer()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCertificate{}.Error())
	}

	// Parse the certificate to verify
	var cert *x509.Certificate
	var parseErr error

	if len(req.GetCertificateDer()) > 0 {
		cert, parseErr = x509.ParseCertificate(req.GetCertificateDer())
	} else {
		block, _ := pem.Decode(req.GetCertificatePem())
		if block == nil {
			return &platformv1.VerifyCertificateResponse{
				Status:    caFailureStatusGRPC("failed to decode PEM certificate"),
				Valid:     false,
				Errors:    []string{"failed to decode PEM certificate"},
				Timestamp: timestamppb.Now(),
			}, nil
		}
		cert, parseErr = x509.ParseCertificate(block.Bytes)
	}

	if parseErr != nil {
		return &platformv1.VerifyCertificateResponse{
			Status:    caFailureStatusGRPC("failed to parse certificate: " + parseErr.Error()),
			Valid:     false,
			Errors:    []string{"failed to parse certificate: " + parseErr.Error()},
			Timestamp: timestamppb.Now(),
		}, nil
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
		extraRoot, rootErr := x509.ParseCertificate(rootDER)
		if rootErr == nil {
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

	var respStatus *platformv1.Status
	switch {
	case valid:
		respStatus = caSuccessStatusGRPC("certificate verification successful")
	case len(errors) > 0:
		respStatus = caFailureStatusGRPC("certificate verification failed: " + errors[0])
	default:
		respStatus = caFailureStatusGRPC("certificate verification failed")
	}

	return &platformv1.VerifyCertificateResponse{
		Status:    respStatus,
		Valid:     valid,
		Chain:     chainSerials,
		Errors:    errors,
		Warnings:  warnings,
		Revoked:   revoked,
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetCRL returns the current Certificate Revocation List.
func (s *CAGRPCService) GetCRL(
	ctx context.Context,
	req *platformv1.GetCRLRequest,
) (*platformv1.GetCRLResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
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
			return nil, status.Errorf(codes.Internal, "failed to generate CRL: %v", err)
		}
	} else {
		// Return empty CRL if not supported
		crl := &platformv1.CRL{
			Data:         []byte{},
			LastUpdate:   timestamppb.Now(),
			NextUpdate:   timestamppb.New(time.Now().Add(24 * time.Hour)),
			RevokedCount: 0,
		}
		return &platformv1.GetCRLResponse{
			Crl:       crl,
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Handle empty CRL data (CA supports CRL but returned no data)
	if len(crlDER) == 0 {
		crl := &platformv1.CRL{
			Data:         []byte{},
			LastUpdate:   timestamppb.Now(),
			NextUpdate:   timestamppb.New(time.Now().Add(24 * time.Hour)),
			RevokedCount: 0,
		}
		return &platformv1.GetCRLResponse{
			Crl:       crl,
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Parse the CRL to get metadata
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		s.logger.Error(err, "failed to parse CRL")
		return nil, status.Errorf(codes.Internal, "failed to parse CRL: %v", err)
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

// GetCABundle returns the CA certificate bundle.
func (s *CAGRPCService) GetCABundle(
	ctx context.Context,
	req *platformv1.GetCABundleRequest,
) (*platformv1.GetCABundleResponse, error) {

	if s.ca == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilCAService{}.Error())
	}

	// Get the CA bundle (use default store type and key algorithm)
	bundle, err := s.ca.CABundleFiltered(xkmssdk.StoreUnknown, 0)
	if err != nil {
		s.logger.Error(err, "failed to get CA bundle")
		return nil, status.Errorf(codes.Internal, "failed to get CA bundle: %v", err)
	}

	if len(bundle) == 0 {
		return nil, status.Error(codes.NotFound, "CA bundle not found")
	}

	// Parse bundle to get certificate summaries
	var certificates []*platformv1.CertificateSummary
	certs, parseErr := s.ca.ParseBundle(bundle)
	if parseErr == nil {
		for _, cert := range certs {
			// Skip intermediates if not requested
			if !req.GetIncludeIntermediates() && !cert.IsCA {
				continue
			}
			certificates = append(certificates, s.certToSummary(cert))
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

// findCertByIdentifier searches the certificate store for a certificate matching
// the given identifier. It first tries a direct CN-based lookup (the cert store's
// native key), then falls back to iterating all certificates and matching by
// hex-encoded serial number.
func (s *CAGRPCService) findCertByIdentifier(identifier string) *x509.Certificate {
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

func caSuccessStatusGRPC(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func caFailureStatusGRPC(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: false,
		Message: message,
	}
}

// matchesCertFilter checks if a certificate matches the filter criteria.
func (s *CAGRPCService) matchesCertFilter(cert *x509.Certificate, req *platformv1.ListCertificatesRequest) bool {
	// Check status filter
	statusFilter := req.GetStatusFilter()
	if statusFilter != platformv1.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED {
		certStatus := s.getCertificateStatus(cert)
		if certStatus != statusFilter {
			return false
		}
	}

	// Check type filter
	typeFilter := req.GetTypeFilter()
	if typeFilter != platformv1.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED {
		certType := s.getCertificateType(cert)
		if certType != typeFilter {
			return false
		}
	}

	// Check issuer filter
	issuerFilter := req.GetIssuerFilter()
	if issuerFilter != "" {
		if cert.Issuer.CommonName != issuerFilter {
			return false
		}
	}

	return true
}

// getCertificateStatus determines the status of a certificate.
func (s *CAGRPCService) getCertificateStatus(cert *x509.Certificate) platformv1.CertificateStatus {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING
	}
	if now.After(cert.NotAfter) {
		return platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	}
	return platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID
}

// getCertificateType determines the type of a certificate.
func (s *CAGRPCService) getCertificateType(cert *x509.Certificate) platformv1.CertificateType {
	if cert.IsCA {
		return platformv1.CertificateType_CERTIFICATE_TYPE_CA
	}

	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			return platformv1.CertificateType_CERTIFICATE_TYPE_SERVER
		case x509.ExtKeyUsageClientAuth:
			return platformv1.CertificateType_CERTIFICATE_TYPE_CLIENT
		case x509.ExtKeyUsageCodeSigning:
			return platformv1.CertificateType_CERTIFICATE_TYPE_CODE_SIGNING
		case x509.ExtKeyUsageEmailProtection:
			return platformv1.CertificateType_CERTIFICATE_TYPE_EMAIL
		}
	}

	return platformv1.CertificateType_CERTIFICATE_TYPE_UNSPECIFIED
}

// revocationReasonToProto converts an integer revocation reason to proto enum.
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

// certToSummary converts an x509.Certificate to a CertificateSummary proto.
func (s *CAGRPCService) certToSummary(cert *x509.Certificate) *platformv1.CertificateSummary {
	if cert == nil {
		return nil
	}

	return &platformv1.CertificateSummary{
		Serial:       hex.EncodeToString(cert.SerialNumber.Bytes()),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		NotBefore:    timestamppb.New(cert.NotBefore),
		NotAfter:     timestamppb.New(cert.NotAfter),
		Status:       s.getCertificateStatus(cert),
		KeyAlgorithm: s.x509AlgorithmToProto(cert.PublicKeyAlgorithm),
	}
}

// certToProto converts an x509.Certificate to a Certificate proto with full details.
func (s *CAGRPCService) certToProto(cert *x509.Certificate, includePEM, includeDER bool) *platformv1.Certificate {
	if cert == nil {
		return nil
	}

	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	c := &platformv1.Certificate{
		Serial: hex.EncodeToString(cert.SerialNumber.Bytes()),
		Subject: &platformv1.Subject{
			CommonName:         cert.Subject.CommonName,
			Organization:       firstOrEmptyGRPC(cert.Subject.Organization),
			OrganizationalUnit: firstOrEmptyGRPC(cert.Subject.OrganizationalUnit),
			Country:            firstOrEmptyGRPC(cert.Subject.Country),
			Province:           firstOrEmptyGRPC(cert.Subject.Province),
			Locality:           firstOrEmptyGRPC(cert.Subject.Locality),
			Address:            firstOrEmptyGRPC(cert.Subject.StreetAddress),
			PostalCode:         firstOrEmptyGRPC(cert.Subject.PostalCode),
		},
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          timestamppb.New(cert.NotBefore),
		NotAfter:           timestamppb.New(cert.NotAfter),
		Status:             s.getCertificateStatus(cert),
		KeyAlgorithm:       s.x509AlgorithmToProto(cert.PublicKeyAlgorithm),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		IsCa:               cert.IsCA,
		MaxPathLen:         int32(cert.MaxPathLen),
		KeyUsage:           s.keyUsageToStrings(cert.KeyUsage),
		ExtKeyUsage:        s.extKeyUsageToStrings(cert.ExtKeyUsage),
		FingerprintSha256:  hex.EncodeToString(fingerprint[:]),
	}

	// Add SANs
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		c.Sans = &platformv1.SubjectAlternativeNames{
			DnsNames:       cert.DNSNames,
			EmailAddresses: cert.EmailAddresses,
		}

		// Convert IP addresses to strings
		for _, ip := range cert.IPAddresses {
			c.Sans.IpAddresses = append(c.Sans.IpAddresses, ip.String())
		}

		// Convert URIs to strings
		for _, uri := range cert.URIs {
			c.Sans.Uris = append(c.Sans.Uris, uri.String())
		}
	}

	if includePEM {
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		c.Pem = pemBlock
	}

	if includeDER {
		c.Der = cert.Raw
	}

	return c
}

// keyAlgorithmToString converts an x509.PublicKeyAlgorithm to a string.
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

// x509AlgorithmToProto converts an x509.PublicKeyAlgorithm to a proto KeyAlgorithm.
func (s *CAGRPCService) x509AlgorithmToProto(alg x509.PublicKeyAlgorithm) platformv1.KeyAlgorithm {
	switch alg {
	case x509.RSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	case x509.ECDSA:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case x509.Ed25519:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519
	default:
		return platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED
	}
}

// protoAlgorithmToX509 converts a proto KeyAlgorithm to x509.PublicKeyAlgorithm.
// keyUsageToStrings converts x509.KeyUsage to string slice.
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

// extKeyUsageToStrings converts []x509.ExtKeyUsage to string slice.
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

// parseKeyUsage converts string slice to x509.KeyUsage.
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

// parseExtKeyUsage converts string slice to []x509.ExtKeyUsage.
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

func firstOrEmptyGRPC(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// Ensure CAGRPCService implements the CAServiceServer interface.
var _ platformv1.CAServiceServer = (*CAGRPCService)(nil)
