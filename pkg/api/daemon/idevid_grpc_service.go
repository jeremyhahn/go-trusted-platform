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
	"fmt"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// IDevIDGRPCService implements the IDevID gRPC service for device identity operations.
// It provides IDevID (Initial Device Identifier) and IAK (Initial Attestation Key)
// management per TCG (Trusted Computing Group) specifications.
type IDevIDGRPCService struct {
	platformv1.UnimplementedIDevIDServiceServer

	logger      *logging.Logger
	tpm2Service xkmssdk.TrustedPlatformModule
}

// NewIDevIDGRPCService creates a new IDevID gRPC service instance.
func NewIDevIDGRPCService(logger *logging.Logger) *IDevIDGRPCService {
	return &IDevIDGRPCService{
		logger: logger,
	}
}

// SetTPM2Service sets the TPM2 service for device identity operations.
func (s *IDevIDGRPCService) SetTPM2Service(svc xkmssdk.TrustedPlatformModule) {
	s.tpm2Service = svc
}

// =============================================================================
// IDevID Operations
// =============================================================================

// GenerateIDevID creates a new IDevID key in the TPM.
func (s *IDevIDGRPCService) GenerateIDevID(ctx context.Context, req *platformv1.GenerateIDevIDRequest) (*platformv1.GenerateIDevIDResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Get EK attributes for IAK creation (needed before IDevID)
	ekAttrs, err := s.tpm2Service.EKAttributes()
	if err != nil {
		s.logger.Error(err, "Failed to get EK attributes")
		return nil, s.mapTPM2Error(err, "get EK attributes")
	}

	// Create IAK first (required for IDevID creation)
	iakAttrs, err := s.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		s.logger.Error(err, "Failed to create IAK")
		return nil, s.mapTPM2Error(err, "create IAK")
	}

	// Create IDevID using IAK
	idevidAttrs, _, err := s.tpm2Service.CreateIDevID(iakAttrs, nil, nil)
	if err != nil {
		s.logger.Error(err, "Failed to create IDevID")
		return nil, s.mapTPM2Error(err, "create IDevID")
	}

	s.logger.Info("IDevID generated", "handle", idevidAttrs.TPMAttributes.Handle)

	return &platformv1.GenerateIDevIDResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IDevID generated successfully",
		},
	}, nil
}

// GetIDevIDInfo retrieves information about the IDevID key.
func (s *IDevIDGRPCService) GetIDevIDInfo(ctx context.Context, req *platformv1.GetIDevIDInfoRequest) (*platformv1.GetIDevIDInfoResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	attrs, err := s.tpm2Service.IDevIDAttributes()
	if err != nil {
		return nil, status.Error(codes.NotFound, "IDevID not found")
	}

	keyInfo := &platformv1.DeviceKeyInfo{
		Handle:    uint32(attrs.TPMAttributes.Handle),
		Algorithm: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256, // Default
	}

	// Encode public key as PEM
	pubKeyPEM, err := encodePublicKeyPEM(attrs.TPMAttributes.Public)
	if err == nil {
		keyInfo.PublicKeyPem = []byte(pubKeyPEM)
	}

	keyInfo.CreatedAt = timestamppb.Now()

	// Check if certificate exists
	cert, certErr := s.tpm2Service.IDevIDCertificate()
	if certErr == nil && cert != nil {
		keyInfo.HasCertificate = true
		keyInfo.CertificateInfo = s.certToProto(cert)
	}

	return &platformv1.GetIDevIDInfoResponse{
		KeyInfo: keyInfo,
	}, nil
}

// HasIDevID checks if an IDevID key exists in the TPM.
func (s *IDevIDGRPCService) HasIDevID(ctx context.Context, req *platformv1.HasIDevIDRequest) (*platformv1.HasIDevIDResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	_, err := s.tpm2Service.IDevIDAttributes()
	exists := err == nil

	return &platformv1.HasIDevIDResponse{
		Exists: exists,
	}, nil
}

// DeleteIDevID removes the IDevID key from the TPM.
func (s *IDevIDGRPCService) DeleteIDevID(ctx context.Context, req *platformv1.DeleteIDevIDRequest) (*platformv1.DeleteIDevIDResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Delete the IDevID certificate first
	if err := s.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		// Log but continue - certificate might not exist
		s.logger.Debug("IDevID certificate deletion skipped", "error", err)
	}

	s.logger.Info("IDevID deleted")

	return &platformv1.DeleteIDevIDResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IDevID deleted successfully",
		},
	}, nil
}

// =============================================================================
// IAK Operations
// =============================================================================

// GenerateIAK creates a new IAK (Initial Attestation Key) in the TPM.
func (s *IDevIDGRPCService) GenerateIAK(ctx context.Context, req *platformv1.GenerateIAKRequest) (*platformv1.GenerateIAKResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Get EK attributes for IAK creation
	ekAttrs, err := s.tpm2Service.EKAttributes()
	if err != nil {
		s.logger.Error(err, "Failed to get EK attributes")
		return nil, s.mapTPM2Error(err, "get EK attributes")
	}

	// Create IAK
	iakAttrs, err := s.tpm2Service.CreateIAK(ekAttrs, nil)
	if err != nil {
		s.logger.Error(err, "Failed to create IAK")
		return nil, s.mapTPM2Error(err, "create IAK")
	}

	s.logger.Info("IAK generated", "handle", iakAttrs.TPMAttributes.Handle)

	return &platformv1.GenerateIAKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IAK generated successfully",
		},
	}, nil
}

// GetIAKInfo retrieves information about the IAK key.
func (s *IDevIDGRPCService) GetIAKInfo(ctx context.Context, req *platformv1.GetIAKInfoRequest) (*platformv1.GetIAKInfoResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	attrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		return nil, status.Error(codes.NotFound, "IAK not found")
	}

	keyInfo := &platformv1.DeviceKeyInfo{
		Handle:    uint32(attrs.TPMAttributes.Handle),
		Algorithm: platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256, // Default
	}

	// Encode public key as PEM
	pubKeyPEM, err := encodePublicKeyPEM(attrs.TPMAttributes.Public)
	if err == nil {
		keyInfo.PublicKeyPem = []byte(pubKeyPEM)
	}

	keyInfo.CreatedAt = timestamppb.Now()

	// Check if certificate exists
	cert, certErr := s.tpm2Service.IAKCertificate()
	if certErr == nil && cert != nil {
		keyInfo.HasCertificate = true
		keyInfo.CertificateInfo = s.certToProto(cert)
	}

	return &platformv1.GetIAKInfoResponse{
		KeyInfo: keyInfo,
	}, nil
}

// HasIAK checks if an IAK key exists in the TPM.
func (s *IDevIDGRPCService) HasIAK(ctx context.Context, req *platformv1.HasIAKRequest) (*platformv1.HasIAKResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	_, err := s.tpm2Service.IAKAttributes()
	exists := err == nil

	return &platformv1.HasIAKResponse{
		Exists: exists,
	}, nil
}

// DeleteIAK removes the IAK key from the TPM.
func (s *IDevIDGRPCService) DeleteIAK(ctx context.Context, req *platformv1.DeleteIAKRequest) (*platformv1.DeleteIAKResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Delete the IAK certificate first
	if err := s.tpm2Service.DeleteIAKCertificate(); err != nil {
		// Log but continue - certificate might not exist
		s.logger.Debug("IAK certificate deletion skipped", "error", err)
	}

	s.logger.Info("IAK deleted")

	return &platformv1.DeleteIAKResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IAK deleted successfully",
		},
	}, nil
}

// =============================================================================
// CSR Operations
// =============================================================================

// CreateIDevIDCSR creates a certificate signing request for the IDevID key.
func (s *IDevIDGRPCService) CreateIDevIDCSR(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest) (*platformv1.CreateIDevIDCSRResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Get IDevID attributes
	idevidAttrs, err := s.tpm2Service.IDevIDAttributes()
	if err != nil {
		s.logger.Error(err, "Failed to get IDevID attributes")
		return nil, status.Error(codes.NotFound, "IDevID not found")
	}

	// Get IAK attributes for CSR creation
	iakAttrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		s.logger.Error(err, "Failed to get IAK attributes")
		return nil, status.Error(codes.NotFound, "IAK not found")
	}

	// Create TCG CSR using TPM2
	tcgCSR, err := s.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, idevidAttrs)
	if err != nil {
		s.logger.Error(err, "Failed to create TCG CSR")
		return nil, s.mapTPM2Error(err, "create IDevID CSR")
	}

	// Marshal CSR to bytes
	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		s.logger.Error(err, "Failed to marshal TCG CSR")
		return nil, status.Error(codes.Internal, "failed to marshal CSR")
	}

	s.logger.Info("IDevID CSR generated")

	return &platformv1.CreateIDevIDCSRResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IDevID CSR generated successfully",
		},
		CsrPem: csrBytes,
	}, nil
}

// CreateIAKCSR creates a certificate signing request for the IAK key.
func (s *IDevIDGRPCService) CreateIAKCSR(ctx context.Context, req *platformv1.CreateIAKCSRRequest) (*platformv1.CreateIAKCSRResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Get IAK attributes
	iakAttrs, err := s.tpm2Service.IAKAttributes()
	if err != nil {
		s.logger.Error(err, "Failed to get IAK attributes")
		return nil, status.Error(codes.NotFound, "IAK not found")
	}

	// Create TCG CSR for IAK - use CreateTCG_CSR_IDEVID with iakAttrs for both params
	tcgCSR, err := s.tpm2Service.CreateTCG_CSR_IDEVID(nil, iakAttrs, iakAttrs)
	if err != nil {
		s.logger.Error(err, "Failed to create IAK CSR")
		return nil, s.mapTPM2Error(err, "create IAK CSR")
	}

	// Marshal CSR to bytes
	csrBytes, err := tcgCSR.Marshal()
	if err != nil {
		s.logger.Error(err, "Failed to marshal TCG CSR")
		return nil, status.Error(codes.Internal, "failed to marshal CSR")
	}

	s.logger.Info("IAK CSR generated")

	return &platformv1.CreateIAKCSRResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IAK CSR generated successfully",
		},
		CsrPem: csrBytes,
	}, nil
}

// =============================================================================
// Certificate Operations
// =============================================================================

// InstallIDevIDCertificate installs an IDevID certificate.
func (s *IDevIDGRPCService) InstallIDevIDCertificate(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest) (*platformv1.InstallIDevIDCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	certPEM := req.GetCertificatePem()
	if len(certPEM) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate PEM is required")
	}

	// Parse PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate PEM format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate: "+err.Error())
	}

	// Install using TPM2
	if err := s.tpm2Service.ProvisionIDevIDCert(cert); err != nil {
		s.logger.Error(err, "Failed to install IDevID certificate")
		return nil, s.mapTPM2Error(err, "install IDevID certificate")
	}

	s.logger.Info("IDevID certificate installed", "subject", cert.Subject.CommonName)

	return &platformv1.InstallIDevIDCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IDevID certificate installed successfully",
		},
	}, nil
}

// InstallIAKCertificate installs an IAK certificate.
func (s *IDevIDGRPCService) InstallIAKCertificate(ctx context.Context, req *platformv1.InstallIAKCertificateRequest) (*platformv1.InstallIAKCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	certPEM := req.GetCertificatePem()
	if len(certPEM) == 0 {
		return nil, status.Error(codes.InvalidArgument, "certificate PEM is required")
	}

	// Parse PEM certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate PEM format")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid certificate: "+err.Error())
	}

	// Install using TPM2
	if err := s.tpm2Service.ProvisionIAKCert(cert); err != nil {
		s.logger.Error(err, "Failed to install IAK certificate")
		return nil, s.mapTPM2Error(err, "install IAK certificate")
	}

	s.logger.Info("IAK certificate installed", "subject", cert.Subject.CommonName)

	return &platformv1.InstallIAKCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IAK certificate installed successfully",
		},
	}, nil
}

// GetIDevIDCertificate retrieves the installed IDevID certificate.
func (s *IDevIDGRPCService) GetIDevIDCertificate(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest) (*platformv1.GetIDevIDCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	cert, err := s.tpm2Service.IDevIDCertificate()
	if err != nil {
		s.logger.Error(err, "Failed to get IDevID certificate")
		return nil, status.Error(codes.NotFound, "IDevID certificate not found")
	}

	return &platformv1.GetIDevIDCertificateResponse{
		Certificate: s.certToProto(cert),
	}, nil
}

// GetIAKCertificate retrieves the installed IAK certificate.
func (s *IDevIDGRPCService) GetIAKCertificate(ctx context.Context, req *platformv1.GetIAKCertificateRequest) (*platformv1.GetIAKCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	cert, err := s.tpm2Service.IAKCertificate()
	if err != nil {
		s.logger.Error(err, "Failed to get IAK certificate")
		return nil, status.Error(codes.NotFound, "IAK certificate not found")
	}

	return &platformv1.GetIAKCertificateResponse{
		Certificate: s.certToProto(cert),
	}, nil
}

// DeleteIDevIDCertificate removes the installed IDevID certificate.
func (s *IDevIDGRPCService) DeleteIDevIDCertificate(ctx context.Context, req *platformv1.DeleteIDevIDCertificateRequest) (*platformv1.DeleteIDevIDCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	if err := s.tpm2Service.DeleteIDevIDCertificate(); err != nil {
		s.logger.Error(err, "Failed to delete IDevID certificate")
		return nil, s.mapTPM2Error(err, "delete IDevID certificate")
	}

	s.logger.Info("IDevID certificate deleted")

	return &platformv1.DeleteIDevIDCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IDevID certificate deleted successfully",
		},
	}, nil
}

// DeleteIAKCertificate removes the installed IAK certificate.
func (s *IDevIDGRPCService) DeleteIAKCertificate(ctx context.Context, req *platformv1.DeleteIAKCertificateRequest) (*platformv1.DeleteIAKCertificateResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	if err := s.tpm2Service.DeleteIAKCertificate(); err != nil {
		s.logger.Error(err, "Failed to delete IAK certificate")
		return nil, s.mapTPM2Error(err, "delete IAK certificate")
	}

	s.logger.Info("IAK certificate deleted")

	return &platformv1.DeleteIAKCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "IAK certificate deleted successfully",
		},
	}, nil
}

// =============================================================================
// Device Operations
// =============================================================================

// GetDeviceAttributes retrieves TCG device attributes from TPM and platform.
func (s *IDevIDGRPCService) GetDeviceAttributes(ctx context.Context, req *platformv1.GetDeviceAttributesRequest) (*platformv1.GetDeviceAttributesResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Use go-xkms's platform discovery (package-level function)
	platformAttrs := xkmssdk.DiscoverPlatformAttributes()

	// Get TPM properties
	var tpmManufacturer, tpmModel, tpmVersion string
	props, err := s.tpm2Service.FixedProperties()
	if err == nil && props != nil {
		tpmManufacturer = props.Manufacturer
		tpmModel = props.Family
		tpmVersion = fmt.Sprintf("%d.%d", props.FwMajor, props.FwMinor)
	}

	return &platformv1.GetDeviceAttributesResponse{
		Attributes: &platformv1.TCGDeviceAttributes{
			TpmManufacturer:      tpmManufacturer,
			TpmModel:             tpmModel,
			TpmVersion:           tpmVersion,
			PlatformManufacturer: platformAttrs.Manufacturer,
			PlatformModel:        platformAttrs.Model,
			PlatformVersion:      platformAttrs.Version,
			PlatformSerial:       platformAttrs.Serial,
		},
	}, nil
}

// FlushTransientContexts flushes all transient TPM contexts.
func (s *IDevIDGRPCService) FlushTransientContexts(ctx context.Context, req *platformv1.FlushTransientContextsRequest) (*platformv1.FlushTransientContextsResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	// Note: FlushTransientHandles is not in the TrustedPlatformModule interface.
	// This operation is not supported via the interface.
	// Return unimplemented for now.
	return nil, status.Error(codes.Unimplemented, "flush transient contexts not supported via gRPC")
}

// ActivateCredential decrypts a credential blob using the EK and AK.
func (s *IDevIDGRPCService) ActivateCredential(ctx context.Context, req *platformv1.ActivateCredentialRequest) (*platformv1.ActivateCredentialResponse, error) {
	if s.tpm2Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "TPM2 service not initialized")
	}

	credentialBlob := req.GetCredentialBlob()
	secret := req.GetSecret()

	if len(credentialBlob) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credential_blob is required")
	}
	if len(secret) == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret is required")
	}

	// Activate credential using TPM2 interface
	decrypted, err := s.tpm2Service.ActivateCredential(credentialBlob, secret)
	if err != nil {
		s.logger.Error(err, "Failed to activate credential")
		return nil, s.mapTPM2Error(err, "activate credential")
	}

	s.logger.Info("Credential activated successfully")

	return &platformv1.ActivateCredentialResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Credential activated successfully",
		},
		DecryptedSecret: decrypted,
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// certToProto converts an x509.Certificate to a platformv1.DeviceIdentityCertificate.
func (s *IDevIDGRPCService) certToProto(cert *x509.Certificate) *platformv1.DeviceIdentityCertificate {
	if cert == nil {
		return nil
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)

	// Determine key algorithm
	keyAlgo := "unknown"
	keySize := uint32(0)
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		keyAlgo = "RSA"
	case x509.ECDSA:
		keyAlgo = "ECDSA"
	case x509.Ed25519:
		keyAlgo = "Ed25519"
	}

	return &platformv1.DeviceIdentityCertificate{
		Pem:                pemBytes,
		Der:                cert.Raw,
		KeyType:            keyAlgo,
		IssuedAt:           timestamppb.New(cert.NotBefore),
		ExpiresAt:          timestamppb.New(cert.NotAfter),
		IssuerCn:           cert.Issuer.CommonName,
		SubjectCn:          cert.Subject.CommonName,
		SerialNumber:       cert.SerialNumber.String(),
		Fingerprint:        hex.EncodeToString(fingerprint[:]),
		KeyAlgorithm:       keyAlgo,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeySize:            keySize,
	}
}

// mapTPM2Error maps TPM2 errors to appropriate gRPC status codes.
func (s *IDevIDGRPCService) mapTPM2Error(err error, operation string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common TPM2 error patterns
	switch {
	case strings.Contains(errStr, "not found") || strings.Contains(errStr, "does not exist") || strings.Contains(errStr, "no such"):
		return status.Error(codes.NotFound, operation+": "+errStr)
	case strings.Contains(errStr, "already exists") || strings.Contains(errStr, "duplicate"):
		return status.Error(codes.AlreadyExists, operation+": "+errStr)
	case strings.Contains(errStr, "invalid") || strings.Contains(errStr, "malformed"):
		return status.Error(codes.InvalidArgument, operation+": "+errStr)
	case strings.Contains(errStr, "permission") || strings.Contains(errStr, "unauthorized") || strings.Contains(errStr, "forbidden"):
		return status.Error(codes.PermissionDenied, operation+": "+errStr)
	case strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline"):
		return status.Error(codes.DeadlineExceeded, operation+": "+errStr)
	case strings.Contains(errStr, "unavailable") || strings.Contains(errStr, "not ready"):
		return status.Error(codes.Unavailable, operation+": "+errStr)
	default:
		return status.Error(codes.Internal, operation+" failed: "+errStr)
	}
}
