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
	"context"
	"os"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"google.golang.org/grpc"
)

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements CACommands using gRPC calls to platformd.
type GRPCAdapter struct {
	conn *grpc.ClientConn
	ca   pb.CAServiceClient
}

// NewGRPCAdapter creates a new gRPC protocol adapter instance.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{}
}

// Name returns the protocol adapter identifier.
func (g *GRPCAdapter) Name() string {
	return "gRPC"
}

// Setup initializes the gRPC connection to platformd.
func (g *GRPCAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformGRPCEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformGRPC
	}

	conn, err := grpc.NewClient(endpoint,
		helpers.GRPCTransportCredentials(),
	)
	if err != nil {
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}

	g.conn = conn
	g.ca = pb.NewCAServiceClient(conn)

	// Verify connectivity by getting CA info
	_, err = g.ca.GetCAInfo(ctx, &pb.GetCAInfoRequest{})
	if err != nil {
		conn.Close()
		return ErrConnectionFailed{Protocol: "gRPC", Endpoint: endpoint, Err: err}
	}

	return nil
}

// Teardown closes the gRPC connection.
func (g *GRPCAdapter) Teardown() error {
	if g.conn != nil {
		return g.conn.Close()
	}
	return nil
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via gRPC.
func (g *GRPCAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := g.ca.GetCAInfo(ctx, &pb.GetCAInfoRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetCAInfo", Err: err}
	}

	result := &InfoResult{}
	if resp.CaInfo != nil {
		result.CommonName = resp.CaInfo.CommonName
		result.IsInitialized = resp.CaInfo.IsInitialized
		result.IsIntermediate = resp.CaInfo.IsIntermediate
		result.DefaultAlgorithm = resp.CaInfo.DefaultAlgorithm
		result.DefaultValidityDays = resp.CaInfo.DefaultValidityDays

		if resp.CaInfo.RootCert != nil {
			result.RootCertificate = convertCertificateSummary(resp.CaInfo.RootCert)
		}

		for _, intermediate := range resp.CaInfo.Intermediates {
			if intermediate != nil {
				result.Intermediates = append(result.Intermediates, *convertCertificateSummary(intermediate))
			}
		}

		for _, ks := range resp.CaInfo.KeyStores {
			if ks != nil {
				result.KeyStores = append(result.KeyStores, KeyStoreInfo{
					Type:         ks.Type,
					Available:    ks.Available,
					Capabilities: ks.Capabilities,
				})
			}
		}
	}

	return result, nil
}

// =============================================================================
// CA Init Operations
// =============================================================================

// Init initializes the CA via gRPC.
// Note: CA initialization is typically done during daemon startup, not via gRPC.
// This method returns an error as init is not exposed via gRPC.
func (g *GRPCAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "CA init"}
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via gRPC.
func (g *GRPCAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
	resp, err := g.ca.IssueCertificate(ctx, issueCertificateRequest(opts))
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "IssueCertificate", Err: err}
	}
	return issueResult(resp), nil
}

// issueCertificateRequest builds the IssueCertificate request the gRPC and
// REST adapters both send.
func issueCertificateRequest(opts IssueCertificateOptions) *pb.IssueCertificateRequest {
	req := &pb.IssueCertificateRequest{
		Request: &pb.CertificateRequest{
			Subject: &pb.Subject{
				CommonName: opts.CommonName,
			},
			ValidDays:    opts.ValidDays,
			KeyAlgorithm: parseKeyAlgorithm(opts.Algorithm),
			StoreType:    opts.StoreType,
			IsCa:         opts.IsCA,
			MaxPathLen:   opts.MaxPathLen,
			KeyUsage:     opts.KeyUsage,
			ExtKeyUsage:  opts.ExtKeyUsage,
		},
	}

	if len(opts.SANsDNS) > 0 || len(opts.SANsIPs) > 0 || len(opts.SANsEmail) > 0 {
		req.Request.Sans = &pb.SubjectAlternativeNames{
			DnsNames:       opts.SANsDNS,
			IpAddresses:    opts.SANsIPs,
			EmailAddresses: opts.SANsEmail,
		}
	}
	return req
}

// SignCSR certifies a KMS key for code signing via gRPC.
func (g *GRPCAdapter) SignCSR(ctx context.Context, opts SignCSROptions) (*IssueCertificateResult, error) {
	resp, err := g.ca.SignCSR(ctx, &pb.SignCSRRequest{CsrPem: opts.CSRPEM, ValidDays: opts.ValidDays})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "SignCSR", Err: err}
	}
	return issueResult(resp), nil
}

// issueResult converts the response IssueCertificate and SignCSR share; the
// gRPC, Unix and REST adapters all use it.
func issueResult(resp *pb.IssueCertificateResponse) *IssueCertificateResult {
	result := &IssueCertificateResult{
		Success: resp.Status != nil && resp.Status.Success,
	}

	if resp.Certificate != nil {
		result.Certificate = convertCertificate(resp.Certificate)
	}

	return result
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via gRPC.
// The serial field in the proto accepts either a hex-encoded serial number or
// a common name, so when Serial is empty but CommonName is provided, the
// CommonName is sent as the serial field for CN-based lookup.
func (g *GRPCAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
	// Determine the identifier to send: prefer Serial, fall back to CommonName
	identifier := opts.Serial
	if identifier == "" && opts.CommonName != "" {
		identifier = opts.CommonName
	}

	req := &pb.GetCertificateRequest{
		Serial:     identifier,
		IncludePem: opts.IncludePEM,
		IncludeDer: opts.IncludeDER,
	}

	resp, err := g.ca.GetCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetCertificate", Err: err}
	}

	result := &GetCertificateResult{}
	if resp.Certificate != nil {
		result.Certificate = convertCertificate(resp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate List Operations
// =============================================================================

// ListCertificates lists certificates via gRPC.
func (g *GRPCAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
	req := &pb.ListCertificatesRequest{
		StatusFilter: parseCertificateStatus(opts.Status),
		IssuerFilter: opts.Issuer,
	}

	if opts.Limit > 0 || opts.Offset > 0 {
		var pageNum uint32
		if opts.Limit > 0 {
			pageNum = uint32(opts.Offset / opts.Limit)
		}
		req.Pagination = &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     pageNum,
		}
	}

	resp, err := g.ca.ListCertificates(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "ListCertificates", Err: err}
	}

	result := &ListCertificatesResult{
		Certificates: make([]CertificateSummary, 0, len(resp.Certificates)),
	}

	for _, cert := range resp.Certificates {
		if cert != nil {
			result.Certificates = append(result.Certificates, *convertCertificateSummary(cert))
		}
	}

	if resp.Pagination != nil {
		result.Total = int32(resp.Pagination.TotalItems)
	}

	return result, nil
}

// =============================================================================
// Certificate Verify Operations
// =============================================================================

// VerifyCertificate verifies a certificate via gRPC.
func (g *GRPCAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	req := &pb.VerifyCertificateRequest{
		CertificatePem:   opts.CertificatePEM,
		VerifyRevocation: opts.CheckCRL,
		VerifyExpiration: opts.CheckExpiration,
	}

	resp, err := g.ca.VerifyCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "VerifyCertificate", Err: err}
	}

	result := &VerifyCertificateResult{
		Valid:         resp.Valid,
		Revoked:       resp.Revoked,
		ChainValid:    resp.Valid && len(resp.Errors) == 0,
		ChainLength:   len(resp.Chain),
		ChainSubjects: resp.Chain,
		Errors:        resp.Errors,
		Warnings:      resp.Warnings,
	}

	if resp.Status != nil && !resp.Status.Success {
		result.ValidationError = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// Certificate Revoke Operations
// =============================================================================

// RevokeCertificate revokes a certificate via gRPC.
func (g *GRPCAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	req := &pb.RevokeCertificateRequest{
		Serial:     opts.Serial,
		Reason:     pb.RevocationReason(opts.Reason),
		DeleteKeys: opts.DeleteKeys,
	}

	resp, err := g.ca.RevokeCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "RevokeCertificate", Err: err}
	}

	result := &RevokeCertificateResult{
		Success: resp.Status != nil && resp.Status.Success,
		Serial:  resp.Serial,
		Status:  CertificateStatus(resp.CertificateStatus),
		Reason:  RevocationReason(resp.Reason),
	}

	if resp.RevokedAt != nil {
		result.RevokedAt = resp.RevokedAt.AsTime()
	}

	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// Certificate Renew Operations
// =============================================================================

// RenewCertificate renews a certificate via gRPC.
func (g *GRPCAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
	req := &pb.RenewCertificateRequest{
		Serial:       opts.Serial,
		ValidDays:    opts.ValidDays,
		PreserveSans: opts.PreserveSANs,
	}

	if len(opts.NewSANsDNS) > 0 || len(opts.NewSANsIPs) > 0 || len(opts.NewSANsEmail) > 0 {
		req.NewSans = &pb.SubjectAlternativeNames{
			DnsNames:       opts.NewSANsDNS,
			IpAddresses:    opts.NewSANsIPs,
			EmailAddresses: opts.NewSANsEmail,
		}
	}

	resp, err := g.ca.RenewCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "RenewCertificate", Err: err}
	}

	result := &RenewCertificateResult{
		Success: resp.Status != nil && resp.Status.Success,
	}

	if resp.OldCertificate != nil {
		result.OldCertificate = convertCertificate(resp.OldCertificate)
	}

	if resp.NewCertificate != nil {
		result.NewCertificate = convertCertificate(resp.NewCertificate)
	}

	if resp.Status != nil {
		result.Message = resp.Status.Message
	}

	return result, nil
}

// =============================================================================
// CRL Operations
// =============================================================================

// GetCRL retrieves the CRL via gRPC.
func (g *GRPCAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	req := &pb.GetCRLRequest{
		IncludeEntries: opts.IncludeEntries,
	}

	resp, err := g.ca.GetCRL(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetCRL", Err: err}
	}

	result := &GetCRLResult{}
	if resp.Crl != nil {
		result.Data = resp.Crl.Data
		result.RevokedCount = resp.Crl.RevokedCount

		if resp.Crl.LastUpdate != nil {
			result.ThisUpdate = resp.Crl.LastUpdate.AsTime()
		}

		if resp.Crl.NextUpdate != nil {
			result.NextUpdate = resp.Crl.NextUpdate.AsTime()
		}

		for _, entry := range resp.Crl.RevokedCerts {
			if entry != nil {
				rce := RevokedCertEntry{
					Serial: entry.Serial,
					Reason: RevocationReason(entry.Reason),
				}
				if entry.RevocationTime != nil {
					rce.RevocationTime = entry.RevocationTime.AsTime()
				}
				result.RevokedCerts = append(result.RevokedCerts, rce)
			}
		}
	}

	return result, nil
}

// GenerateCRL generates a new CRL via gRPC.
func (g *GRPCAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	resp, err := g.ca.GetCRL(ctx, &pb.GetCRLRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GenerateCRL", Err: err}
	}

	result := &GenerateCRLResult{Success: true}
	if resp.Crl != nil {
		if resp.Crl.LastUpdate != nil {
			result.ThisUpdate = resp.Crl.LastUpdate.AsTime()
		}
		if resp.Crl.NextUpdate != nil {
			result.NextUpdate = resp.Crl.NextUpdate.AsTime()
		}
	}

	return result, nil
}

// ExportCRL exports the CRL via gRPC.
// Note: CRL export to file is a CLI operation, not exposed via gRPC.
func (g *GRPCAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "CRL export"}
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via gRPC.
func (g *GRPCAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	req := &pb.GetCABundleRequest{
		IncludeIntermediates: true,
	}

	resp, err := g.ca.GetCABundle(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "gRPC", Method: "GetCABundle", Err: err}
	}

	result := &ExportBundleResult{
		Success: resp.Bundle != nil && len(resp.Bundle.Pem) > 0,
	}

	if resp.Bundle != nil {
		result.CertCount = resp.Bundle.CertCount
		result.Size = int64(len(resp.Bundle.Pem))

		// If output path specified, write to file
		if output != "" {
			if err := os.WriteFile(output, resp.Bundle.Pem, 0644); err != nil {
				return nil, ErrExportFailed{Type: "CA bundle", Path: output, Reason: err.Error()}
			}
			result.FilePath = output
		}
	}

	return result, nil
}

// =============================================================================
// Install/Uninstall Operations
// =============================================================================

// InstallCACertificates installs CA certificates via gRPC.
// Note: CA certificate installation is a local OS operation, not exposed via gRPC.
func (g *GRPCAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "install CA certificates"}
}

// UninstallCACertificates uninstalls CA certificates via gRPC.
// Note: CA certificate uninstallation is a local OS operation, not exposed via gRPC.
func (g *GRPCAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "uninstall CA certificates"}
}

// =============================================================================
// Helper Functions
// =============================================================================

// parseKeyAlgorithm converts a string algorithm name to the proto enum value.
func parseKeyAlgorithm(algorithm string) pb.KeyAlgorithm {
	switch algorithm {
	case "RSA-2048", "RSA2048", "rsa":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	case "RSA-3072", "RSA3072":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_3072
	case "RSA-4096", "RSA4096":
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_4096
	case "ECDSA-P256", "ECDSAP256", "P256", "ecdsa":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	case "ECDSA-P384", "ECDSAP384", "P384":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384
	case "ECDSA-P521", "ECDSAP521", "P521":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521
	case "Ed25519", "ED25519":
		return pb.KeyAlgorithm_KEY_ALGORITHM_ED25519
	default:
		return pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048
	}
}

// formatKeyAlgorithm converts a proto enum value to a human-readable string.
func formatKeyAlgorithm(alg pb.KeyAlgorithm) string {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_2048:
		return "RSA-2048"
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_3072:
		return "RSA-3072"
	case pb.KeyAlgorithm_KEY_ALGORITHM_RSA_4096:
		return "RSA-4096"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256:
		return "ECDSA-P256"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384:
		return "ECDSA-P384"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P521:
		return "ECDSA-P521"
	case pb.KeyAlgorithm_KEY_ALGORITHM_ED25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// parseCertificateStatus converts a string status to the proto enum value.
func parseCertificateStatus(status string) pb.CertificateStatus {
	switch status {
	case "valid", "active":
		return pb.CertificateStatus_CERTIFICATE_STATUS_VALID
	case "revoked":
		return pb.CertificateStatus_CERTIFICATE_STATUS_REVOKED
	case "expired":
		return pb.CertificateStatus_CERTIFICATE_STATUS_EXPIRED
	case "pending":
		return pb.CertificateStatus_CERTIFICATE_STATUS_PENDING
	default:
		return pb.CertificateStatus_CERTIFICATE_STATUS_UNSPECIFIED
	}
}

// convertCertificateSummary converts a proto CertificateSummary to our type.
func convertCertificateSummary(cert *pb.CertificateSummary) *CertificateSummary {
	if cert == nil {
		return nil
	}

	result := &CertificateSummary{
		Serial:       cert.Serial,
		CommonName:   cert.CommonName,
		Issuer:       cert.Issuer,
		Status:       CertificateStatus(cert.Status),
		KeyAlgorithm: formatKeyAlgorithm(cert.KeyAlgorithm),
	}

	if cert.NotBefore != nil {
		result.NotBefore = cert.NotBefore.AsTime()
	}

	if cert.NotAfter != nil {
		result.NotAfter = cert.NotAfter.AsTime()
	}

	return result
}

// convertCertificate converts a proto Certificate to our type.
func convertCertificate(cert *pb.Certificate) *Certificate {
	if cert == nil {
		return nil
	}

	result := &Certificate{
		Serial:             cert.Serial,
		Issuer:             cert.Issuer,
		Status:             CertificateStatus(cert.Status),
		KeyAlgorithm:       formatKeyAlgorithm(cert.KeyAlgorithm),
		SignatureAlgorithm: cert.SignatureAlgorithm,
		IsCA:               cert.IsCa,
		MaxPathLen:         cert.MaxPathLen,
		KeyUsage:           cert.KeyUsage,
		ExtKeyUsage:        cert.ExtKeyUsage,
		PEM:                cert.Pem,
		DER:                cert.Der,
		FingerprintSHA256:  cert.FingerprintSha256,
	}

	if cert.Subject != nil {
		result.Subject = Subject{
			CommonName:         cert.Subject.CommonName,
			Organization:       cert.Subject.Organization,
			OrganizationalUnit: cert.Subject.OrganizationalUnit,
			Country:            cert.Subject.Country,
			Province:           cert.Subject.Province,
			Locality:           cert.Subject.Locality,
			Address:            cert.Subject.Address,
			PostalCode:         cert.Subject.PostalCode,
		}
	}

	if cert.NotBefore != nil {
		result.NotBefore = cert.NotBefore.AsTime()
	}

	if cert.NotAfter != nil {
		result.NotAfter = cert.NotAfter.AsTime()
	}

	if cert.Sans != nil {
		result.SANsDNS = cert.Sans.DnsNames
		result.SANsIPs = cert.Sans.IpAddresses
		result.SANsEmail = cert.Sans.EmailAddresses
		result.SANsURIs = cert.Sans.Uris
	}

	return result
}

// Ensure GRPCAdapter implements CACommands interface.
var _ CACommands = (*GRPCAdapter)(nil)
