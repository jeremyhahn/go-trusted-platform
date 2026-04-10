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

	pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Unix Socket Protocol Adapter
// =============================================================================

// UnixAdapter implements CACommands using gRPC over Unix domain socket to platformd.
// This reuses the same protobuf CAServiceClient as the gRPC adapter, but connects
// via a Unix domain socket instead of TCP.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	ca         pb.CAServiceClient
}

// NewUnixAdapter creates a new Unix socket protocol adapter instance.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup initializes the gRPC connection over Unix domain socket.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	socketPath := os.Getenv(EnvPlatformUnixSocket)
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformUnix
	}
	u.socketPath = socketPath

	// Verify socket file exists
	if _, err := os.Stat(u.socketPath); os.IsNotExist(err) {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: u.socketPath, Err: err}
	}

	conn, err := grpc.NewClient(
		"unix://"+u.socketPath,
		helpers.GRPCUnixCredentials(),
	)
	if err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: u.socketPath, Err: err}
	}

	u.conn = conn
	u.ca = pb.NewCAServiceClient(conn)

	// Verify connectivity by getting CA info
	_, err = u.ca.GetCAInfo(ctx, &pb.GetCAInfoRequest{})
	if err != nil {
		conn.Close()
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: u.socketPath, Err: err}
	}

	return nil
}

// Teardown closes the Unix socket connection.
func (u *UnixAdapter) Teardown() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// =============================================================================
// CA Info Operations
// =============================================================================

// Info retrieves CA information via Unix socket.
func (u *UnixAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := u.ca.GetCAInfo(ctx, &pb.GetCAInfoRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "GetCAInfo", Err: err}
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

// Init initializes the CA via Unix socket.
// Note: CA initialization is done during daemon startup, not via gRPC.
func (u *UnixAdapter) Init(ctx context.Context, opts InitOptions) (*InitResult, error) {
	return nil, ErrNotImplemented{Feature: "CA init via Unix"}
}

// =============================================================================
// Certificate Issue Operations
// =============================================================================

// IssueCertificate issues a new certificate via Unix socket.
func (u *UnixAdapter) IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error) {
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

	resp, err := u.ca.IssueCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "IssueCertificate", Err: err}
	}

	result := &IssueCertificateResult{
		Success: resp.Status != nil && resp.Status.Success,
	}

	if resp.Certificate != nil {
		result.Certificate = convertCertificate(resp.Certificate)
	}

	return result, nil
}

// =============================================================================
// Certificate Get Operations
// =============================================================================

// GetCertificate retrieves a certificate via Unix socket.
// The serial field in the proto accepts either a hex-encoded serial number or
// a common name, so when Serial is empty but CommonName is provided, the
// CommonName is sent as the serial field for CN-based lookup.
func (u *UnixAdapter) GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error) {
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

	resp, err := u.ca.GetCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "GetCertificate", Err: err}
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

// ListCertificates lists certificates via Unix socket.
func (u *UnixAdapter) ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error) {
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

	resp, err := u.ca.ListCertificates(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "ListCertificates", Err: err}
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

// VerifyCertificate verifies a certificate via Unix socket.
func (u *UnixAdapter) VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error) {
	req := &pb.VerifyCertificateRequest{
		CertificatePem:   opts.CertificatePEM,
		VerifyRevocation: opts.CheckCRL,
		VerifyExpiration: opts.CheckExpiration,
	}

	resp, err := u.ca.VerifyCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "VerifyCertificate", Err: err}
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

// RevokeCertificate revokes a certificate via Unix socket.
func (u *UnixAdapter) RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error) {
	req := &pb.RevokeCertificateRequest{
		Serial:     opts.Serial,
		Reason:     pb.RevocationReason(opts.Reason),
		DeleteKeys: opts.DeleteKeys,
	}

	resp, err := u.ca.RevokeCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "RevokeCertificate", Err: err}
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

// RenewCertificate renews a certificate via Unix socket.
func (u *UnixAdapter) RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error) {
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

	resp, err := u.ca.RenewCertificate(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "RenewCertificate", Err: err}
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

// GetCRL retrieves the CRL via Unix socket.
func (u *UnixAdapter) GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error) {
	req := &pb.GetCRLRequest{
		IncludeEntries: opts.IncludeEntries,
	}

	resp, err := u.ca.GetCRL(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "GetCRL", Err: err}
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

// GenerateCRL generates a new CRL via Unix socket.
func (u *UnixAdapter) GenerateCRL(ctx context.Context) (*GenerateCRLResult, error) {
	resp, err := u.ca.GetCRL(ctx, &pb.GetCRLRequest{})
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "GenerateCRL", Err: err}
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

// ExportCRL exports the CRL via Unix socket.
// Note: CRL export to file is a CLI operation, not exposed via gRPC.
func (u *UnixAdapter) ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error) {
	return nil, ErrNotImplemented{Feature: "CRL export via Unix"}
}

// =============================================================================
// Export Bundle Operations
// =============================================================================

// ExportBundle exports the CA bundle via Unix socket.
func (u *UnixAdapter) ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error) {
	req := &pb.GetCABundleRequest{
		IncludeIntermediates: true,
	}

	resp, err := u.ca.GetCABundle(ctx, req)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "Unix", Method: "GetCABundle", Err: err}
	}

	result := &ExportBundleResult{
		Success: resp.Bundle != nil && len(resp.Bundle.Pem) > 0,
	}

	if resp.Bundle != nil {
		result.CertCount = resp.Bundle.CertCount
		result.Size = int64(len(resp.Bundle.Pem))

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

// InstallCACertificates installs CA certificates via Unix socket.
// Note: CA certificate installation is a local OS operation, not exposed via gRPC.
func (u *UnixAdapter) InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error) {
	return nil, ErrNotImplemented{Feature: "install CA certificates via Unix"}
}

// UninstallCACertificates uninstalls CA certificates via Unix socket.
// Note: CA certificate uninstallation is a local OS operation, not exposed via gRPC.
func (u *UnixAdapter) UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error) {
	return nil, ErrNotImplemented{Feature: "uninstall CA certificates via Unix"}
}

// Ensure UnixAdapter implements CACommands interface.
var _ CACommands = (*UnixAdapter)(nil)
