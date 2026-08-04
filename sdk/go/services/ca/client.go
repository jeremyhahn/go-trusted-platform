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

// Package ca provides a client for Certificate Authority service operations.
package ca

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// RevocationStatus contains the revocation status of a certificate.
type RevocationStatus struct {
	Revoked   bool
	Reason    platformv1.RevocationReason
	RevokedAt string
}

// InstallResult contains the result of installing CA certificates.
type InstallResult struct {
	CertificatesInstalled int32
	InstallPath           string
}

// UninstallResult contains the result of uninstalling CA certificates.
type UninstallResult struct {
	CertificatesRemoved int32
}

// Client provides access to CA service operations.
type Client struct {
	grpc platformv1.CAServiceClient
}

// NewClient creates a new CA service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewCAServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new CA service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.CAServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// GetCAInfo returns information about the Certificate Authority.
func (c *Client) GetCAInfo(ctx context.Context) (*platformv1.CAInfo, error) {
	resp, err := c.grpc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		return nil, &ErrGetCAInfoFailed{Cause: err}
	}
	return resp.CaInfo, nil
}

// InitCA initializes the Certificate Authority.
// If force is true, reinitializes even if already initialized.
func (c *Client) InitCA(ctx context.Context, force bool) (*platformv1.CAInfo, error) {
	resp, err := c.grpc.InitCA(ctx, &platformv1.InitCARequest{
		Force: force,
	})
	if err != nil {
		return nil, &ErrInitCAFailed{Cause: err}
	}
	return resp.CaInfo, nil
}

// InstallCACertificates installs CA certificates to the system trust store.
// If includeIntermediates is true, intermediate certificates are also installed.
func (c *Client) InstallCACertificates(ctx context.Context, includeIntermediates bool) (*InstallResult, error) {
	resp, err := c.grpc.InstallCACertificates(ctx, &platformv1.InstallCACertificatesRequest{
		IncludeIntermediates: includeIntermediates,
	})
	if err != nil {
		return nil, &ErrInstallCACertificatesFailed{Cause: err}
	}
	return &InstallResult{
		CertificatesInstalled: resp.CertificatesInstalled,
		InstallPath:           resp.InstallPath,
	}, nil
}

// UninstallCACertificates removes CA certificates from the system trust store.
// If includeIntermediates is true, intermediate certificates are also removed.
func (c *Client) UninstallCACertificates(ctx context.Context, includeIntermediates bool) (*UninstallResult, error) {
	resp, err := c.grpc.UninstallCACertificates(ctx, &platformv1.UninstallCACertificatesRequest{
		IncludeIntermediates: includeIntermediates,
	})
	if err != nil {
		return nil, &ErrUninstallCACertificatesFailed{Cause: err}
	}
	return &UninstallResult{
		CertificatesRemoved: resp.CertificatesRemoved,
	}, nil
}

// IssueCertificate issues a new certificate.
func (c *Client) IssueCertificate(ctx context.Context, req *platformv1.CertificateRequest) (*platformv1.Certificate, error) {
	resp, err := c.grpc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{Request: req})
	if err != nil {
		return nil, &ErrIssueCertificateFailed{Cause: err}
	}
	return resp.Certificate, nil
}

// GetCertificate retrieves a certificate by serial number.
func (c *Client) GetCertificate(ctx context.Context, serial string, includePEM, includeDER bool) (*platformv1.Certificate, error) {
	resp, err := c.grpc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: includePEM,
		IncludeDer: includeDER,
	})
	if err != nil {
		return nil, &ErrGetCertificateFailed{Serial: serial, Cause: err}
	}
	return resp.Certificate, nil
}

// ListCertificates returns a paginated list of certificates.
func (c *Client) ListCertificates(ctx context.Context, req *platformv1.ListCertificatesRequest) ([]*platformv1.CertificateSummary, *common.PageResult, error) {
	resp, err := c.grpc.ListCertificates(ctx, req)
	if err != nil {
		return nil, nil, &ErrListCertificatesFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Certificates, pageResult, nil
}

// RevokeCertificate revokes a certificate.
func (c *Client) RevokeCertificate(ctx context.Context, serial string, reason platformv1.RevocationReason, deleteKeys bool) (*platformv1.RevokeCertificateResponse, error) {
	resp, err := c.grpc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     reason,
		DeleteKeys: deleteKeys,
	})
	if err != nil {
		return nil, &ErrRevokeCertificateFailed{Serial: serial, Cause: err}
	}
	return resp, nil
}

// RenewCertificate renews an existing certificate.
func (c *Client) RenewCertificate(ctx context.Context, serial string, validDays int32, preserveSANs bool, newSANs *platformv1.SubjectAlternativeNames) (*platformv1.RenewCertificateResponse, error) {
	resp, err := c.grpc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:       serial,
		ValidDays:    validDays,
		PreserveSans: preserveSANs,
		NewSans:      newSANs,
	})
	if err != nil {
		return nil, &ErrRenewCertificateFailed{Serial: serial, Cause: err}
	}
	return resp, nil
}

// VerifyCertificate verifies a certificate chain.
func (c *Client) VerifyCertificate(ctx context.Context, req *platformv1.VerifyCertificateRequest) (*platformv1.VerifyCertificateResponse, error) {
	resp, err := c.grpc.VerifyCertificate(ctx, req)
	if err != nil {
		return nil, &ErrVerifyCertificateFailed{Cause: err}
	}
	return resp, nil
}

// GetCRL returns the current Certificate Revocation List.
func (c *Client) GetCRL(ctx context.Context, includeEntries bool) (*platformv1.CRL, error) {
	resp, err := c.grpc.GetCRL(ctx, &platformv1.GetCRLRequest{IncludeEntries: includeEntries})
	if err != nil {
		return nil, &ErrGetCRLFailed{Cause: err}
	}
	return resp.Crl, nil
}

// GetCABundle returns the CA certificate bundle.
func (c *Client) GetCABundle(ctx context.Context, includeIntermediates bool) (*platformv1.CABundle, error) {
	resp, err := c.grpc.GetCABundle(ctx, &platformv1.GetCABundleRequest{IncludeIntermediates: includeIntermediates})
	if err != nil {
		return nil, &ErrGetCABundleFailed{Cause: err}
	}
	return resp.Bundle, nil
}

// DownloadCRL returns the raw CRL data in binary (DER) format.
func (c *Client) DownloadCRL(ctx context.Context) ([]byte, error) {
	crl, err := c.GetCRL(ctx, false)
	if err != nil {
		return nil, err
	}
	if crl == nil {
		return nil, &ErrDownloadCRLFailed{Cause: ErrNilCRL}
	}
	return crl.Data, nil
}

// DownloadBundle returns the CA certificate bundle in PEM format.
func (c *Client) DownloadBundle(ctx context.Context, includeIntermediates bool) ([]byte, error) {
	bundle, err := c.GetCABundle(ctx, includeIntermediates)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, &ErrDownloadBundleFailed{Cause: ErrNilBundle}
	}
	return bundle.Pem, nil
}

// DownloadCertificatePEM returns a certificate in PEM format.
func (c *Client) DownloadCertificatePEM(ctx context.Context, serial string) ([]byte, error) {
	cert, err := c.GetCertificate(ctx, serial, true, false)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, &ErrDownloadCertificateFailed{Serial: serial, Cause: ErrNilCertificate}
	}
	if len(cert.Pem) == 0 {
		return nil, &ErrDownloadCertificateFailed{Serial: serial, Cause: ErrNoPEMData}
	}
	return cert.Pem, nil
}

// DownloadCertificateDER returns a certificate in DER (binary) format.
func (c *Client) DownloadCertificateDER(ctx context.Context, serial string) ([]byte, error) {
	cert, err := c.GetCertificate(ctx, serial, false, true)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, &ErrDownloadCertificateFailed{Serial: serial, Cause: ErrNilCertificate}
	}
	if len(cert.Der) == 0 {
		return nil, &ErrDownloadCertificateFailed{Serial: serial, Cause: ErrNoDERData}
	}
	return cert.Der, nil
}

// GetCertificateChain returns the certificate chain for the given serial.
// The chain is ordered from the certificate to the root CA.
func (c *Client) GetCertificateChain(ctx context.Context, serial string) ([]*platformv1.CertificateSummary, error) {
	cert, err := c.GetCertificate(ctx, serial, false, false)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, &ErrGetCertificateChainFailed{Serial: serial, Cause: ErrNilCertificate}
	}

	chain := []*platformv1.CertificateSummary{
		{
			Serial:       cert.Serial,
			CommonName:   cert.Subject.GetCommonName(),
			Issuer:       cert.Issuer,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			Status:       cert.Status,
			KeyAlgorithm: cert.KeyAlgorithm,
		},
	}

	bundle, err := c.GetCABundle(ctx, true)
	if err != nil {
		return nil, &ErrGetCertificateChainFailed{Serial: serial, Cause: err}
	}
	if bundle == nil || len(bundle.Certificates) == 0 {
		return chain, nil
	}

	issuer := cert.Issuer
	for issuer != "" {
		found := false
		for _, caCert := range bundle.Certificates {
			if caCert.CommonName == issuer {
				chain = append(chain, caCert)
				if caCert.CommonName == caCert.Issuer {
					return chain, nil
				}
				issuer = caCert.Issuer
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	return chain, nil
}

// IsRevoked checks if a certificate is revoked by its serial number.
func (c *Client) IsRevoked(ctx context.Context, serial string) (*RevocationStatus, error) {
	cert, err := c.GetCertificate(ctx, serial, false, false)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, &ErrCheckRevocationFailed{Serial: serial, Cause: ErrNilCertificate}
	}

	if cert.Status != platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		return &RevocationStatus{Revoked: false}, nil
	}

	crl, err := c.GetCRL(ctx, true)
	if err != nil {
		return &RevocationStatus{
			Revoked: true,
			Reason:  platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
		}, nil
	}

	if crl != nil {
		for _, entry := range crl.RevokedCerts {
			if entry.Serial == serial {
				revokedAt := ""
				if entry.RevocationTime != nil {
					revokedAt = entry.RevocationTime.AsTime().String()
				}
				return &RevocationStatus{
					Revoked:   true,
					Reason:    entry.Reason,
					RevokedAt: revokedAt,
				}, nil
			}
		}
	}

	return &RevocationStatus{
		Revoked: true,
		Reason:  platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
	}, nil
}
