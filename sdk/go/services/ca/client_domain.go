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
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// GetCAInfoDomain returns CA information as a domain type.
func (c *Client) GetCAInfoDomain(ctx context.Context) (*CAInfo, error) {
	resp, err := c.grpc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		return nil, &ErrGetCAInfoFailed{Cause: err}
	}
	return CAInfoFromProto(resp.CaInfo), nil
}

// InitCADomain initializes the CA and returns domain types.
func (c *Client) InitCADomain(ctx context.Context, force bool) (*CAInfo, error) {
	resp, err := c.grpc.InitCA(ctx, &platformv1.InitCARequest{Force: force})
	if err != nil {
		return nil, &ErrInitCAFailed{Cause: err}
	}
	return CAInfoFromProto(resp.CaInfo), nil
}

// GetCertificateDomain retrieves a certificate and returns a domain Certificate.
func (c *Client) GetCertificateDomain(ctx context.Context, params *GetCertificateParams) (*Certificate, error) {
	resp, err := c.grpc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     params.Serial,
		IncludePem: params.IncludePEM,
		IncludeDer: params.IncludeDER,
	})
	if err != nil {
		return nil, &ErrGetCertificateFailed{Serial: params.Serial, Cause: err}
	}
	return CertificateFromProto(resp.Certificate), nil
}

// ListCertificatesDomain lists certificates and returns domain types.
func (c *Client) ListCertificatesDomain(ctx context.Context, params *ListCertificatesParams) (*ListCertificatesResult, error) {
	req := listParamsToProto(params)
	resp, err := c.grpc.ListCertificates(ctx, req)
	if err != nil {
		return nil, &ErrListCertificatesFailed{Cause: err}
	}

	result := &ListCertificatesResult{}
	if len(resp.Certificates) > 0 {
		result.Certificates = make([]*CertificateSummary, len(resp.Certificates))
		for i, c := range resp.Certificates {
			result.Certificates[i] = CertificateSummaryFromProto(c)
		}
	}
	if resp.Pagination != nil {
		result.Page = resp.Pagination.Page
		result.TotalPages = resp.Pagination.TotalPages
		result.TotalItems = resp.Pagination.TotalItems
	}
	return result, nil
}

// IssueCertificateDomain issues a certificate and returns domain types.
func (c *Client) IssueCertificateDomain(ctx context.Context, params *IssueCertificateParams) (*IssueCertificateResult, error) {
	req := issueParamsToProto(params)
	resp, err := c.grpc.IssueCertificate(ctx, req)
	if err != nil {
		return nil, &ErrIssueCertificateFailed{Cause: err}
	}
	return &IssueCertificateResult{
		Certificate: CertificateFromProto(resp.Certificate),
	}, nil
}

// RevokeCertificateDomain revokes a certificate and returns domain types.
func (c *Client) RevokeCertificateDomain(ctx context.Context, params *RevokeCertificateParams) (*RevokeCertificateResult, error) {
	req := revokeParamsToProto(params)
	resp, err := c.grpc.RevokeCertificate(ctx, req)
	if err != nil {
		return nil, &ErrRevokeCertificateFailed{Serial: params.Serial, Cause: err}
	}

	result := &RevokeCertificateResult{
		Serial: resp.Serial,
		Reason: RevocationReasonFromProto(resp.Reason),
	}
	if resp.RevokedAt != nil {
		result.RevokedAt = resp.RevokedAt.AsTime()
	}
	if resp.Status != nil {
		result.Success = resp.Status.Success
		result.Message = resp.Status.Message
	}
	return result, nil
}

// RenewCertificateDomain renews a certificate and returns domain types.
func (c *Client) RenewCertificateDomain(ctx context.Context, params *RenewCertificateParams) (*RenewCertificateResult, error) {
	req := renewParamsToProto(params)
	resp, err := c.grpc.RenewCertificate(ctx, req)
	if err != nil {
		return nil, &ErrRenewCertificateFailed{Serial: params.Serial, Cause: err}
	}
	return &RenewCertificateResult{
		NewCertificate: CertificateFromProto(resp.NewCertificate),
	}, nil
}

// VerifyCertificateDomain verifies a certificate and returns domain types.
func (c *Client) VerifyCertificateDomain(ctx context.Context, params *VerifyCertificateParams) (*VerifyCertificateResult, error) {
	req := verifyParamsToProto(params)
	resp, err := c.grpc.VerifyCertificate(ctx, req)
	if err != nil {
		return nil, &ErrVerifyCertificateFailed{Cause: err}
	}
	return VerifyCertificateResultFromProto(resp), nil
}

// GetCRLDomain returns the CRL as domain types.
func (c *Client) GetCRLDomain(ctx context.Context, includeEntries bool) (*CRL, error) {
	resp, err := c.grpc.GetCRL(ctx, &platformv1.GetCRLRequest{IncludeEntries: includeEntries})
	if err != nil {
		return nil, &ErrGetCRLFailed{Cause: err}
	}
	return CRLFromProto(resp.Crl), nil
}

// GetCABundleDomain returns the CA bundle as domain types.
func (c *Client) GetCABundleDomain(ctx context.Context, includeIntermediates bool) (*CABundle, error) {
	resp, err := c.grpc.GetCABundle(ctx, &platformv1.GetCABundleRequest{IncludeIntermediates: includeIntermediates})
	if err != nil {
		return nil, &ErrGetCABundleFailed{Cause: err}
	}
	return CABundleFromProto(resp.Bundle), nil
}

// InstallCACertificatesDomain installs CA certificates and returns domain types.
func (c *Client) InstallCACertificatesDomain(ctx context.Context, includeIntermediates bool) (*InstallResult, error) {
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

// UninstallCACertificatesDomain removes CA certificates and returns domain types.
func (c *Client) UninstallCACertificatesDomain(ctx context.Context, includeIntermediates bool) (*UninstallResult, error) {
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
