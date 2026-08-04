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

package idevid

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Domain-typed convenience methods
//
// These methods return domain types instead of proto types, enabling callers
// to avoid importing platformv1 directly.

// NewClientFromGRPC creates a new IDevID service client from a gRPC client.
func NewClientFromGRPC(grpcClient platformv1.IDevIDServiceClient) *Client {
	return &Client{grpc: grpcClient}
}

// GenerateIDevIDDomain generates a new IDevID key using domain parameters.
// Returns the generated key info on success.
func (c *Client) GenerateIDevIDDomain(ctx context.Context, algorithm DeviceKeyAlgorithm, overwrite bool) (*DeviceKeyInfo, error) {
	alg, ok := AlgorithmToProto(string(algorithm))
	if !ok {
		return nil, &ErrInvalidAlgorithm{Algorithm: string(algorithm)}
	}
	resp, err := c.grpc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{
		Config: &platformv1.IDevIDConfig{
			Algorithm: alg,
			Overwrite: overwrite,
		},
	})
	if err != nil {
		return nil, &ErrGenerateIDevIDFailed{Cause: err}
	}
	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return nil, &ErrGenerateIDevIDFailed{Cause: &ErrStatusMessage{Message: msg}}
	}
	// Fetch key info after generation
	return c.GetIDevIDInfoDomain(ctx)
}

// GetIDevIDInfoDomain retrieves IDevID key info as domain type.
func (c *Client) GetIDevIDInfoDomain(ctx context.Context) (*DeviceKeyInfo, error) {
	resp, err := c.grpc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		return nil, &ErrGetIDevIDInfoFailed{Cause: err}
	}
	if resp.KeyInfo == nil {
		return nil, &ErrIDevIDNotFound{}
	}
	return DeviceKeyInfoFromProto(resp.KeyInfo), nil
}

// DeleteIDevIDDomain deletes the IDevID key.
// Returns true if deleted, false otherwise, with an optional message.
func (c *Client) DeleteIDevIDDomain(ctx context.Context) (bool, string, error) {
	resp, err := c.grpc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
	if err != nil {
		return false, "", &ErrDeleteIDevIDFailed{Cause: err}
	}
	deleted := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
	return deleted, message, nil
}

// CreateIDevIDCSRDomain creates a CSR for the IDevID key using domain types.
func (c *Client) CreateIDevIDCSRDomain(ctx context.Context, template *CSRTemplate) ([]byte, error) {
	resp, err := c.grpc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{
		Template: CSRTemplateToProto(template),
	})
	if err != nil {
		return nil, &ErrCreateIDevIDCSRFailed{Cause: err}
	}
	return resp.CsrPem, nil
}

// InstallIDevIDCertificateDomain installs an IDevID certificate.
// Returns true if installed, false otherwise, with an optional message.
func (c *Client) InstallIDevIDCertificateDomain(ctx context.Context, certPEM []byte) (bool, string, error) {
	resp, err := c.grpc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: certPEM,
	})
	if err != nil {
		return false, "", &ErrInstallIDevIDCertFailed{Cause: err}
	}
	installed := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
	return installed, message, nil
}

// GetIDevIDCertificateDomain retrieves the IDevID certificate as domain type.
func (c *Client) GetIDevIDCertificateDomain(ctx context.Context) (*DeviceIdentityCertificate, error) {
	resp, err := c.grpc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		return nil, &ErrGetIDevIDCertFailed{Cause: err}
	}
	if resp.Certificate == nil {
		return nil, &ErrIDevIDCertificateNotFound{}
	}
	return DeviceIdentityCertificateFromProto(resp.Certificate), nil
}

// GenerateIAKDomain generates a new IAK key using domain parameters.
func (c *Client) GenerateIAKDomain(ctx context.Context, algorithm DeviceKeyAlgorithm, overwrite bool) (*DeviceKeyInfo, error) {
	alg, ok := AlgorithmToProto(string(algorithm))
	if !ok {
		return nil, &ErrInvalidAlgorithm{Algorithm: string(algorithm)}
	}
	resp, err := c.grpc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{
		Config: &platformv1.IAKConfig{
			Algorithm: alg,
			Overwrite: overwrite,
		},
	})
	if err != nil {
		return nil, &ErrGenerateIAKFailed{Cause: err}
	}
	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return nil, &ErrGenerateIAKFailed{Cause: &ErrStatusMessage{Message: msg}}
	}
	return c.GetIAKInfoDomain(ctx)
}

// GetIAKInfoDomain retrieves IAK key info as domain type.
func (c *Client) GetIAKInfoDomain(ctx context.Context) (*DeviceKeyInfo, error) {
	resp, err := c.grpc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
	if err != nil {
		return nil, &ErrGetIAKInfoFailed{Cause: err}
	}
	if resp.KeyInfo == nil {
		return nil, &ErrIAKNotFound{}
	}
	return DeviceKeyInfoFromProto(resp.KeyInfo), nil
}

// DeleteIAKDomain deletes the IAK key.
func (c *Client) DeleteIAKDomain(ctx context.Context) (bool, string, error) {
	resp, err := c.grpc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
	if err != nil {
		return false, "", &ErrDeleteIAKFailed{Cause: err}
	}
	deleted := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
	return deleted, message, nil
}

// CreateIAKCSRDomain creates a CSR for the IAK key using domain types.
func (c *Client) CreateIAKCSRDomain(ctx context.Context, template *CSRTemplate) ([]byte, error) {
	resp, err := c.grpc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{
		Template: CSRTemplateToProto(template),
	})
	if err != nil {
		return nil, &ErrCreateIAKCSRFailed{Cause: err}
	}
	return resp.CsrPem, nil
}

// InstallIAKCertificateDomain installs an IAK certificate.
func (c *Client) InstallIAKCertificateDomain(ctx context.Context, certPEM []byte) (bool, string, error) {
	resp, err := c.grpc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
		CertificatePem: certPEM,
	})
	if err != nil {
		return false, "", &ErrInstallIAKCertFailed{Cause: err}
	}
	installed := resp.Status != nil && resp.Status.Success
	message := ""
	if resp.Status != nil {
		message = resp.Status.Message
	}
	return installed, message, nil
}

// GetIAKCertificateDomain retrieves the IAK certificate as domain type.
func (c *Client) GetIAKCertificateDomain(ctx context.Context) (*DeviceIdentityCertificate, error) {
	resp, err := c.grpc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	if err != nil {
		return nil, &ErrGetIAKCertFailed{Cause: err}
	}
	if resp.Certificate == nil {
		return nil, &ErrIAKCertificateNotFound{}
	}
	return DeviceIdentityCertificateFromProto(resp.Certificate), nil
}

// FlushTransientContextsDomain flushes transient TPM contexts.
func (c *Client) FlushTransientContextsDomain(ctx context.Context) (uint32, string, error) {
	resp, err := c.grpc.FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})
	if err != nil {
		return 0, "", &ErrFlushTransientContextsFailed{Cause: err}
	}
	message := ""
	if resp.Status != nil {
		message = resp.Status.GetMessage()
	}
	return resp.FlushedCount, message, nil
}

// GetDeviceAttributesDomain retrieves device attributes as domain type.
func (c *Client) GetDeviceAttributesDomain(ctx context.Context) (*DeviceAttributes, error) {
	resp, err := c.grpc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})
	if err != nil {
		return nil, &ErrGetDeviceAttributesFailed{Cause: err}
	}
	attrs := resp.GetAttributes()
	if attrs == nil {
		return nil, &ErrGetDeviceAttributesFailed{Cause: &ErrStatusMessage{Message: "no attributes returned"}}
	}
	return DeviceAttributesFromProto(attrs), nil
}
