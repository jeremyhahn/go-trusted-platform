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

// Package idevid provides a client for IDevID service operations.
package idevid

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to IDevID service operations.
type Client struct {
	grpc platformv1.IDevIDServiceClient
}

// NewClient creates a new IDevID service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewIDevIDServiceClient(grpcConn),
	}, nil
}

// IDevID Operations

// GenerateIDevID creates a new IDevID key in the TPM.
func (c *Client) GenerateIDevID(ctx context.Context, config *platformv1.IDevIDConfig) error {
	_, err := c.grpc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{Config: config})
	if err != nil {
		return &ErrGenerateIDevIDFailed{Cause: err}
	}
	return nil
}

// GetIDevIDInfo retrieves information about the IDevID key.
func (c *Client) GetIDevIDInfo(ctx context.Context) (*platformv1.DeviceKeyInfo, error) {
	resp, err := c.grpc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
	if err != nil {
		return nil, &ErrGetIDevIDInfoFailed{Cause: err}
	}
	return resp.KeyInfo, nil
}

// HasIDevID checks if an IDevID key exists in the TPM.
func (c *Client) HasIDevID(ctx context.Context) (bool, error) {
	resp, err := c.grpc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})
	if err != nil {
		return false, &ErrHasIDevIDFailed{Cause: err}
	}
	return resp.Exists, nil
}

// DeleteIDevID removes the IDevID key from the TPM.
func (c *Client) DeleteIDevID(ctx context.Context) error {
	_, err := c.grpc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
	if err != nil {
		return &ErrDeleteIDevIDFailed{Cause: err}
	}
	return nil
}

// IAK Operations

// GenerateIAK creates a new IAK (Initial Attestation Key) in the TPM.
func (c *Client) GenerateIAK(ctx context.Context, config *platformv1.IAKConfig) error {
	_, err := c.grpc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{Config: config})
	if err != nil {
		return &ErrGenerateIAKFailed{Cause: err}
	}
	return nil
}

// GetIAKInfo retrieves information about the IAK key.
func (c *Client) GetIAKInfo(ctx context.Context) (*platformv1.DeviceKeyInfo, error) {
	resp, err := c.grpc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
	if err != nil {
		return nil, &ErrGetIAKInfoFailed{Cause: err}
	}
	return resp.KeyInfo, nil
}

// HasIAK checks if an IAK key exists in the TPM.
func (c *Client) HasIAK(ctx context.Context) (bool, error) {
	resp, err := c.grpc.HasIAK(ctx, &platformv1.HasIAKRequest{})
	if err != nil {
		return false, &ErrHasIAKFailed{Cause: err}
	}
	return resp.Exists, nil
}

// DeleteIAK removes the IAK key from the TPM.
func (c *Client) DeleteIAK(ctx context.Context) error {
	_, err := c.grpc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
	if err != nil {
		return &ErrDeleteIAKFailed{Cause: err}
	}
	return nil
}

// CSR Operations

// CreateIDevIDCSR creates a certificate signing request for the IDevID key.
func (c *Client) CreateIDevIDCSR(ctx context.Context, template *platformv1.CSRTemplate) ([]byte, error) {
	resp, err := c.grpc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{Template: template})
	if err != nil {
		return nil, &ErrCreateIDevIDCSRFailed{Cause: err}
	}
	return resp.CsrPem, nil
}

// CreateIAKCSR creates a certificate signing request for the IAK key.
func (c *Client) CreateIAKCSR(ctx context.Context, template *platformv1.CSRTemplate) ([]byte, error) {
	resp, err := c.grpc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{Template: template})
	if err != nil {
		return nil, &ErrCreateIAKCSRFailed{Cause: err}
	}
	return resp.CsrPem, nil
}

// CreateLDevID provisions a Local Device Identifier (IEEE 802.1AR). It creates
// a TPM-resident LDevID key distinct from the IDevID/IAK birth keys, builds a
// PKCS#10 CSR signed by that key, and has the platform CA issue the
// certificate. Issuance requires a proven IDevID.
func (c *Client) CreateLDevID(ctx context.Context, req *platformv1.CreateLDevIDRequest) (*platformv1.CreateLDevIDResponse, error) {
	resp, err := c.grpc.CreateLDevID(ctx, req)
	if err != nil {
		return nil, &ErrCreateLDevIDFailed{Cause: err}
	}
	return resp, nil
}

// Certificate Operations

// InstallIDevIDCertificate installs an IDevID certificate.
func (c *Client) InstallIDevIDCertificate(ctx context.Context, certificatePEM []byte) error {
	_, err := c.grpc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{
		CertificatePem: certificatePEM,
	})
	if err != nil {
		return &ErrInstallIDevIDCertFailed{Cause: err}
	}
	return nil
}

// InstallIAKCertificate installs an IAK certificate.
func (c *Client) InstallIAKCertificate(ctx context.Context, certificatePEM []byte) error {
	_, err := c.grpc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{
		CertificatePem: certificatePEM,
	})
	if err != nil {
		return &ErrInstallIAKCertFailed{Cause: err}
	}
	return nil
}

// GetIDevIDCertificate retrieves the installed IDevID certificate.
func (c *Client) GetIDevIDCertificate(ctx context.Context) (*platformv1.DeviceIdentityCertificate, error) {
	resp, err := c.grpc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	if err != nil {
		return nil, &ErrGetIDevIDCertFailed{Cause: err}
	}
	return resp.Certificate, nil
}

// GetIAKCertificate retrieves the installed IAK certificate.
func (c *Client) GetIAKCertificate(ctx context.Context) (*platformv1.DeviceIdentityCertificate, error) {
	resp, err := c.grpc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	if err != nil {
		return nil, &ErrGetIAKCertFailed{Cause: err}
	}
	return resp.Certificate, nil
}

// DeleteIDevIDCertificate removes the installed IDevID certificate.
func (c *Client) DeleteIDevIDCertificate(ctx context.Context) error {
	_, err := c.grpc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
	if err != nil {
		return &ErrDeleteIDevIDCertFailed{Cause: err}
	}
	return nil
}

// DeleteIAKCertificate removes the installed IAK certificate.
func (c *Client) DeleteIAKCertificate(ctx context.Context) error {
	_, err := c.grpc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
	if err != nil {
		return &ErrDeleteIAKCertFailed{Cause: err}
	}
	return nil
}

// Device Attributes

// GetDeviceAttributes retrieves TCG device attributes from TPM and platform.
func (c *Client) GetDeviceAttributes(ctx context.Context) (*platformv1.TCGDeviceAttributes, error) {
	resp, err := c.grpc.GetDeviceAttributes(ctx, &platformv1.GetDeviceAttributesRequest{})
	if err != nil {
		return nil, &ErrGetDeviceAttributesFailed{Cause: err}
	}
	return resp.Attributes, nil
}

// TPM Binding Verification

// ActivateCredential decrypts a credential blob using the EK and AK.
func (c *Client) ActivateCredential(ctx context.Context, credentialBlob, secret []byte) ([]byte, error) {
	resp, err := c.grpc.ActivateCredential(ctx, &platformv1.ActivateCredentialRequest{
		CredentialBlob: credentialBlob,
		Secret:         secret,
	})
	if err != nil {
		return nil, &ErrActivateCredentialFailed{Cause: err}
	}
	return resp.DecryptedSecret, nil
}

// TPM Context Management

// FlushTransientContexts flushes all transient TPM contexts.
func (c *Client) FlushTransientContexts(ctx context.Context) (uint32, error) {
	resp, err := c.grpc.FlushTransientContexts(ctx, &platformv1.FlushTransientContextsRequest{})
	if err != nil {
		return 0, &ErrFlushTransientContextsFailed{Cause: err}
	}
	return resp.FlushedCount, nil
}
