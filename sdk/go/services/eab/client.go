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

// Package eab provides a client for External Account Binding service operations.
// EAB credentials are used for ACME certificate enrollment with pre-authorized
// account binding.
package eab

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to EAB service operations.
type Client struct {
	grpc platformv1.EABServiceClient
}

// NewClient creates a new EAB service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewEABServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new EAB service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.EABServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// CreateCredential creates a new EAB credential for device enrollment.
// The returned credential includes the HMAC key which is only available at creation time.
func (c *Client) CreateCredential(ctx context.Context, req *platformv1.CreateEABCredentialRequest) (*platformv1.EABCredential, error) {
	resp, err := c.grpc.CreateCredential(ctx, req)
	if err != nil {
		return nil, &ErrCreateCredentialFailed{Cause: err}
	}
	return resp.Credential, nil
}

// GetCredential retrieves an EAB credential by its ID.
// The HMAC key is not included in the response for security.
func (c *Client) GetCredential(ctx context.Context, credentialID uint64) (*platformv1.EABCredential, error) {
	resp, err := c.grpc.GetCredential(ctx, &platformv1.GetEABCredentialRequest{
		CredentialId: credentialID,
	})
	if err != nil {
		return nil, &ErrGetCredentialFailed{ID: credentialID, Cause: err}
	}
	return resp.Credential, nil
}

// GetCredentialByKeyID retrieves an EAB credential by its key ID.
// The HMAC key is not included in the response for security.
func (c *Client) GetCredentialByKeyID(ctx context.Context, keyID string) (*platformv1.EABCredential, error) {
	resp, err := c.grpc.GetCredentialByKeyID(ctx, &platformv1.GetEABCredentialByKeyIDRequest{
		KeyId: keyID,
	})
	if err != nil {
		return nil, &ErrGetCredentialByKeyIDFailed{KeyID: keyID, Cause: err}
	}
	return resp.Credential, nil
}

// ListCredentials returns EAB credentials with optional filtering.
// Credentials are returned without HMAC keys for security.
func (c *Client) ListCredentials(ctx context.Context, req *platformv1.ListEABCredentialsRequest) ([]*platformv1.EABCredential, *common.PageResult, int64, error) {
	resp, err := c.grpc.ListCredentials(ctx, req)
	if err != nil {
		return nil, nil, 0, &ErrListCredentialsFailed{Cause: err}
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
	return resp.Credentials, pageResult, resp.Total, nil
}

// RevokeCredential marks an EAB credential as revoked.
// Revoked credentials cannot be used for enrollment.
func (c *Client) RevokeCredential(ctx context.Context, credentialID, revokerID uint64) (*platformv1.RevokeEABCredentialResponse, error) {
	resp, err := c.grpc.RevokeCredential(ctx, &platformv1.RevokeEABCredentialRequest{
		CredentialId: credentialID,
		RevokerId:    revokerID,
	})
	if err != nil {
		return nil, &ErrRevokeCredentialFailed{ID: credentialID, Cause: err}
	}
	return resp, nil
}

// ValidateCredential checks if an EAB credential is valid for use.
// Returns validation result including whether the credential is valid.
func (c *Client) ValidateCredential(ctx context.Context, keyID, hmacKey string) (*platformv1.ValidateEABCredentialResponse, error) {
	resp, err := c.grpc.ValidateCredential(ctx, &platformv1.ValidateEABCredentialRequest{
		KeyId:   keyID,
		HmacKey: hmacKey,
	})
	if err != nil {
		return nil, &ErrValidateCredentialFailed{KeyID: keyID, Cause: err}
	}
	return resp, nil
}

// DeleteCredential permanently removes an EAB credential.
func (c *Client) DeleteCredential(ctx context.Context, credentialID uint64) (*platformv1.DeleteEABCredentialResponse, error) {
	resp, err := c.grpc.DeleteCredential(ctx, &platformv1.DeleteEABCredentialRequest{
		CredentialId: credentialID,
	})
	if err != nil {
		return nil, &ErrDeleteCredentialFailed{ID: credentialID, Cause: err}
	}
	return resp, nil
}

// GetQRCode generates a QR code image for an EAB credential.
// The QR code can be scanned by devices for enrollment.
func (c *Client) GetQRCode(ctx context.Context, credentialID uint64, size int32) (*platformv1.GetEABCredentialQRCodeResponse, error) {
	resp, err := c.grpc.GetCredentialQRCode(ctx, &platformv1.GetEABCredentialQRCodeRequest{
		CredentialId: credentialID,
		Size:         size,
	})
	if err != nil {
		return nil, &ErrGetQRCodeFailed{ID: credentialID, Cause: err}
	}
	return resp, nil
}

// GetEnrollmentURL generates an enrollment URL with embedded credentials.
// The URL can be used directly for device enrollment.
func (c *Client) GetEnrollmentURL(ctx context.Context, credentialID uint64, path string) (string, error) {
	resp, err := c.grpc.GetEnrollmentURL(ctx, &platformv1.GetEABEnrollmentURLRequest{
		CredentialId: credentialID,
		Path:         path,
	})
	if err != nil {
		return "", &ErrGetEnrollmentURLFailed{ID: credentialID, Cause: err}
	}
	return resp.Url, nil
}

// MarkCredentialUsed marks a credential as used after successful enrollment.
// Used credentials cannot be reused for subsequent enrollments.
func (c *Client) MarkCredentialUsed(ctx context.Context, credentialID uint64) (*platformv1.MarkEABCredentialUsedResponse, error) {
	resp, err := c.grpc.MarkCredentialUsed(ctx, &platformv1.MarkEABCredentialUsedRequest{
		CredentialId: credentialID,
	})
	if err != nil {
		return nil, &ErrMarkCredentialUsedFailed{ID: credentialID, Cause: err}
	}
	return resp, nil
}

// CleanupExpiredCredentials removes all expired credentials.
// If tenantID is empty, cleanup is performed across all tenants.
func (c *Client) CleanupExpiredCredentials(ctx context.Context, tenantID string) (int32, error) {
	resp, err := c.grpc.CleanupExpiredCredentials(ctx, &platformv1.CleanupExpiredEABCredentialsRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return 0, &ErrCleanupExpiredCredentialsFailed{Cause: err}
	}
	return resp.DeletedCount, nil
}
