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

package tenant

import (
	"context"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// TenantDEKClient is the platform-side boundary to the quicbaas SDK Data
// Encryption Key surface used for per-tenant DEK isolation. The platform
// tenant manager owns the tenant -> DEK lifecycle policy (when to create,
// rotate, delete a tenant's key) but the cryptographic semantics of the DEK
// itself are owned by the quicbaas server / qrdb barrier. This interface is
// deliberately small and tenant-centric; it mirrors the TenantBarrierClient
// boundary so the manager depends only on the verbs it actually consumes and
// can be unit-tested with a mock that performs no real cryptography.
//
// It is satisfied by NewTenantDEKClient, which adapts the verbs onto the
// quicbaas path-based DEK SDK (quicbaas.DEKClient). Each tenant maps to the
// DEK path "tenant/<tenantID>".
type TenantDEKClient interface {
	// EnsureTenantDEK creates the tenant's DEK if it does not already exist
	// and returns its identifier (the DEK path). It is idempotent.
	EnsureTenantDEK(ctx context.Context, req *EnsureTenantDEKRequest) (*EnsureTenantDEKResponse, error)

	// DeleteTenantDEK removes the tenant's DEK.
	DeleteTenantDEK(ctx context.Context, req *DeleteTenantDEKRequest) (*DeleteTenantDEKResponse, error)

	// RotateTenantDEK creates a new version of the tenant's DEK, optionally
	// kicking off background re-encryption of data sealed under the prior
	// version.
	RotateTenantDEK(ctx context.Context, req *RotateTenantDEKRequest) (*RotateTenantDEKResponse, error)

	// TenantDEKStatus reports the current version and re-encryption state of
	// the tenant's DEK.
	TenantDEKStatus(ctx context.Context, req *TenantDEKStatusRequest) (*TenantDEKStatusResponse, error)
}

// EnsureTenantDEKRequest asks the backend to create-if-absent the DEK for a
// tenant.
type EnsureTenantDEKRequest struct {
	// TenantID identifies the tenant whose DEK is being ensured.
	TenantID string

	// Algorithm is the requested encryption algorithm (e.g. "AES-256-GCM").
	// When empty the backend default is used.
	Algorithm string
}

// EnsureTenantDEKResponse carries the resolved DEK identifier.
type EnsureTenantDEKResponse struct {
	// DEKID is the stable identifier of the tenant DEK (its path).
	DEKID string

	// Created is true when a new DEK was provisioned by this call (false on
	// the idempotent no-op path).
	Created bool

	// Algorithm is the algorithm the DEK was created with.
	Algorithm string

	// CreatedAt is the creation timestamp of the DEK.
	CreatedAt time.Time
}

// DeleteTenantDEKRequest asks the backend to remove a tenant's DEK.
type DeleteTenantDEKRequest struct {
	// TenantID identifies the tenant whose DEK is being deleted.
	TenantID string
}

// DeleteTenantDEKResponse carries the deletion result.
type DeleteTenantDEKResponse struct {
	// DEKID is the identifier of the deleted DEK.
	DEKID string

	// DeletedAt is when the deletion completed.
	DeletedAt time.Time
}

// RotateTenantDEKRequest asks the backend to roll a tenant's DEK forward a
// version.
type RotateTenantDEKRequest struct {
	// TenantID identifies the tenant whose DEK is being rotated.
	TenantID string

	// Reason is an audit annotation describing why the rotation occurred.
	Reason string

	// AutoStartReencryption requests background re-encryption of data sealed
	// under the prior DEK version.
	AutoStartReencryption bool
}

// RotateTenantDEKResponse carries the rotation result.
type RotateTenantDEKResponse struct {
	// OldVersion is the DEK version prior to rotation.
	OldVersion uint64

	// NewVersion is the DEK version after rotation.
	NewVersion uint64

	// RotatedAt is when the rotation completed.
	RotatedAt time.Time
}

// TenantDEKStatusRequest asks for a tenant DEK's current status.
type TenantDEKStatusRequest struct {
	// TenantID identifies the tenant whose DEK status is requested.
	TenantID string
}

// TenantDEKStatusResponse carries the tenant DEK status.
type TenantDEKStatusResponse struct {
	// Algorithm is the DEK's encryption algorithm.
	Algorithm string

	// CurrentVersion is the active DEK version.
	CurrentVersion uint64

	// CreatedAt is the DEK creation timestamp.
	CreatedAt time.Time

	// RotatedAt is the most recent rotation timestamp, nil if never rotated.
	RotatedAt *time.Time

	// ReencryptionInProgress is true when a background re-encryption is
	// running for this DEK.
	ReencryptionInProgress bool
}

// dekPathForTenant returns the canonical DEK path for a tenant. Per-tenant
// DEK isolation is expressed in the quicbaas path-based DEK surface as a
// dedicated path per tenant.
func dekPathForTenant(tenantID string) string {
	return "tenant/" + tenantID
}

// sdkTenantDEKClient adapts the quicbaas path-based DEK SDK onto the
// tenant-centric TenantDEKClient boundary. The cryptographic operations are
// performed entirely by the quicbaas server; this type only translates the
// tenant identifier into a DEK path and maps the request/response shapes.
type sdkTenantDEKClient struct {
	dek quicbaas.DEKClient
}

// NewTenantDEKClient wraps a quicbaas SDK DEK client as a platform
// TenantDEKClient. The supplied client is typically obtained from
// SDK.Security().DEK() (or the equivalent Client.DEK() accessor). Returns nil
// when no underlying client is available so callers can fail closed.
func NewTenantDEKClient(dek quicbaas.DEKClient) TenantDEKClient {
	if dek == nil {
		return nil
	}
	return &sdkTenantDEKClient{dek: dek}
}

func (c *sdkTenantDEKClient) EnsureTenantDEK(ctx context.Context, req *EnsureTenantDEKRequest) (*EnsureTenantDEKResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	path := dekPathForTenant(req.TenantID)

	// Idempotent create: if the DEK already exists, return it unchanged.
	if existing, err := c.dek.GetDEK(ctx, path); err == nil && existing != nil {
		return &EnsureTenantDEKResponse{
			DEKID:     existing.Path,
			Created:   false,
			Algorithm: existing.Algorithm,
			CreatedAt: existing.CreatedAt,
		}, nil
	}

	created, err := c.dek.CreateDEK(ctx, &quicbaas.CreateDEKSDKRequest{
		Path:        path,
		Algorithm:   req.Algorithm,
		Description: "per-tenant DEK for " + req.TenantID,
	})
	if err != nil {
		return nil, err
	}
	if created == nil || created.DEK == nil {
		return nil, ErrDEKOperationFailed{TenantID: req.TenantID, Operation: "ensure"}
	}

	return &EnsureTenantDEKResponse{
		DEKID:     created.DEK.Path,
		Created:   true,
		Algorithm: created.DEK.Algorithm,
		CreatedAt: created.DEK.CreatedAt,
	}, nil
}

func (c *sdkTenantDEKClient) DeleteTenantDEK(ctx context.Context, req *DeleteTenantDEKRequest) (*DeleteTenantDEKResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	path := dekPathForTenant(req.TenantID)

	resp, err := c.dek.DeleteDEK(ctx, &quicbaas.DeleteDEKSDKRequest{
		Path:  path,
		Force: true,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.Deleted {
		return nil, ErrDEKOperationFailed{TenantID: req.TenantID, Operation: "delete"}
	}

	return &DeleteTenantDEKResponse{
		DEKID:     resp.Path,
		DeletedAt: time.Now().UTC(),
	}, nil
}

func (c *sdkTenantDEKClient) RotateTenantDEK(ctx context.Context, req *RotateTenantDEKRequest) (*RotateTenantDEKResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	path := dekPathForTenant(req.TenantID)

	resp, err := c.dek.RotateDEK(ctx, &quicbaas.RotateDEKSDKRequest{
		Path:       path,
		Background: req.AutoStartReencryption,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, ErrDEKOperationFailed{TenantID: req.TenantID, Operation: "rotate"}
	}

	return &RotateTenantDEKResponse{
		OldVersion: uint64(resp.OldVersion),
		NewVersion: uint64(resp.NewVersion),
		RotatedAt:  time.Now().UTC(),
	}, nil
}

func (c *sdkTenantDEKClient) TenantDEKStatus(ctx context.Context, req *TenantDEKStatusRequest) (*TenantDEKStatusResponse, error) {
	if req == nil || req.TenantID == "" {
		return nil, ErrInvalidRequest{Reason: "tenant ID is required"}
	}

	path := dekPathForTenant(req.TenantID)

	status, err := c.dek.GetDEKStatus(ctx, path)
	if err != nil {
		return nil, err
	}
	if status == nil || status.DEK == nil {
		return nil, ErrDEKOperationFailed{TenantID: req.TenantID, Operation: "status"}
	}

	out := &TenantDEKStatusResponse{
		Algorithm:      status.DEK.Algorithm,
		CurrentVersion: uint64(status.DEK.Version),
		CreatedAt:      status.DEK.CreatedAt,
	}
	if !status.DEK.RotatedAt.IsZero() {
		rotated := status.DEK.RotatedAt
		out.RotatedAt = &rotated
	}
	if status.ReencryptionProgress != nil {
		out.ReencryptionInProgress = status.ReencryptionProgress.InProgress
	}
	return out, nil
}
