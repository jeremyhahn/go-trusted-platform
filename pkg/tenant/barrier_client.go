// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package tenant

import (
	"context"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// sdkTenantBarrierClient adapts the quicbaas SDK's QRDB tenant client to
// the manager's TenantBarrierClient boundary. The SDK's TenantBarrierInit
// also returns an init response (Shamir shares for that strategy); the
// manager's boundary carries only the error, so the response is dropped.
type sdkTenantBarrierClient struct {
	c quicbaassdk.QRDBTenantClient
}

var _ TenantBarrierClient = (*sdkTenantBarrierClient)(nil)

// NewTenantBarrierClient wraps a QRDB tenant client as the manager's
// per-tenant barrier backend. A nil client returns a nil interface, so
// ManagerConfig.TenantBarrierClient stays nil and BarrierConfigured
// reports false.
func NewTenantBarrierClient(c quicbaassdk.QRDBTenantClient) TenantBarrierClient {
	if c == nil {
		return nil
	}
	return &sdkTenantBarrierClient{c: c}
}

// TenantBarrierInit initializes the tenant's barrier through the SDK.
func (s *sdkTenantBarrierClient) TenantBarrierInit(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierInitRequest) error {
	_, err := s.c.TenantBarrierInit(ctx, req)
	return err
}

// TenantBarrierUnseal unseals the tenant's barrier through the SDK.
func (s *sdkTenantBarrierClient) TenantBarrierUnseal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierUnsealRequest) error {
	return s.c.TenantBarrierUnseal(ctx, req)
}

// TenantBarrierSeal seals the tenant's barrier through the SDK.
func (s *sdkTenantBarrierClient) TenantBarrierSeal(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierSealRequest) error {
	return s.c.TenantBarrierSeal(ctx, req)
}

// TenantBarrierStatus reports the tenant's barrier state through the SDK.
func (s *sdkTenantBarrierClient) TenantBarrierStatus(ctx context.Context, req *quicbaassdk.QRDBTenantBarrierStatusRequest) (*quicbaassdk.QRDBTenantBarrierStatusResponse, error) {
	return s.c.TenantBarrierStatus(ctx, req)
}
