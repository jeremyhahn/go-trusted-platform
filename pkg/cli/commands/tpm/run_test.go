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

package tpm

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Mock implementations
// =============================================================================

// mockIDevIDServiceClient implements platformv1.IDevIDServiceClient for testing
type mockIDevIDServiceClient struct {
	platformv1.IDevIDServiceClient

	generateIDevIDFunc           func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error)
	getIDevIDInfoFunc            func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error)
	deleteIDevIDFunc             func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error)
	createIDevIDCSRFunc          func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error)
	installIDevIDCertificateFunc func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error)
	getIDevIDCertificateFunc     func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error)

	generateIAKFunc           func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error)
	getIAKInfoFunc            func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error)
	deleteIAKFunc             func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error)
	createIAKCSRFunc          func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error)
	installIAKCertificateFunc func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error)
	getIAKCertificateFunc     func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error)

	flushTransientContextsFunc func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error)
	getDeviceAttributesFunc    func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error)
}

func (m *mockIDevIDServiceClient) GenerateIDevID(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
	if m.generateIDevIDFunc != nil {
		return m.generateIDevIDFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GenerateIDevID not configured")
}

func (m *mockIDevIDServiceClient) GetIDevIDInfo(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
	if m.getIDevIDInfoFunc != nil {
		return m.getIDevIDInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIDevIDInfo not configured")
}

func (m *mockIDevIDServiceClient) DeleteIDevID(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
	if m.deleteIDevIDFunc != nil {
		return m.deleteIDevIDFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: DeleteIDevID not configured")
}

func (m *mockIDevIDServiceClient) CreateIDevIDCSR(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
	if m.createIDevIDCSRFunc != nil {
		return m.createIDevIDCSRFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: CreateIDevIDCSR not configured")
}

func (m *mockIDevIDServiceClient) InstallIDevIDCertificate(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
	if m.installIDevIDCertificateFunc != nil {
		return m.installIDevIDCertificateFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: InstallIDevIDCertificate not configured")
}

func (m *mockIDevIDServiceClient) GetIDevIDCertificate(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
	if m.getIDevIDCertificateFunc != nil {
		return m.getIDevIDCertificateFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIDevIDCertificate not configured")
}

func (m *mockIDevIDServiceClient) GenerateIAK(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
	if m.generateIAKFunc != nil {
		return m.generateIAKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GenerateIAK not configured")
}

func (m *mockIDevIDServiceClient) GetIAKInfo(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
	if m.getIAKInfoFunc != nil {
		return m.getIAKInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIAKInfo not configured")
}

func (m *mockIDevIDServiceClient) DeleteIAK(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
	if m.deleteIAKFunc != nil {
		return m.deleteIAKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: DeleteIAK not configured")
}

func (m *mockIDevIDServiceClient) CreateIAKCSR(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
	if m.createIAKCSRFunc != nil {
		return m.createIAKCSRFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: CreateIAKCSR not configured")
}

func (m *mockIDevIDServiceClient) InstallIAKCertificate(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
	if m.installIAKCertificateFunc != nil {
		return m.installIAKCertificateFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: InstallIAKCertificate not configured")
}

func (m *mockIDevIDServiceClient) GetIAKCertificate(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
	if m.getIAKCertificateFunc != nil {
		return m.getIAKCertificateFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIAKCertificate not configured")
}

func (m *mockIDevIDServiceClient) FlushTransientContexts(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
	if m.flushTransientContextsFunc != nil {
		return m.flushTransientContextsFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: FlushTransientContexts not configured")
}

func (m *mockIDevIDServiceClient) GetDeviceAttributes(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
	if m.getDeviceAttributesFunc != nil {
		return m.getDeviceAttributesFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetDeviceAttributes not configured")
}

// mockBaseCommand implements BaseCommandInterface for testing
type mockBaseCommand struct {
	flags   *cli.CommonFlags
	client  IDevIDClientProvider
	printer *cli.Printer
	ctx     context.Context
	output  *bytes.Buffer
}

func (m *mockBaseCommand) Client() IDevIDClientProvider {
	return m.client
}

func (m *mockBaseCommand) Printer() *cli.Printer {
	return m.printer
}

func (m *mockBaseCommand) Context() context.Context {
	return m.ctx
}

func (m *mockBaseCommand) Close() error {
	return nil
}

func (m *mockBaseCommand) Flags() *cli.CommonFlags {
	return m.flags
}

// =============================================================================
// Test helpers
// =============================================================================

func createTestKeyInfo() *platformv1.DeviceKeyInfo {
	return &platformv1.DeviceKeyInfo{
		Handle:       0x81010100,
		Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		PublicKeyPem: []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"),
		CreatedAt:    timestamppb.New(time.Date(2025, 1, 7, 12, 0, 0, 0, time.UTC)),
	}
}

func createTestCertificate() *platformv1.DeviceIdentityCertificate {
	return &platformv1.DeviceIdentityCertificate{
		Pem:          []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
		SubjectCn:    "device-001",
		IssuerCn:     "Test CA",
		SerialNumber: "1234567890",
		IssuedAt:     timestamppb.New(time.Date(2025, 1, 6, 12, 0, 0, 0, time.UTC)),
		ExpiresAt:    timestamppb.New(time.Date(2026, 1, 6, 12, 0, 0, 0, time.UTC)),
	}
}

// =============================================================================
// IDevID Tests
// =============================================================================

// =============================================================================
// IAK Tests
// =============================================================================

// =============================================================================
// TPM Device Tests
// =============================================================================

// =============================================================================
// Output Format Tests
// =============================================================================

// =============================================================================
// IAK Additional Tests
// =============================================================================

// =============================================================================
// TPM Device Additional Tests
// =============================================================================
