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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

// mockIDevIDClientProvider implements IDevIDClientProvider for testing
type mockIDevIDClientProvider struct {
	idevidClient platformv1.IDevIDServiceClient
}

func (m *mockIDevIDClientProvider) IDevID() platformv1.IDevIDServiceClient {
	return m.idevidClient
}

// mockBaseCommand implements BaseCommandInterface for testing
type mockBaseCommand struct {
	flags   *cli.CommonFlags
	client  IDevIDClientProvider
	printer *cli.Printer
	ctx     context.Context
	output  *bytes.Buffer
}

func newMockBaseCommand(flags *cli.CommonFlags, idevidClient platformv1.IDevIDServiceClient) *mockBaseCommand {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, output)

	return &mockBaseCommand{
		flags:   flags,
		client:  &mockIDevIDClientProvider{idevidClient: idevidClient},
		printer: printer,
		ctx:     context.Background(),
		output:  output,
	}
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

func TestRunIDevIDGenerateWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "ECDSA-P256")
}

func TestRunIDevIDGenerateWithClient_InvalidAlgorithm(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{}
	base := newMockBaseCommand(flags, mockClient)

	err := runIDevIDGenerateWithClient(base, "INVALID-ALG", false)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidAlgorithm{}, err)
}

func TestRunIDevIDGenerateWithClient_GenerateError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return nil, errors.New("TPM not available")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGenerateIDevIDFailed{}, err)
}

func TestRunIDevIDInfoWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81010100")
}

func TestRunIDevIDInfoWithClient_NotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrIDevIDNotFound{}, err)
}

func TestRunIDevIDDeleteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIDevIDFunc: func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
			return &platformv1.DeleteIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunIDevIDDeleteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIDevIDFunc: func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
			return nil, errors.New("key not found")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDDeleteWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrDeleteIDevIDFailed{}, err)
}

func TestRunIDevIDCSRWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIDevIDCSRFunc: func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
			assert.Equal(t, "device.example.com", req.Template.CommonName)
			assert.Equal(t, "Example Corp", req.Template.Organization)
			return &platformv1.CreateIDevIDCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCSRWithClient(base, "device.example.com", "Example Corp", "US", "CA", "SF", "Engineering")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "csr_pem")
}

func TestRunIDevIDCSRWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIDevIDCSRFunc: func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
			return nil, errors.New("signing failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.Error(t, err)
	assert.IsType(t, ErrCreateIDevIDCSRFailed{}, err)
}

func TestRunIDevIDInstallWithClient_Success(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
			return &platformv1.InstallIDevIDCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIDevIDInstallWithClient(base, tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunIDevIDInstallWithClient_FileNotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{}
	base := newMockBaseCommand(flags, mockClient)

	err := runIDevIDInstallWithClient(base, "/nonexistent/path.pem")
	require.Error(t, err)
	assert.IsType(t, ErrInstallIDevIDCertificateFailed{}, err)
}

func TestRunIDevIDCertWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
			return &platformv1.GetIDevIDCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCertWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "device-001")
}

func TestRunIDevIDCertWithClient_NotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
			return &platformv1.GetIDevIDCertificateResponse{
				Certificate: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrIDevIDCertificateNotFound{}, err)
}

// =============================================================================
// IAK Tests
// =============================================================================

func TestRunIAKGenerateWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return &platformv1.GenerateIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "ECDSA-P256")
}

func TestRunIAKGenerateWithClient_InvalidAlgorithm(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{}
	base := newMockBaseCommand(flags, mockClient)

	err := runIAKGenerateWithClient(base, "INVALID-ALG", false)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidAlgorithm{}, err)
}

func TestRunIAKInfoWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKInfoWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81010100")
}

func TestRunIAKInfoWithClient_NotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrIAKNotFound{}, err)
}

func TestRunIAKDeleteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return &platformv1.DeleteIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunIAKCSRWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIAKCSRFunc: func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
			return &platformv1.CreateIAKCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "csr_pem")
}

func TestRunIAKInstallWithClient_Success(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIAKCertificateFunc: func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
			return &platformv1.InstallIAKCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIAKInstallWithClient(base, tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunIAKCertWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKCertificateFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return &platformv1.GetIAKCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCertWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "device-001")
}

func TestRunIAKCertWithClient_NotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKCertificateFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return &platformv1.GetIAKCertificateResponse{
				Certificate: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrIAKCertificateNotFound{}, err)
}

// =============================================================================
// TPM Device Tests
// =============================================================================

func TestRunFlushWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		flushTransientContextsFunc: func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
			return &platformv1.FlushTransientContextsResponse{
				FlushedCount: 5,
				Status:       &platformv1.Status{Success: true, Message: "Flushed 5 contexts"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runFlushWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "5")
}

func TestRunFlushWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		flushTransientContextsFunc: func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
			return nil, errors.New("TPM busy")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runFlushWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrFlushFailed{}, err)
}

func TestRunDeviceAttributesWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{
				Attributes: &platformv1.TCGDeviceAttributes{
					TpmManufacturer: "Test TPM",
					TpmModel:        "Model X",
					TpmVersion:      "2.0",
				},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runDeviceAttributesWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Test TPM")
}

func TestRunDeviceAttributesWithClient_NoAttributes(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{
				Attributes: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runDeviceAttributesWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetDeviceAttributesFailed{}, err)
}

// =============================================================================
// Output Format Tests
// =============================================================================

func TestRunIDevIDInfoWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.NoError(t, err)
	// Table format output is written to the buffer
	assert.NotEmpty(t, base.output.String())
}

func TestRunIDevIDInfoWithClient_YAMLFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatYAML,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.NoError(t, err)
	// YAML format should contain the handle
	assert.Contains(t, base.output.String(), "0x81010100")
}

func TestRunIDevIDInfoWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIDevIDInfoWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetIDevIDInfoFailed{}, err)
}

func TestRunIDevIDGenerateWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "IDevID key generated")
}

func TestRunIDevIDGenerateWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: nil,
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGenerateIDevIDFailed{}, err)
}

func TestRunIDevIDGenerateWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: &platformv1.Status{Success: false, Message: "Key already exists"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGenerateIDevIDFailed{}, err)
	assert.Contains(t, err.Error(), "Key already exists")
}

func TestRunIDevIDGenerateWithClient_InfoError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return nil, errors.New("failed to get info")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGetIDevIDInfoFailed{}, err)
}

func TestRunIDevIDGenerateWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIDevIDFunc: func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
			return &platformv1.GenerateIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
			return &platformv1.GetIDevIDInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIDevIDDeleteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIDevIDFunc: func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
			return &platformv1.DeleteIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "deleted successfully")
}

func TestRunIDevIDDeleteWithClient_TableFormatFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIDevIDFunc: func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
			return &platformv1.DeleteIDevIDResponse{
				Status: &platformv1.Status{Success: false, Message: "Key not found"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Failed to delete IDevID")
}

func TestRunIDevIDDeleteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIDevIDFunc: func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
			return &platformv1.DeleteIDevIDResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDDeleteWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIDevIDCSRWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIDevIDCSRFunc: func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
			return &platformv1.CreateIDevIDCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "CSR created successfully")
}

func TestRunIDevIDCSRWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIDevIDCSRFunc: func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
			return &platformv1.CreateIDevIDCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIDevIDInstallWithClient_TableFormat(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
			return &platformv1.InstallIDevIDCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIDevIDInstallWithClient(base, tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "installed successfully")
}

func TestRunIDevIDInstallWithClient_TableFormatFailed(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
			return &platformv1.InstallIDevIDCertificateResponse{
				Status: &platformv1.Status{Success: false, Message: "Invalid certificate"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIDevIDInstallWithClient(base, tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Failed to install")
}

func TestRunIDevIDInstallWithClient_Error(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
			return nil, errors.New("NV write failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIDevIDInstallWithClient(base, tmpFile.Name())
	require.Error(t, err)
	assert.IsType(t, ErrInstallIDevIDCertificateFailed{}, err)
}

func TestRunIDevIDInstallWithClient_InvalidFormat(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
			return &platformv1.InstallIDevIDCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIDevIDInstallWithClient(base, tmpFile.Name())
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIDevIDCertWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
			return &platformv1.GetIDevIDCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCertWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "device-001")
}

func TestRunIDevIDCertWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
			return nil, errors.New("NV read failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetIDevIDCertificateFailed{}, err)
}

func TestRunIDevIDCertWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIDevIDCertificateFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
			return &platformv1.GetIDevIDCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIDevIDCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// IAK Additional Tests
// =============================================================================

func TestRunIAKGenerateWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return &platformv1.GenerateIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "IAK key generated")
}

func TestRunIAKGenerateWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return nil, errors.New("TPM busy")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGenerateIAKFailed{}, err)
}

func TestRunIAKGenerateWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return &platformv1.GenerateIAKResponse{Status: nil}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGenerateIAKFailed{}, err)
}

func TestRunIAKGenerateWithClient_InfoError(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return &platformv1.GenerateIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return nil, errors.New("failed to get info")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, ErrGetIAKInfoFailed{}, err)
}

func TestRunIAKGenerateWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		generateIAKFunc: func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
			return &platformv1.GenerateIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key generated"},
			}, nil
		},
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKGenerateWithClient(base, "ECDSA-P256", false)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIAKInfoWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKInfoWithClient(base)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunIAKInfoWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetIAKInfoFailed{}, err)
}

func TestRunIAKInfoWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
			return &platformv1.GetIAKInfoResponse{
				KeyInfo: createTestKeyInfo(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIAKDeleteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return &platformv1.DeleteIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "deleted successfully")
}

func TestRunIAKDeleteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return nil, errors.New("permission denied")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKDeleteWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrDeleteIAKFailed{}, err)
}

func TestRunIAKDeleteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return &platformv1.DeleteIAKResponse{
				Status: &platformv1.Status{Success: true, Message: "Key deleted"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKDeleteWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIAKCSRWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIAKCSRFunc: func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
			return &platformv1.CreateIAKCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "CSR created successfully")
}

func TestRunIAKCSRWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIAKCSRFunc: func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
			return nil, errors.New("signing failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.Error(t, err)
	assert.IsType(t, ErrCreateIAKCSRFailed{}, err)
}

func TestRunIAKCSRWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		createIAKCSRFunc: func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
			return &platformv1.CreateIAKCSRResponse{
				CsrPem: []byte("-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----"),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCSRWithClient(base, "device.example.com", "", "", "", "", "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIAKInstallWithClient_TableFormat(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIAKCertificateFunc: func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
			return &platformv1.InstallIAKCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIAKInstallWithClient(base, tmpFile.Name())
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "installed successfully")
}

func TestRunIAKInstallWithClient_Error(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIAKCertificateFunc: func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
			return nil, errors.New("NV write failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIAKInstallWithClient(base, tmpFile.Name())
	require.Error(t, err)
	assert.IsType(t, ErrInstallIAKCertificateFailed{}, err)
}

func TestRunIAKInstallWithClient_FileNotFound(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{}
	base := newMockBaseCommand(flags, mockClient)

	err := runIAKInstallWithClient(base, "/nonexistent/path.pem")
	require.Error(t, err)
	assert.IsType(t, ErrInstallIAKCertificateFailed{}, err)
}

func TestRunIAKInstallWithClient_InvalidFormat(t *testing.T) {
	// Create temp cert file
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
	require.NoError(t, err)
	tmpFile.Close()

	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		installIAKCertificateFunc: func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
			return &platformv1.InstallIAKCertificateResponse{
				Status: &platformv1.Status{Success: true, Message: "Certificate installed"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err = runIAKInstallWithClient(base, tmpFile.Name())
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunIAKCertWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKCertificateFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return &platformv1.GetIAKCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCertWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "device-001")
}

func TestRunIAKCertWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKCertificateFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return nil, errors.New("NV read failed")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetIAKCertificateFailed{}, err)
}

func TestRunIAKCertWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getIAKCertificateFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return &platformv1.GetIAKCertificateResponse{
				Certificate: createTestCertificate(),
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runIAKCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// TPM Device Additional Tests
// =============================================================================

func TestRunFlushWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		flushTransientContextsFunc: func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
			return &platformv1.FlushTransientContextsResponse{
				FlushedCount: 5,
				Status:       &platformv1.Status{Success: true, Message: "Flushed 5 contexts"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runFlushWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Flushed 5 transient TPM contexts")
}

func TestRunFlushWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		flushTransientContextsFunc: func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
			return &platformv1.FlushTransientContextsResponse{
				FlushedCount: 5,
				Status:       &platformv1.Status{Success: true, Message: "Flushed 5 contexts"},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runFlushWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunDeviceAttributesWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{
				Attributes: &platformv1.TCGDeviceAttributes{
					TpmManufacturer:      "Test TPM",
					TpmModel:             "Model X",
					TpmVersion:           "2.0",
					PlatformManufacturer: "Test Platform",
					PlatformModel:        "Platform Model",
					PlatformVersion:      "1.0",
					PlatformSerial:       "SERIAL123",
				},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runDeviceAttributesWithClient(base)
	require.NoError(t, err)
	output := base.output.String()
	assert.Contains(t, output, "Test TPM")
	assert.Contains(t, output, "Model X")
}

func TestRunDeviceAttributesWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runDeviceAttributesWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetDeviceAttributesFailed{}, err)
}

func TestRunDeviceAttributesWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockIDevIDServiceClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{
				Attributes: &platformv1.TCGDeviceAttributes{
					TpmManufacturer: "Test TPM",
					TpmModel:        "Model X",
					TpmVersion:      "2.0",
				},
			}, nil
		},
	}

	base := newMockBaseCommand(flags, mockClient)
	err := runDeviceAttributesWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
