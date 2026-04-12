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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Mock TPM Service Client
// =============================================================================

type mockTPMServiceClient struct {
	platformv1.TPMServiceClient

	infoFunc          func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error)
	provisionFunc     func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error)
	clearFunc         func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error)
	createEKFunc      func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error)
	getEKFunc         func(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error)
	getEKCertFunc     func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error)
	deleteEKFunc      func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error)
	createSRKFunc     func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error)
	getSRKFunc        func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error)
	deleteSRKFunc     func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error)
	sealFunc          func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error)
	unsealFunc        func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error)
	getEventLogFunc   func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error)
	defineNVRAMFunc   func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error)
	writeNVRAMFunc    func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error)
	readNVRAMFunc     func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error)
	undefineNVRAMFunc func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error)
}

func (m *mockTPMServiceClient) Info(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
	if m.infoFunc != nil {
		return m.infoFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: Info not configured")
}

func (m *mockTPMServiceClient) Provision(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
	if m.provisionFunc != nil {
		return m.provisionFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: Provision not configured")
}

func (m *mockTPMServiceClient) Clear(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
	if m.clearFunc != nil {
		return m.clearFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: Clear not configured")
}

func (m *mockTPMServiceClient) CreateEK(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
	if m.createEKFunc != nil {
		return m.createEKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: CreateEK not configured")
}

func (m *mockTPMServiceClient) GetEK(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error) {
	if m.getEKFunc != nil {
		return m.getEKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetEK not configured")
}

func (m *mockTPMServiceClient) GetEKCertificate(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
	if m.getEKCertFunc != nil {
		return m.getEKCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetEKCertificate not configured")
}

func (m *mockTPMServiceClient) DeleteEK(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
	if m.deleteEKFunc != nil {
		return m.deleteEKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: DeleteEK not configured")
}

func (m *mockTPMServiceClient) CreateSRK(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
	if m.createSRKFunc != nil {
		return m.createSRKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: CreateSRK not configured")
}

func (m *mockTPMServiceClient) GetSRK(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
	if m.getSRKFunc != nil {
		return m.getSRKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetSRK not configured")
}

func (m *mockTPMServiceClient) DeleteSRK(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
	if m.deleteSRKFunc != nil {
		return m.deleteSRKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: DeleteSRK not configured")
}

func (m *mockTPMServiceClient) Seal(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
	if m.sealFunc != nil {
		return m.sealFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: Seal not configured")
}

func (m *mockTPMServiceClient) Unseal(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
	if m.unsealFunc != nil {
		return m.unsealFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: Unseal not configured")
}

func (m *mockTPMServiceClient) GetEventLog(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
	if m.getEventLogFunc != nil {
		return m.getEventLogFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetEventLog not configured")
}

func (m *mockTPMServiceClient) DefineNVRAM(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
	if m.defineNVRAMFunc != nil {
		return m.defineNVRAMFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: DefineNVRAM not configured")
}

func (m *mockTPMServiceClient) WriteNVRAM(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
	if m.writeNVRAMFunc != nil {
		return m.writeNVRAMFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: WriteNVRAM not configured")
}

func (m *mockTPMServiceClient) ReadNVRAM(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
	if m.readNVRAMFunc != nil {
		return m.readNVRAMFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: ReadNVRAM not configured")
}

func (m *mockTPMServiceClient) UndefineNVRAM(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
	if m.undefineNVRAMFunc != nil {
		return m.undefineNVRAMFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: UndefineNVRAM not configured")
}

// =============================================================================
// Mock TPM Base Command
// =============================================================================

type mockTPMBaseCommand struct {
	flags     *cli.CommonFlags
	tpmClient platformv1.TPMServiceClient
	printer   *cli.Printer
	ctx       context.Context
	output    *bytes.Buffer
}

func newMockTPMBaseCommand(flags *cli.CommonFlags, tpmClient platformv1.TPMServiceClient) *mockTPMBaseCommand {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, output)

	return &mockTPMBaseCommand{
		flags:     flags,
		tpmClient: tpmClient,
		printer:   printer,
		ctx:       context.Background(),
		output:    output,
	}
}

func (m *mockTPMBaseCommand) TPMClient() platformv1.TPMServiceClient {
	return m.tpmClient
}

func (m *mockTPMBaseCommand) Printer() *cli.Printer {
	return m.printer
}

func (m *mockTPMBaseCommand) Context() context.Context {
	return m.ctx
}

func (m *mockTPMBaseCommand) Close() error {
	return nil
}

func (m *mockTPMBaseCommand) Flags() *cli.CommonFlags {
	return m.flags
}

// =============================================================================
// TPM Info Tests
// =============================================================================

func TestRunInfoWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		infoFunc: func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
			return &platformv1.TPMInfoResponse{
				Version:     platformv1.TPMVersion_TPM_VERSION_2_0,
				IsSimulator: false,
				FipsMode:    true,
				Properties: map[string]string{
					"info": "TPM 2.0 - Test TPM Model X",
				},
				Manufacturer: &platformv1.TPMManufacturer{
					Name:  "Test TPM",
					Model: "Model X",
				},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runInfoWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "2.0")
}

func TestRunInfoWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		infoFunc: func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
			return nil, errors.New("connection refused")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrTPMInfoFailed{}, err)
}

func TestRunInfoWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		infoFunc: func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
			return &platformv1.TPMInfoResponse{
				Version:     platformv1.TPMVersion_TPM_VERSION_2_0,
				IsSimulator: true,
				Manufacturer: &platformv1.TPMManufacturer{
					Name:            "Test TPM",
					Model:           "Model X",
					FirmwareVersion: "1.0",
				},
				PcrBanks:     []platformv1.PCRBank{platformv1.PCRBank_PCR_BANK_SHA256},
				MaxNvramSize: 4096,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runInfoWithClient(base)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunInfoWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		infoFunc: func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
			return &platformv1.TPMInfoResponse{
				Version: platformv1.TPMVersion_TPM_VERSION_2_0,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runInfoWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// TPM Provision Tests
// =============================================================================

func TestRunProvisionWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			assert.True(t, req.CreateEk)
			assert.True(t, req.CreateSrk)
			assert.True(t, req.CreateAk)
			return &platformv1.TPMProvisionResponse{
				Status:    &platformv1.Status{Success: true, Message: "Provisioned"},
				EkPublic:  []byte("ek-public"),
				SrkPublic: []byte("srk-public"),
				AkPublic:  []byte("ak-public"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{
		CreateEK:  true,
		CreateSRK: true,
		CreateAK:  true,
	}
	err := runProvisionWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunProvisionWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			return nil, errors.New("TPM locked")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{
		CreateEK: true,
	}
	err := runProvisionWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrTPMProvisionFailed{}, err)
}

func TestRunProvisionWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			return &platformv1.TPMProvisionResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{}
	err := runProvisionWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrTPMProvisionFailed{}, err)
}

func TestRunProvisionWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			return &platformv1.TPMProvisionResponse{
				Status: &platformv1.Status{Success: false, Message: "Already provisioned"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{}
	err := runProvisionWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrTPMProvisionFailed{}, err)
	assert.Contains(t, err.Error(), "Already provisioned")
}

func TestRunProvisionWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			return &platformv1.TPMProvisionResponse{
				Status:    &platformv1.Status{Success: true, Message: "Provisioned"},
				EkPublic:  []byte("ek"),
				SrkPublic: []byte("srk"),
				AkPublic:  []byte("ak"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{
		CreateEK:  true,
		CreateSRK: true,
		CreateAK:  true,
	}
	err := runProvisionWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "provisioned successfully")
}

func TestRunProvisionWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		provisionFunc: func(ctx context.Context, req *platformv1.TPMProvisionRequest, opts ...grpc.CallOption) (*platformv1.TPMProvisionResponse, error) {
			return &platformv1.TPMProvisionResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &provisionOptions{}
	err := runProvisionWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// TPM Clear Tests
// =============================================================================

func TestRunClearWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			assert.True(t, req.Confirm)
			return &platformv1.TPMClearResponse{
				Status: &platformv1.Status{Success: true, Message: "TPM cleared"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunClearWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			return nil, errors.New("lockout mode")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "")
	require.Error(t, err)
	assert.IsType(t, ErrTPMClearFailed{}, err)
}

func TestRunClearWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK Clear() returns an error when the gRPC call fails;
	// it never returns a response with nil Status.
	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			return nil, errors.New("clear failed: nil status")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "")
	require.Error(t, err)
	assert.IsType(t, ErrTPMClearFailed{}, err)
}

func TestRunClearWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK Clear() returns an error when the gRPC call fails;
	// it never returns a response with Status.Success=false.
	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			return nil, errors.New("authorization failed")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "")
	require.Error(t, err)
	assert.IsType(t, ErrTPMClearFailed{}, err)
}

func TestRunClearWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			return &platformv1.TPMClearResponse{
				Status: &platformv1.Status{Success: true, Message: "Cleared"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "password")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "cleared successfully")
}

func TestRunClearWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		clearFunc: func(ctx context.Context, req *platformv1.TPMClearRequest, opts ...grpc.CallOption) (*platformv1.TPMClearResponse, error) {
			return &platformv1.TPMClearResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runClearWithClient(base, "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
