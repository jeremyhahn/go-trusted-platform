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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Mock IDevID Client for coverage-specific BaseCommandInterface tests
// =============================================================================

type coverageMockIDevIDClient struct {
	platformv1.IDevIDServiceClient
	generateIDevIDFunc      func(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error)
	getIDevIDInfoFunc       func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error)
	deleteIDevIDFunc        func(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error)
	createIDevIDCSRFunc     func(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error)
	installIDevIDCertFunc   func(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error)
	getIDevIDCertFunc       func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error)
	generateIAKFunc         func(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error)
	getIAKInfoFunc          func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error)
	deleteIAKFunc           func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error)
	createIAKCSRFunc        func(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error)
	installIAKCertFunc      func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error)
	getIAKCertFunc          func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error)
	flushFunc               func(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error)
	getDeviceAttributesFunc func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error)
}

func (m *coverageMockIDevIDClient) GenerateIDevID(ctx context.Context, req *platformv1.GenerateIDevIDRequest, opts ...grpc.CallOption) (*platformv1.GenerateIDevIDResponse, error) {
	if m.generateIDevIDFunc != nil {
		return m.generateIDevIDFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GetIDevIDInfo(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
	if m.getIDevIDInfoFunc != nil {
		return m.getIDevIDInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) DeleteIDevID(ctx context.Context, req *platformv1.DeleteIDevIDRequest, opts ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
	if m.deleteIDevIDFunc != nil {
		return m.deleteIDevIDFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) CreateIDevIDCSR(ctx context.Context, req *platformv1.CreateIDevIDCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIDevIDCSRResponse, error) {
	if m.createIDevIDCSRFunc != nil {
		return m.createIDevIDCSRFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) InstallIDevIDCertificate(ctx context.Context, req *platformv1.InstallIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIDevIDCertificateResponse, error) {
	if m.installIDevIDCertFunc != nil {
		return m.installIDevIDCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GetIDevIDCertificate(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
	if m.getIDevIDCertFunc != nil {
		return m.getIDevIDCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GenerateIAK(ctx context.Context, req *platformv1.GenerateIAKRequest, opts ...grpc.CallOption) (*platformv1.GenerateIAKResponse, error) {
	if m.generateIAKFunc != nil {
		return m.generateIAKFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GetIAKInfo(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
	if m.getIAKInfoFunc != nil {
		return m.getIAKInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) DeleteIAK(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
	if m.deleteIAKFunc != nil {
		return m.deleteIAKFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) CreateIAKCSR(ctx context.Context, req *platformv1.CreateIAKCSRRequest, opts ...grpc.CallOption) (*platformv1.CreateIAKCSRResponse, error) {
	if m.createIAKCSRFunc != nil {
		return m.createIAKCSRFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) InstallIAKCertificate(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
	if m.installIAKCertFunc != nil {
		return m.installIAKCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GetIAKCertificate(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
	if m.getIAKCertFunc != nil {
		return m.getIAKCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) FlushTransientContexts(ctx context.Context, req *platformv1.FlushTransientContextsRequest, opts ...grpc.CallOption) (*platformv1.FlushTransientContextsResponse, error) {
	if m.flushFunc != nil {
		return m.flushFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}
func (m *coverageMockIDevIDClient) GetDeviceAttributes(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
	if m.getDeviceAttributesFunc != nil {
		return m.getDeviceAttributesFunc(ctx, req, opts...)
	}
	return nil, errors.New("not configured")
}

// =============================================================================
// Mock BaseCommandInterface for coverage tests
// =============================================================================

type coverageMockClientProvider struct {
	client *coverageMockIDevIDClient
}

func (p *coverageMockClientProvider) IDevID() platformv1.IDevIDServiceClient {
	return p.client
}

type coverageMockBaseCmd struct {
	flags   *cli.CommonFlags
	idevid  *coverageMockIDevIDClient
	printer *cli.Printer
	ctx     context.Context
	output  *bytes.Buffer
}

func newCoverageMockBaseCmd(flags *cli.CommonFlags, idevid *coverageMockIDevIDClient) *coverageMockBaseCmd {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(flags.OutputFormat, flags.NoColor, output)
	return &coverageMockBaseCmd{flags: flags, idevid: idevid, printer: printer, ctx: context.Background(), output: output}
}

func (m *coverageMockBaseCmd) Client() IDevIDClientProvider {
	return &coverageMockClientProvider{client: m.idevid}
}
func (m *coverageMockBaseCmd) Printer() *cli.Printer    { return m.printer }
func (m *coverageMockBaseCmd) Context() context.Context { return m.ctx }
func (m *coverageMockBaseCmd) Close() error             { return nil }
func (m *coverageMockBaseCmd) Flags() *cli.CommonFlags  { return m.flags }

// =============================================================================
// Eventlog WithClient Tests
// =============================================================================

func TestRunEventlogWithClient_BinaryJSON(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON, NoColor: true}
	base := newMockTPMBaseCommand(flags, &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{Format: "binary", EventCount: 5, EventLog: []byte{0xDE, 0xAD}}, nil
		},
	})
	err := runEventlogWithClient(base, "binary")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "dead")
}

func TestRunEventlogWithClient_TableBinary(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	base := newMockTPMBaseCommand(flags, &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{Format: "binary", EventCount: 3, EventLog: []byte{0x01}}, nil
		},
	})
	err := runEventlogWithClient(base, "binary")
	require.NoError(t, err)
}

func TestRunEventlogWithClient_TableText(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	base := newMockTPMBaseCommand(flags, &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{Format: "text", EventCount: 2, EventLog: []byte("event1\n")}, nil
		},
	})
	err := runEventlogWithClient(base, "text")
	require.NoError(t, err)
}

// =============================================================================
// IAK/IDevID edge case tests via BaseCommandInterface
// =============================================================================

func TestRunIAKDeleteWithClient_TableFailed(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return &platformv1.DeleteIAKResponse{Status: &platformv1.Status{Success: false, Message: "key not found"}}, nil
		},
	})
	err := runIAKDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Failed to delete IAK")
}

func TestRunIAKDeleteWithClient_TableFailedNoMsg(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		deleteIAKFunc: func(ctx context.Context, req *platformv1.DeleteIAKRequest, opts ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
			return &platformv1.DeleteIAKResponse{Status: &platformv1.Status{Success: false}}, nil
		},
	})
	err := runIAKDeleteWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "unknown error")
}

func TestRunIAKInstallWithClient_TableFailed(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	tmpFile := filepath.Join(t.TempDir(), "test.pem")
	require.NoError(t, os.WriteFile(tmpFile, []byte("cert"), 0600))
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		installIAKCertFunc: func(ctx context.Context, req *platformv1.InstallIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.InstallIAKCertificateResponse, error) {
			return &platformv1.InstallIAKCertificateResponse{Status: &platformv1.Status{Success: false, Message: "bad cert"}}, nil
		},
	})
	err := runIAKInstallWithClient(base, tmpFile)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Failed to install certificate")
}

func TestRunIAKCertWithClient_NilCert(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON, NoColor: true}
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		getIAKCertFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
			return &platformv1.GetIAKCertificateResponse{Certificate: nil}, nil
		},
	})
	err := runIAKCertWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrIAKCertificateNotFound{}, err)
}

// =============================================================================
// Device Attributes edge case tests
// =============================================================================

func TestRunDeviceAttributesWithClient_NilAttrs(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON, NoColor: true}
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{Attributes: nil}, nil
		},
	})
	err := runDeviceAttributesWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrGetDeviceAttributesFailed{}, err)
}

func TestRunDeviceAttributesWithClient_Table(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}
	base := newCoverageMockBaseCmd(flags, &coverageMockIDevIDClient{
		getDeviceAttributesFunc: func(ctx context.Context, req *platformv1.GetDeviceAttributesRequest, opts ...grpc.CallOption) (*platformv1.GetDeviceAttributesResponse, error) {
			return &platformv1.GetDeviceAttributesResponse{Attributes: &platformv1.TCGDeviceAttributes{
				TpmManufacturer: "Mfg", TpmModel: "Mdl", TpmVersion: "2.0",
				PlatformManufacturer: "PM", PlatformModel: "PMdl", PlatformVersion: "1.0", PlatformSerial: "SN",
			}}, nil
		},
	})
	err := runDeviceAttributesWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Mfg")
}

// =============================================================================
// Command Creation Tests
// =============================================================================

func TestNewClearCommand_Fields(t *testing.T) {
	cmd := newClearCommand(func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON} })
	require.NotNil(t, cmd)
	assert.Equal(t, "clear", cmd.Use)
	require.NotNil(t, cmd.Flag("owner-password"))
	require.NotNil(t, cmd.Flag("confirm"))
}

func TestNewClearCommand_WithoutConfirm(t *testing.T) {
	cmd := newClearCommand(func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON} })
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.NoError(t, err)
}

func TestNewDestroyCommand_ReturnsError(t *testing.T) {
	cmd := newDestroyCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	require.NotNil(t, cmd)
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestNewEnrollCommand_ReturnsError(t *testing.T) {
	cmd := newEnrollCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestNewExtendCommand_ReturnsError(t *testing.T) {
	cmd := newExtendCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestNewEKCommand_Subcommands(t *testing.T) {
	cmd := newEKCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	require.NotNil(t, cmd)
	assert.Equal(t, "ek", cmd.Use)
	assert.Len(t, cmd.Commands(), 4)
}

func TestNewEventlogCommand_Flags(t *testing.T) {
	cmd := newEventlogCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	require.NotNil(t, cmd)
	formatFlag := cmd.Flag("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "text", formatFlag.DefValue)
}

func TestKeyAlgorithmStringValues(t *testing.T) {
	tests := []struct {
		alg      tpmsvc.KeyAlgorithm
		expected string
	}{
		{tpmsvc.KeyAlgorithmRSA2048, "RSA-2048"},
		{tpmsvc.KeyAlgorithmRSA3072, "RSA-3072"},
		{tpmsvc.KeyAlgorithmRSA4096, "RSA-4096"},
		{tpmsvc.KeyAlgorithmECDSAP256, "ECDSA-P256"},
		{tpmsvc.KeyAlgorithmECDSAP384, "ECDSA-P384"},
		{tpmsvc.KeyAlgorithmECDSAP521, "ECDSA-P521"},
		{tpmsvc.KeyAlgorithmUnspecified, "UNSPECIFIED"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, string(tc.alg))
	}
}
