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
// EK Create Tests
// =============================================================================

func TestRunEKCreateWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			assert.True(t, req.Persistent)
			return &platformv1.CreateEKResponse{
				Status:    &platformv1.Status{Success: true, Message: "EK created"},
				Handle:    0x81010001,
				PublicKey: []byte{0x01, 0x02, 0x03},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81010001")
}

func TestRunEKCreateWithClient_InvalidAlgorithm(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{}
	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "INVALID-ALG", true)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidKeyAlgorithm{}, err)
}

func TestRunEKCreateWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			return nil, errors.New("TPM busy")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.Error(t, err)
	assert.IsType(t, ErrEKCreateFailed{}, err)
}

func TestRunEKCreateWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			return &platformv1.CreateEKResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.Error(t, err)
	assert.IsType(t, ErrEKCreateFailed{}, err)
}

func TestRunEKCreateWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			return &platformv1.CreateEKResponse{
				Status: &platformv1.Status{Success: false, Message: "EK exists"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.Error(t, err)
	assert.IsType(t, ErrEKCreateFailed{}, err)
}

func TestRunEKCreateWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			return &platformv1.CreateEKResponse{
				Status:    &platformv1.Status{Success: true},
				Handle:    0x81010001,
				PublicKey: []byte{0x01, 0x02},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "created successfully")
}

func TestRunEKCreateWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createEKFunc: func(ctx context.Context, req *platformv1.CreateEKRequest, opts ...grpc.CallOption) (*platformv1.CreateEKResponse, error) {
			return &platformv1.CreateEKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCreateWithClient(base, "RSA-2048", true)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// EK Info Tests
// =============================================================================

func TestRunEKInfoWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKFunc: func(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error) {
			assert.Equal(t, uint32(0x81010001), req.Handle)
			return &platformv1.GetEKResponse{
				Handle:    0x81010001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
				PublicKey: []byte{0x01, 0x02, 0x03},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKInfoWithClient(base, 0x81010001)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81010001")
}

func TestRunEKInfoWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKFunc: func(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error) {
			return nil, errors.New("not found")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKInfoWithClient(base, 0x81010001)
	require.Error(t, err)
	assert.IsType(t, ErrEKNotFound{}, err)
}

func TestRunEKInfoWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKFunc: func(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error) {
			return &platformv1.GetEKResponse{
				Handle:    0x81010001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKInfoWithClient(base, 0x81010001)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunEKInfoWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKFunc: func(ctx context.Context, req *platformv1.GetEKRequest, opts ...grpc.CallOption) (*platformv1.GetEKResponse, error) {
			return &platformv1.GetEKResponse{
				Handle:    0x81010001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKInfoWithClient(base, 0x81010001)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// EK Certificate Tests
// =============================================================================

func TestRunEKCertificateWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
			return &platformv1.GetEKCertificateResponse{
				Certificate: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
				Format:      "PEM",
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCertificateWithClient(base)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "PEM")
}

func TestRunEKCertificateWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
			return nil, errors.New("certificate not found")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCertificateWithClient(base)
	require.Error(t, err)
	assert.IsType(t, ErrEKCertificateNotFound{}, err)
}

func TestRunEKCertificateWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
			return &platformv1.GetEKCertificateResponse{
				Certificate: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"),
				Format:      "PEM",
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCertificateWithClient(base)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunEKCertificateWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
			return &platformv1.GetEKCertificateResponse{Format: "PEM"}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKCertificateWithClient(base)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// EK Delete Tests
// =============================================================================

func TestRunEKDeleteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			assert.Equal(t, uint32(0x81010001), req.Handle)
			assert.Equal(t, "password", req.Password)
			return &platformv1.DeleteEKResponse{
				Status: &platformv1.Status{Success: true, Message: "Deleted"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "password")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunEKDeleteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			return nil, errors.New("auth failed")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "")
	require.Error(t, err)
	assert.IsType(t, ErrEKDeleteFailed{}, err)
}

func TestRunEKDeleteWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			return &platformv1.DeleteEKResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "")
	require.Error(t, err)
	assert.IsType(t, ErrEKDeleteFailed{}, err)
}

func TestRunEKDeleteWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			return &platformv1.DeleteEKResponse{
				Status: &platformv1.Status{Success: false, Message: "Not found"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "")
	require.Error(t, err)
	assert.IsType(t, ErrEKDeleteFailed{}, err)
}

func TestRunEKDeleteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			return &platformv1.DeleteEKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "deleted successfully")
}

func TestRunEKDeleteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteEKFunc: func(ctx context.Context, req *platformv1.DeleteEKRequest, opts ...grpc.CallOption) (*platformv1.DeleteEKResponse, error) {
			return &platformv1.DeleteEKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEKDeleteWithClient(base, 0x81010001, "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// SRK Create Tests
// =============================================================================

func TestRunSRKCreateWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			assert.True(t, req.Persistent)
			return &platformv1.CreateSRKResponse{
				Status:    &platformv1.Status{Success: true},
				Handle:    0x81000001,
				PublicKey: []byte{0x01, 0x02},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{
		Algorithm:  "RSA-2048",
		Persistent: true,
	}
	err := runSRKCreateWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81000001")
}

func TestRunSRKCreateWithClient_InvalidAlgorithm(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{}
	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "INVALID"}
	err := runSRKCreateWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidKeyAlgorithm{}, err)
}

func TestRunSRKCreateWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			return nil, errors.New("TPM error")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "RSA-2048"}
	err := runSRKCreateWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSRKCreateFailed{}, err)
}

func TestRunSRKCreateWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			return &platformv1.CreateSRKResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "RSA-2048"}
	err := runSRKCreateWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSRKCreateFailed{}, err)
}

func TestRunSRKCreateWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			return &platformv1.CreateSRKResponse{
				Status: &platformv1.Status{Success: false, Message: "SRK exists"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "RSA-2048"}
	err := runSRKCreateWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSRKCreateFailed{}, err)
}

func TestRunSRKCreateWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			return &platformv1.CreateSRKResponse{
				Status: &platformv1.Status{Success: true},
				Handle: 0x81000001,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "RSA-2048"}
	err := runSRKCreateWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "created successfully")
}

func TestRunSRKCreateWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		createSRKFunc: func(ctx context.Context, req *platformv1.CreateSRKRequest, opts ...grpc.CallOption) (*platformv1.CreateSRKResponse, error) {
			return &platformv1.CreateSRKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &srkCreateOptions{Algorithm: "RSA-2048"}
	err := runSRKCreateWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// SRK Info Tests
// =============================================================================

func TestRunSRKInfoWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
			return &platformv1.GetSRKResponse{
				Handle:    0x81000001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
				PublicKey: []byte{0x01, 0x02},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKInfoWithClient(base, 0x81000001)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81000001")
}

func TestRunSRKInfoWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
			return nil, errors.New("not found")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKInfoWithClient(base, 0x81000001)
	require.Error(t, err)
	assert.IsType(t, ErrSRKNotFound{}, err)
}

func TestRunSRKInfoWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
			return &platformv1.GetSRKResponse{
				Handle:    0x81000001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKInfoWithClient(base, 0x81000001)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunSRKInfoWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
			return &platformv1.GetSRKResponse{
				Handle:    0x81000001,
				Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKInfoWithClient(base, 0x81000001)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// SRK Delete Tests
// =============================================================================

func TestRunSRKDeleteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return &platformv1.DeleteSRKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunSRKDeleteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return nil, errors.New("auth failed")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrSRKDeleteFailed{}, err)
}

func TestRunSRKDeleteWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return &platformv1.DeleteSRKResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrSRKDeleteFailed{}, err)
}

func TestRunSRKDeleteWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return &platformv1.DeleteSRKResponse{
				Status: &platformv1.Status{Success: false, Message: "Not found"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrSRKDeleteFailed{}, err)
}

func TestRunSRKDeleteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return &platformv1.DeleteSRKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "deleted successfully")
}

func TestRunSRKDeleteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		deleteSRKFunc: func(ctx context.Context, req *platformv1.DeleteSRKRequest, opts ...grpc.CallOption) (*platformv1.DeleteSRKResponse, error) {
			return &platformv1.DeleteSRKResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runSRKDeleteWithClient(base, 0x81000001, "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
