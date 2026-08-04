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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Seal Tests
// =============================================================================

func TestRunSealWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			assert.Equal(t, "test-secret", req.Cn)
			assert.Equal(t, []byte("my-data"), req.Data)
			assert.Equal(t, platformv1.PCRBank_PCR_BANK_SHA256, req.PcrBank)
			return &platformv1.SealResponse{
				Status: &platformv1.Status{Success: true, Message: "Sealed"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{
		CN:      "test-secret",
		Data:    "my-data",
		PCRBank: "sha256",
	}
	err := runSealWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunSealWithClient_WithPCRIndices(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			assert.Equal(t, []uint32{0, 7, 23}, req.PcrIndices)
			return &platformv1.SealResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{
		CN:         "test-secret",
		Data:       "my-data",
		PCRBank:    "sha256",
		PCRIndices: []uint32{0, 7, 23},
	}
	err := runSealWithClient(base, opts)
	require.NoError(t, err)
}

func TestRunSealWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			return nil, errors.New("PCR mismatch")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{
		CN:   "test-secret",
		Data: "my-data",
	}
	err := runSealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSealFailed{}, err)
}

func TestRunSealWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			return &platformv1.SealResponse{Status: nil}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{CN: "test-secret", Data: "my-data"}
	err := runSealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSealFailed{}, err)
}

func TestRunSealWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			return &platformv1.SealResponse{
				Status: &platformv1.Status{Success: false, Message: "Object exists"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{CN: "test-secret", Data: "my-data"}
	err := runSealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrSealFailed{}, err)
}

func TestRunSealWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			return &platformv1.SealResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{CN: "test-secret", Data: "my-data"}
	err := runSealWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "sealed successfully")
}

func TestRunSealWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		sealFunc: func(ctx context.Context, req *platformv1.SealRequest, opts ...grpc.CallOption) (*platformv1.SealResponse, error) {
			return &platformv1.SealResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &sealOptions{CN: "test-secret", Data: "my-data"}
	err := runSealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// Unseal Tests
// =============================================================================

func TestRunUnsealWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			assert.Equal(t, "test-secret", req.Cn)
			return &platformv1.UnsealResponse{
				Status: &platformv1.Status{Success: true},
				Data:   []byte("my-secret-data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{
		CN:      "test-secret",
		PCRBank: "sha256",
	}
	err := runUnsealWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "my-secret-data")
}

func TestRunUnsealWithClient_WithPassword(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			assert.Equal(t, "my-password", req.Password)
			return &platformv1.UnsealResponse{
				Status: &platformv1.Status{Success: true},
				Data:   []byte("data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{
		CN:       "test-secret",
		Password: "my-password",
		PCRBank:  "sha256",
	}
	err := runUnsealWithClient(base, opts)
	require.NoError(t, err)
}

func TestRunUnsealWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			return nil, errors.New("policy not satisfied")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{CN: "test-secret"}
	err := runUnsealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrUnsealFailed{}, err)
}

func TestRunUnsealWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with nil Status.
	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			return nil, errors.New("unseal failed: nil status")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{CN: "test-secret"}
	err := runUnsealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrUnsealFailed{}, err)
}

func TestRunUnsealWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with Status.Success=false.
	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			return nil, errors.New("PCR mismatch")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{CN: "test-secret"}
	err := runUnsealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrUnsealFailed{}, err)
}

func TestRunUnsealWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			return &platformv1.UnsealResponse{
				Status: &platformv1.Status{Success: true},
				Data:   []byte("my-secret-data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{CN: "test-secret"}
	err := runUnsealWithClient(base, opts)
	require.NoError(t, err)
	// Table format just prints the raw data
}

func TestRunUnsealWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		unsealFunc: func(ctx context.Context, req *platformv1.UnsealRequest, opts ...grpc.CallOption) (*platformv1.UnsealResponse, error) {
			return &platformv1.UnsealResponse{
				Status: &platformv1.Status{Success: true},
				Data:   []byte("data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &unsealOptions{CN: "test-secret"}
	err := runUnsealWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// Eventlog Tests
// =============================================================================

func TestRunEventlogWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			assert.Equal(t, "text", req.Format)
			return &platformv1.GetEventLogResponse{
				Format:     "text",
				EventCount: 10,
				EventLog:   []byte("Event log content"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "text")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "10")
}

func TestRunEventlogWithClient_BinaryFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{
				Format:     "binary",
				EventCount: 5,
				EventLog:   []byte{0x00, 0x01, 0x02},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "binary")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "000102")
}

func TestRunEventlogWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return nil, errors.New("file not found")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "text")
	require.Error(t, err)
	assert.IsType(t, ErrEventLogFailed{}, err)
}

func TestRunEventlogWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{
				Format:     "text",
				EventCount: 3,
				EventLog:   []byte("Event log"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "text")
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunEventlogWithClient_TableFormat_Binary(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{
				Format:     "binary",
				EventCount: 3,
				EventLog:   []byte{0xAB, 0xCD},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "binary")
	require.NoError(t, err)
}

func TestRunEventlogWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		getEventLogFunc: func(ctx context.Context, req *platformv1.GetEventLogRequest, opts ...grpc.CallOption) (*platformv1.GetEventLogResponse, error) {
			return &platformv1.GetEventLogResponse{
				Format:     "text",
				EventCount: 1,
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runEventlogWithClient(base, "text")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
