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
// NVRAM Define Tests
// =============================================================================

func TestRunNVRAMDefineWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			assert.Equal(t, uint32(0x01000001), req.Index)
			assert.Equal(t, uint32(256), req.Size)
			return &platformv1.DefineNVRAMResponse{
				Status: &platformv1.Status{Success: true, Message: "Defined"},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{
		Index: 0x01000001,
		Size:  256,
	}
	err := runNVRAMDefineWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x01000001")
}

func TestRunNVRAMDefineWithClient_WithAttributes(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			assert.Equal(t, []string{"AUTHWRITE", "AUTHREAD"}, req.Attributes)
			return &platformv1.DefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{
		Index:      0x01000001,
		Size:       256,
		Attributes: []string{"AUTHWRITE", "AUTHREAD"},
	}
	err := runNVRAMDefineWithClient(base, opts)
	require.NoError(t, err)
}

func TestRunNVRAMDefineWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			return nil, errors.New("index exists")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{Index: 0x01000001, Size: 256}
	err := runNVRAMDefineWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDefineFailed{}, err)
}

func TestRunNVRAMDefineWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with nil Status.
	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			return nil, errors.New("define failed: nil status")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{Index: 0x01000001, Size: 256}
	err := runNVRAMDefineWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDefineFailed{}, err)
}

func TestRunNVRAMDefineWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with Status.Success=false.
	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			return nil, errors.New("out of space")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{Index: 0x01000001, Size: 256}
	err := runNVRAMDefineWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDefineFailed{}, err)
}

func TestRunNVRAMDefineWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			return &platformv1.DefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{Index: 0x01000001, Size: 256}
	err := runNVRAMDefineWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "defined")
}

func TestRunNVRAMDefineWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		defineNVRAMFunc: func(ctx context.Context, req *platformv1.DefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.DefineNVRAMResponse, error) {
			return &platformv1.DefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramDefineOptions{Index: 0x01000001, Size: 256}
	err := runNVRAMDefineWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// NVRAM Write Tests
// =============================================================================

func TestRunNVRAMWriteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			assert.Equal(t, uint32(0x01000001), req.Index)
			assert.Equal(t, []byte("test data"), req.Data)
			return &platformv1.WriteNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{
		Index: 0x01000001,
		Data:  "test data",
	}
	err := runNVRAMWriteWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunNVRAMWriteWithClient_WithOffset(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			assert.Equal(t, uint32(10), req.Offset)
			return &platformv1.WriteNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{
		Index:  0x01000001,
		Data:   "data",
		Offset: 10,
	}
	err := runNVRAMWriteWithClient(base, opts)
	require.NoError(t, err)
}

func TestRunNVRAMWriteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			return nil, errors.New("write locked")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{Index: 0x01000001, Data: "data"}
	err := runNVRAMWriteWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMWriteFailed{}, err)
}

func TestRunNVRAMWriteWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with nil Status.
	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			return nil, errors.New("write failed: nil status")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{Index: 0x01000001, Data: "data"}
	err := runNVRAMWriteWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMWriteFailed{}, err)
}

func TestRunNVRAMWriteWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with Status.Success=false.
	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			return nil, errors.New("auth failed")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{Index: 0x01000001, Data: "data"}
	err := runNVRAMWriteWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMWriteFailed{}, err)
}

func TestRunNVRAMWriteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			return &platformv1.WriteNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{Index: 0x01000001, Data: "data"}
	err := runNVRAMWriteWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "Written")
}

func TestRunNVRAMWriteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		writeNVRAMFunc: func(ctx context.Context, req *platformv1.WriteNVRAMRequest, opts ...grpc.CallOption) (*platformv1.WriteNVRAMResponse, error) {
			return &platformv1.WriteNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramWriteOptions{Index: 0x01000001, Data: "data"}
	err := runNVRAMWriteWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// NVRAM Read Tests
// =============================================================================

func TestRunNVRAMReadWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			assert.Equal(t, uint32(0x01000001), req.Index)
			return &platformv1.ReadNVRAMResponse{
				Data: []byte("stored data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{
		Index: 0x01000001,
	}
	err := runNVRAMReadWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "stored data")
}

func TestRunNVRAMReadWithClient_HexOutput(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			return &platformv1.ReadNVRAMResponse{
				Data: []byte{0xAB, 0xCD, 0xEF},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{
		Index:     0x01000001,
		HexOutput: true,
	}
	err := runNVRAMReadWithClient(base, opts)
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "abcdef")
}

func TestRunNVRAMReadWithClient_WithOffsetAndSize(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			assert.Equal(t, uint32(10), req.Offset)
			assert.Equal(t, uint32(50), req.Size)
			return &platformv1.ReadNVRAMResponse{
				Data: []byte("partial"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{
		Index:  0x01000001,
		Offset: 10,
		Size:   50,
	}
	err := runNVRAMReadWithClient(base, opts)
	require.NoError(t, err)
}

func TestRunNVRAMReadWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			return nil, errors.New("read locked")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{Index: 0x01000001}
	err := runNVRAMReadWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMReadFailed{}, err)
}

func TestRunNVRAMReadWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			return &platformv1.ReadNVRAMResponse{
				Data: []byte("my-data"),
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{Index: 0x01000001}
	err := runNVRAMReadWithClient(base, opts)
	require.NoError(t, err)
	assert.NotEmpty(t, base.output.String())
}

func TestRunNVRAMReadWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		readNVRAMFunc: func(ctx context.Context, req *platformv1.ReadNVRAMRequest, opts ...grpc.CallOption) (*platformv1.ReadNVRAMResponse, error) {
			return &platformv1.ReadNVRAMResponse{Data: []byte("data")}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	opts := &nvramReadOptions{Index: 0x01000001}
	err := runNVRAMReadWithClient(base, opts)
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

// =============================================================================
// NVRAM Delete Tests
// =============================================================================

func TestRunNVRAMDeleteWithClient_Success(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			assert.Equal(t, uint32(0x01000001), req.Index)
			return &platformv1.UndefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "true")
}

func TestRunNVRAMDeleteWithClient_WithPassword(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			assert.Equal(t, "my-password", req.Password)
			return &platformv1.UndefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "my-password")
	require.NoError(t, err)
}

func TestRunNVRAMDeleteWithClient_Error(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			return nil, errors.New("auth failed")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDeleteFailed{}, err)
}

func TestRunNVRAMDeleteWithClient_StatusNil(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with nil Status.
	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			return nil, errors.New("delete failed: nil status")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDeleteFailed{}, err)
}

func TestRunNVRAMDeleteWithClient_StatusFailed(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// SDK domain methods return an error when the gRPC call fails;
	// they never return a response with Status.Success=false.
	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			return nil, errors.New("not found")
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.Error(t, err)
	assert.IsType(t, ErrNVRAMDeleteFailed{}, err)
}

func TestRunNVRAMDeleteWithClient_TableFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			return &platformv1.UndefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "deleted")
}

func TestRunNVRAMDeleteWithClient_InvalidFormat(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: "invalid",
		NoColor:      true,
	}

	mockClient := &mockTPMServiceClient{
		undefineNVRAMFunc: func(ctx context.Context, req *platformv1.UndefineNVRAMRequest, opts ...grpc.CallOption) (*platformv1.UndefineNVRAMResponse, error) {
			return &platformv1.UndefineNVRAMResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	base := newMockTPMBaseCommand(flags, mockClient)
	err := runNVRAMDeleteWithClient(base, 0x01000001, "")
	require.Error(t, err)
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
