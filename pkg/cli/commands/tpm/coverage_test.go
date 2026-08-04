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
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// =============================================================================
// Mock IDevID Client for coverage-specific BaseCommandInterface tests
// =============================================================================

// =============================================================================
// Mock BaseCommandInterface for coverage tests
// =============================================================================

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

// =============================================================================
// Device Attributes edge case tests
// =============================================================================

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
