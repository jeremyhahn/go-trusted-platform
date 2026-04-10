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

package barrier

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// printInitTable Tests
// =============================================================================

func TestPrintInitTable_SingleKey(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierInitResponse{
		Strategy:      platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		InitializedAt: timestamppb.Now(),
		RootToken:     "root-token-123",
		UnsealKeys:    []string{"key-1"},
	}

	err := printInitTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "initialized successfully")
	assert.Contains(t, out, "single-key")
	assert.Contains(t, out, "root-token-123")
	assert.Contains(t, out, "key-1")
}

func TestPrintInitTable_Shamir(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierInitResponse{
		Strategy:   platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		UnsealKeys: []string{"share-1", "share-2", "share-3"},
	}

	err := printInitTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "shamir")
	assert.Contains(t, out, "share-1")
	assert.Contains(t, out, "share-2")
	assert.Contains(t, out, "share-3")
}

func TestPrintInitTable_NoUnsealKeys(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierInitResponse{
		Strategy: platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	}

	err := printInitTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "initialized successfully")
	assert.NotContains(t, out, "Unseal Key")
}

func TestPrintInitTable_NilInitializedAt(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierInitResponse{
		Strategy:   platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		UnsealKeys: []string{"key-1"},
	}

	err := printInitTable(printer, resp)
	require.NoError(t, err)
	assert.NotContains(t, output.String(), "Initialized At")
}

// =============================================================================
// printStatusTable Tests
// =============================================================================

func TestPrintStatusTable_Unsealed(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierStatusResponse{
		Initialized:   true,
		Sealed:        false,
		Strategy:      platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
		InitializedAt: timestamppb.Now(),
	}

	err := printStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "true")
	assert.Contains(t, out, "false")
	assert.Contains(t, out, "single-key")
}

func TestPrintStatusTable_ShamirDetails(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierStatusResponse{
		Initialized:    true,
		Sealed:         true,
		Strategy:       platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		Threshold:      3,
		SharesTotal:    5,
		SharesProvided: 1,
		InitializedAt:  timestamppb.Now(),
	}

	err := printStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "shamir")
	assert.Contains(t, out, "3")
	assert.Contains(t, out, "5")
	assert.Contains(t, out, "1")
}

func TestPrintStatusTable_NilInitializedAt(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierStatusResponse{
		Initialized: false,
		Sealed:      true,
		Strategy:    platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED,
	}

	err := printStatusTable(printer, resp)
	require.NoError(t, err)
	assert.NotContains(t, output.String(), "Initialized At")
}

// =============================================================================
// printUnsealTable Tests
// =============================================================================

func TestPrintUnsealTable_Unsealed(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierUnsealResponse{
		Sealed: false,
	}

	err := printUnsealTable(printer, resp)
	require.NoError(t, err)
	assert.Contains(t, output.String(), "unsealed successfully")
}

func TestPrintUnsealTable_ShamirProgress(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierUnsealResponse{
		Sealed:          true,
		SharesProvided:  2,
		SharesThreshold: 3,
	}

	err := printUnsealTable(printer, resp)
	require.NoError(t, err)
	assert.Contains(t, output.String(), "2/3")
}

// =============================================================================
// printRekeyTable Tests
// =============================================================================

func TestPrintRekeyTable_Success(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierRekeyResponse{
		Strategy:   platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		UnsealKeys: []string{"new-key-1", "new-key-2"},
	}

	err := printRekeyTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "rekeyed successfully")
	assert.Contains(t, out, "shamir")
	assert.Contains(t, out, "new-key-1")
	assert.Contains(t, out, "new-key-2")
}

func TestPrintRekeyTable_NoKeys(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &platformv1.BarrierRekeyResponse{
		Strategy: platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY,
	}

	err := printRekeyTable(printer, resp)
	require.NoError(t, err)
	assert.Contains(t, output.String(), "rekeyed successfully")
	assert.NotContains(t, output.String(), "Unseal Key")
}

// =============================================================================
// Command Construction Tests (cover remaining newXxx branches)
// =============================================================================

func TestNewSealCommand_Structure(t *testing.T) {
	cmd := newSealCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "seal", cmd.Use)
	assert.Equal(t, "Seal the barrier", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

func TestNewStatusCommand_Structure(t *testing.T) {
	cmd := newStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	assert.Equal(t, "status", cmd.Use)
	assert.Equal(t, "Show barrier status", cmd.Short)
	assert.NotNil(t, cmd.RunE)
	assert.NotEmpty(t, cmd.Long)
}
