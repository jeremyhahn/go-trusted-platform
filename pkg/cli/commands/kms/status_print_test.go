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

package kms

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestPrintKMSStatusTable_Full(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &kmssvc.BackendStatusResult{
		BackendStatus: "healthy",
		BackendType:   "software",
		Device:        "/dev/tpm0",
		Region:        "us-east-1",
		KeyID:         "key-123",
		PcrBanks:      []string{"SHA256", "SHA384"},
		PcrRegisters:  []int32{0, 7, 14},
		Capabilities: map[string]bool{
			"encryption":     true,
			"key_generation": true,
			"signing":        false,
		},
		Timestamp: 1700000000,
	}

	err := printKMSStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "software")
	assert.Contains(t, out, "/dev/tpm0")
	assert.Contains(t, out, "us-east-1")
	assert.Contains(t, out, "key-123")
}

func TestPrintKMSStatusTable_Minimal(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &kmssvc.BackendStatusResult{
		BackendType: "software",
	}

	err := printKMSStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "software")
	assert.Contains(t, out, "UNKNOWN")
}

func TestPrintKMSStatusTable_WithExplicitStatus(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &kmssvc.BackendStatusResult{
		BackendStatus: "degraded",
		BackendType:   "tpm",
	}

	err := printKMSStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.Contains(t, out, "DEGRADED")
	assert.Contains(t, out, "degraded")
}

func TestPrintKMSStatusTable_NoPCRBanks(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	resp := &kmssvc.BackendStatusResult{
		BackendType:   "software",
		BackendStatus: "healthy",
	}

	err := printKMSStatusTable(printer, resp)
	require.NoError(t, err)

	out := output.String()
	assert.NotContains(t, out, "PCR")
}
