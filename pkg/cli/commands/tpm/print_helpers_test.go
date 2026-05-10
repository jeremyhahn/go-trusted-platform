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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// =============================================================================
// printTPMInfoDetails Tests
// =============================================================================

func TestPrintTPMInfoDetails(t *testing.T) {
	t.Run("with all fields", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: true,
			Properties: map[string]string{
				"info": "TPM Information\nVersion: 2.0\nManufacturer: Test TPM\nModel: Model X\nFirmware: 1.0.0\nMax NVRAM: 4096\nPCR Banks: SHA1, SHA256\nFIPS Mode: No\nSimulator: Yes",
			},
		}

		printTPMInfoDetails(printer, resp)

		result := output.String()
		assert.Contains(t, result, "2.0")
		assert.Contains(t, result, "Test TPM")
	})

	t.Run("without properties", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: false,
		}

		printTPMInfoDetails(printer, resp)

		// Should not panic
		_ = output.String()
	})

	t.Run("empty properties", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: false,
			Properties:  map[string]string{},
		}

		printTPMInfoDetails(printer, resp)

		// Should not panic
		_ = output.String()
	})

	t.Run("info property only", func(t *testing.T) {
		output := &bytes.Buffer{}
		printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

		resp := &tpmsvc.InfoResponse{
			IsSimulator: true,
			Properties: map[string]string{
				"info": "TPM Information\nVersion: 1.2",
			},
		}

		printTPMInfoDetails(printer, resp)

		result := output.String()
		assert.Contains(t, result, "1.2")
	})
}

// =============================================================================
// printKeyInfoDetails Tests
// =============================================================================

// =============================================================================
// printCertificateDetails Tests
// =============================================================================

// =============================================================================
// printStatusDetails Tests
// =============================================================================
