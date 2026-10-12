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
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// The operations below are the ones `kms crypto verify` and
// `kms crypto hmac verify` pass to printVerifyResult.
var verifyOperations = []string{"Signature", "HMAC"}

func TestPrintVerifyResult_ValidReturnsNil(t *testing.T) {
	for _, operation := range verifyOperations {
		for _, format := range []cli.OutputFormat{cli.OutputFormatJSON, cli.OutputFormatTable} {
			t.Run(operation+"/"+string(format), func(t *testing.T) {
				output := &bytes.Buffer{}
				printer := cli.NewPrinterWithWriter(format, true, output)

				err := printVerifyResult(printer, format, operation, verifyResult{KeyID: "k1", KeyVersion: 2, Valid: true})
				require.NoError(t, err)
				assert.NotEmpty(t, output.String())
			})
		}
	}
}

func TestPrintVerifyResult_InvalidReturnsVerificationFailed(t *testing.T) {
	for _, operation := range verifyOperations {
		for _, format := range []cli.OutputFormat{cli.OutputFormatJSON, cli.OutputFormatTable} {
			t.Run(operation+"/"+string(format), func(t *testing.T) {
				output := &bytes.Buffer{}
				printer := cli.NewPrinterWithWriter(format, true, output)

				err := printVerifyResult(printer, format, operation, verifyResult{KeyID: "k1", KeyVersion: 2, Valid: false})

				var failed ErrVerificationFailed
				require.True(t, errors.As(err, &failed), "expected ErrVerificationFailed, got %v", err)
				assert.Equal(t, ErrVerificationFailed{Operation: operation, KeyID: "k1", KeyVersion: 2}, failed)
				assert.Contains(t, err.Error(), operation+" verification failed")
			})
		}
	}
}

// A failed check still prints its verdict before returning the error, so a
// script reading JSON sees valid=false as well as the non-zero exit.
func TestPrintVerifyResult_InvalidStillPrintsVerdict(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, output)

	err := printVerifyResult(printer, cli.OutputFormatJSON, "Signature", verifyResult{KeyID: "k1", Valid: false})
	require.Error(t, err)

	var printed verifyResult
	require.NoError(t, json.Unmarshal(output.Bytes(), &printed))
	assert.Equal(t, "k1", printed.KeyID)
	assert.False(t, printed.Valid)
}

func TestPrintVerifyResult_InvalidOutputFormat(t *testing.T) {
	output := &bytes.Buffer{}
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, output)

	err := printVerifyResult(printer, cli.OutputFormat("xml"), "HMAC", verifyResult{Valid: true})

	var invalid cli.ErrInvalidOutputFormat
	require.True(t, errors.As(err, &invalid), "expected ErrInvalidOutputFormat, got %v", err)
}
