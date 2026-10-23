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

package device

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// TestAttestCertRecordCommand_FlagsDefaultOff pins #516's contract that the
// clear is never on by default: an operator has to ask for it.
func TestAttestCertRecordCommand_FlagsDefaultOff(t *testing.T) {
	cmd := newAttestCertRecordCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	for _, name := range []string{"reissue", "clear-on-refusal"} {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "--%s is registered", name)
		assert.Equal(t, "false", flag.DefValue, "--%s defaults to off", name)
	}
}

func TestRunAttestCertRecord_RejectsAnInvalidID(t *testing.T) {
	for _, id := range []string{"0", "abc", "-1"} {
		err := runAttestCertRecord(&cli.CommonFlags{}, id, device.RecordAttestCertOptions{ClearOnRefusal: true})
		var invalid ErrInvalidDeviceID
		require.True(t, errors.As(err, &invalid), "id %q: err = %v, want ErrInvalidDeviceID", id, err)
		assert.Equal(t, id, invalid.ID)
	}
}

func TestPrintAttestCertRecord_ReportsTheClear(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	printAttestCertRecord(printer, attestCertRecordOutput{
		ID: 9, Serial: "SN9", Model: "M", Changed: true,
		Subject: "CN=old-ak", CertificateSerial: "77",
		Cleared: true, Refusal: "certificate lacks tcg-cap-verifiedTPMRestricted",
	})

	out := buf.String()
	assert.Contains(t, out, "Refused attestation certificate cleared")
	assert.Contains(t, out, "certificate lacks tcg-cap-verifiedTPMRestricted", "the refusal that caused the clear is shown")
	assert.Contains(t, out, "CN=old-ak", "the cleared certificate is named")
	assert.NotContains(t, out, "Attestation certificate recorded", "a clear is never reported as a record")
}

func TestPrintAttestCertRecord_RecordIsNotAClear(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	printAttestCertRecord(printer, attestCertRecordOutput{
		ID: 9, Serial: "SN9", Model: "M", Changed: true, Source: "stored", Subject: "CN=ak",
	})

	out := buf.String()
	assert.Contains(t, out, "Attestation certificate recorded")
	assert.NotContains(t, out, "cleared")
	assert.NotContains(t, out, "Refusal")
}
