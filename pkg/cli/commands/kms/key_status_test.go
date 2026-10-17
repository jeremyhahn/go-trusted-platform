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
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestKeyStatusFromFlags(t *testing.T) {
	t.Run("EnableSelectsEnabled", func(t *testing.T) {
		status, err := keyStatusFromFlags(true, false, 0)
		require.NoError(t, err)
		assert.Equal(t, kms.KeyStatusEnabled, status)
	})

	t.Run("DisableSelectsDisabled", func(t *testing.T) {
		status, err := keyStatusFromFlags(false, true, 2)
		require.NoError(t, err)
		assert.Equal(t, kms.KeyStatusDisabled, status)
	})

	t.Run("NeitherFlagIsRejected", func(t *testing.T) {
		_, err := keyStatusFromFlags(false, false, 0)
		assert.ErrorIs(t, err, ErrKeyStatusFlagRequired{})
	})

	t.Run("BothFlagsAreRejected", func(t *testing.T) {
		_, err := keyStatusFromFlags(true, true, 0)
		assert.ErrorIs(t, err, ErrKeyStatusFlagRequired{})
	})

	t.Run("NegativeVersionIsRejected", func(t *testing.T) {
		_, err := keyStatusFromFlags(false, true, -1)
		assert.ErrorIs(t, err, ErrInvalidKeyStatusVersion{Version: -1})
	})
}

func TestKeyStatusCommand_RejectsBadFlagsBeforeConnecting(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want error
	}{
		{"NoFlag", []string{"my-key"}, ErrKeyStatusFlagRequired{}},
		{"BothFlags", []string{"my-key", "--enable", "--disable"}, ErrKeyStatusFlagRequired{}},
		{"NegativeVersion", []string{"my-key", "--disable", "--version", "-2"}, ErrInvalidKeyStatusVersion{Version: -2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newKeyStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
			cmd.SetArgs(tc.args)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			assert.ErrorIs(t, cmd.Execute(), tc.want)
		})
	}
}

func TestExecuteKeyStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("PrintsTheStatusTheKMSReports", func(t *testing.T) {
		var got *kms.UpdateKeyStatusRequest
		client := &fakeKMSClient{
			updateKeyStatusFn: func(ctx context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
				got = req
				return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
			},
		}
		var out bytes.Buffer
		printer := cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out)

		err := executeKeyStatus(ctx, client, printer, "key-1", 3, kms.KeyStatusDisabled)
		require.NoError(t, err)

		require.NotNil(t, got)
		assert.Equal(t, "key-1", got.KeyID)
		assert.Equal(t, 3, got.Version)
		assert.Equal(t, kms.KeyStatusDisabled, got.Status)

		var printed keyStatusOutput
		require.NoError(t, json.Unmarshal(out.Bytes(), &printed))
		assert.Equal(t, keyStatusOutput{KeyID: "key-1", Version: 3, Status: "DISABLED"}, printed)
	})

	t.Run("BackendErrorIsWrapped", func(t *testing.T) {
		err := executeKeyStatus(ctx, &fakeKMSClient{}, newTestKMSPrinter(), "key-1", 0, kms.KeyStatusEnabled)
		var statusErr ErrUpdateKeyStatusFailed
		require.ErrorAs(t, err, &statusErr)
		assert.Equal(t, "key-1", statusErr.KeyID)
		assert.ErrorIs(t, err, errCLIKMSMock)
	})
}
