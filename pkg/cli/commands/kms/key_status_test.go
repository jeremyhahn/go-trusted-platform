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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// keyStatusFake is a KMS that answers UpdateKeyStatus by echoing the request,
// or with err, and records the request.
type keyStatusFake struct {
	err     error
	keyID   string
	version uint64
	status  platformv1.KeyStatus
}

func (f *keyStatusFake) UpdateKeyStatus(_ context.Context, keyID string, version uint64, status platformv1.KeyStatus) (*platformv1.UpdateKeyStatusResponse, error) {
	f.keyID, f.version, f.status = keyID, version, status
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.UpdateKeyStatusResponse{KeyId: keyID, Version: version, KeyStatus: status, Timestamp: 1700000000}, nil
}

func TestUpdateKeyStatus_PrintsTheDocumentedJSON(t *testing.T) {
	fake := &keyStatusFake{}

	out, err := updateKeyStatus(context.Background(), fake, "tenant-a-kek", 2, platformv1.KeyStatus_KEY_STATUS_DISABLED)
	require.NoError(t, err)
	assert.Equal(t, "tenant-a-kek", fake.keyID)
	assert.Equal(t, uint64(2), fake.version)
	assert.Equal(t, platformv1.KeyStatus_KEY_STATUS_DISABLED, fake.status)

	var buf bytes.Buffer
	require.NoError(t, printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf), cli.OutputFormatJSON, out))

	var printed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &printed))
	assert.Equal(t, map[string]any{
		"key_id":     "tenant-a-kek",
		"version":    float64(2),
		"status":     "KEY_STATUS_DISABLED",
		"updated_at": float64(1700000000),
	}, printed)
}

func TestKeyStatusVerbs_SendTheirStatus(t *testing.T) {
	cmd := newKeyStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })

	verbs := map[string]bool{}
	for _, sub := range cmd.Commands() {
		verbs[sub.Name()] = true
		assert.NotNil(t, sub.Flags().Lookup("version"), "%s has no --version", sub.Name())
		assert.NotContains(t, sub.Short, "not yet implemented")
	}
	assert.Equal(t, map[string]bool{"enable": true, "disable": true}, verbs)
}

func TestPrintKeyStatus_Table(t *testing.T) {
	var buf bytes.Buffer
	out := &keyStatusOutput{KeyID: "tenant-a-kek", Version: 1, Status: "KEY_STATUS_ENABLED", UpdatedAt: 1700000000}

	require.NoError(t, printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), cli.OutputFormatTable, out))
	assert.Contains(t, buf.String(), "KEY_STATUS_ENABLED")
}

func TestUpdateKeyStatus_Errors(t *testing.T) {
	cause := errors.New("key not found")
	_, err := updateKeyStatus(context.Background(), &keyStatusFake{err: cause}, "missing", 0, platformv1.KeyStatus_KEY_STATUS_ENABLED)

	var statusErr ErrUpdateKeyStatusFailed
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, "missing", statusErr.KeyID)
	assert.ErrorIs(t, err, cause)

	err = printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{}), cli.OutputFormat("xml"), &keyStatusOutput{})
	var formatErr cli.ErrInvalidOutputFormat
	require.ErrorAs(t, err, &formatErr)

	cmd := newKeyStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{"enable"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	assert.ErrorContains(t, cmd.Execute(), "accepts 1 arg(s)")
}
