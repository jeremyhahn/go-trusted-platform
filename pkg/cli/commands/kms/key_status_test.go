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
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// The verbs go through the quicbaas KMS client, the client `key metadata`,
// `key policy` and `key revoke` use (docs/kms/cli.md §3): platformd's
// UpdateKeyStatus RPC reaches the embedded quicbaas.KMS/UpdateKeyStatus
// handler with a request type it refuses.
var _ keyStatusClient = quicbaassdk.KMSClient(nil)

// keyStatusFake is a KMS that answers UpdateKeyStatus by echoing the request,
// or with err, and records the request.
type keyStatusFake struct {
	err error
	req *kms.UpdateKeyStatusRequest
}

func (f *keyStatusFake) UpdateKeyStatus(_ context.Context, req *kms.UpdateKeyStatusRequest) (*kms.UpdateKeyStatusResponse, error) {
	f.req = req
	if f.err != nil {
		return nil, f.err
	}
	return &kms.UpdateKeyStatusResponse{KeyID: req.KeyID, Version: req.Version, Status: req.Status}, nil
}

func TestUpdateKeyStatus_PrintsTheDocumentedJSON(t *testing.T) {
	fake := &keyStatusFake{}

	out, err := updateKeyStatus(context.Background(), fake, "tenant-a-kek", 2, kms.KeyStatusDisabled)
	require.NoError(t, err)
	require.NotNil(t, fake.req)
	assert.Equal(t, &kms.UpdateKeyStatusRequest{KeyID: "tenant-a-kek", Version: 2, Status: kms.KeyStatusDisabled}, fake.req)

	var buf bytes.Buffer
	require.NoError(t, printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf), cli.OutputFormatJSON, out))

	var printed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &printed))
	assert.Equal(t, map[string]any{
		"key_id":  "tenant-a-kek",
		"version": float64(2),
		"status":  "DISABLED",
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
	out := &keyStatusOutput{KeyID: "tenant-a-kek", Version: 1, Status: "ENABLED"}

	require.NoError(t, printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), cli.OutputFormatTable, out))
	assert.Contains(t, buf.String(), "Key tenant-a-kek is now ENABLED")
}

func TestUpdateKeyStatus_Errors(t *testing.T) {
	cause := errors.New("key not found")
	_, err := updateKeyStatus(context.Background(), &keyStatusFake{err: cause}, "missing", 0, kms.KeyStatusEnabled)

	var statusErr ErrUpdateKeyStatusFailed
	require.ErrorAs(t, err, &statusErr)
	assert.Equal(t, "missing", statusErr.KeyID)
	assert.ErrorIs(t, err, cause)

	unsent := &keyStatusFake{}
	_, err = updateKeyStatus(context.Background(), unsent, "k1", math.MaxUint64, kms.KeyStatusEnabled)
	var rangeErr ErrKeyVersionOutOfRange
	require.ErrorAs(t, err, &rangeErr)
	assert.Equal(t, uint64(math.MaxUint64), rangeErr.Version)
	assert.Nil(t, unsent.req, "an out-of-range version is never sent")

	err = printKeyStatus(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{}), cli.OutputFormat("xml"), &keyStatusOutput{})
	var formatErr cli.ErrInvalidOutputFormat
	require.ErrorAs(t, err, &formatErr)

	cmd := newKeyStatusCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{"enable"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	assert.ErrorContains(t, cmd.Execute(), "accepts 1 arg(s)")
}
