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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// keyVersionsFake is a KMS that answers GetKeyVersions with resp or err and
// records the request.
type keyVersionsFake struct {
	resp   *platformv1.GetKeyVersionsResponse
	err    error
	keyID  string
	limit  int32
	cursor string
}

func (f *keyVersionsFake) GetKeyVersions(_ context.Context, keyID string, limit int32, cursor string) (*platformv1.GetKeyVersionsResponse, error) {
	f.keyID, f.limit, f.cursor = keyID, limit, cursor
	return f.resp, f.err
}

func TestListKeyVersions_PrintsTheDocumentedJSON(t *testing.T) {
	fake := &keyVersionsFake{resp: &platformv1.GetKeyVersionsResponse{
		KeyId: "tenant-a-kek",
		Versions: []*platformv1.KMSKeyVersionInfo{
			{Version: 1, Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, Status: platformv1.KeyStatus_KEY_STATUS_DISABLED, CreatedAt: 1700000000, DisabledAt: 1700000100},
			{Version: 2, Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, Status: platformv1.KeyStatus_KEY_STATUS_ENABLED, CreatedAt: 1700000050},
		},
		HasMore:    true,
		NextCursor: "page-2",
	}}

	out, err := listKeyVersions(context.Background(), fake, "tenant-a-kek", 2, "page-1")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a-kek", fake.keyID)
	assert.Equal(t, int32(2), fake.limit)
	assert.Equal(t, "page-1", fake.cursor)

	var buf bytes.Buffer
	require.NoError(t, printKeyVersions(cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &buf), cli.OutputFormatJSON, out))

	var printed map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &printed))
	assert.Equal(t, "tenant-a-kek", printed["key_id"])
	assert.Equal(t, true, printed["has_more"])
	assert.Equal(t, "page-2", printed["next_cursor"])
	versions := printed["versions"].([]any)
	require.Len(t, versions, 2)
	first := versions[0].(map[string]any)
	assert.Equal(t, float64(1), first["version"])
	assert.Equal(t, "KMS_KEY_ALGORITHM_AES_256", first["algorithm"])
	assert.Equal(t, "KEY_STATUS_DISABLED", first["status"])
	assert.Equal(t, float64(1700000000), first["created_at"])
	assert.Equal(t, float64(1700000100), first["disabled_at"])
}

func TestPrintKeyVersions_Table(t *testing.T) {
	out := &keyVersionsOutput{
		KeyID:      "tenant-a-kek",
		Versions:   []keyVersionOutput{{Version: 3, Algorithm: "KMS_KEY_ALGORITHM_AES_256", Status: "KEY_STATUS_ENABLED", CreatedAt: 1700000000}},
		HasMore:    true,
		NextCursor: "page-2",
	}

	var buf bytes.Buffer
	require.NoError(t, printKeyVersions(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf), cli.OutputFormatTable, out))
	assert.Contains(t, buf.String(), "KEY_STATUS_ENABLED")
	assert.Contains(t, buf.String(), "page-2")
}

func TestListKeyVersions_Errors(t *testing.T) {
	cause := errors.New("key not found")
	_, err := listKeyVersions(context.Background(), &keyVersionsFake{err: cause}, "missing", 50, "")

	var listErr ErrListKeyVersionsFailed
	require.ErrorAs(t, err, &listErr)
	assert.Equal(t, "missing", listErr.KeyID)
	assert.ErrorIs(t, err, cause)

	err = printKeyVersions(cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{}), cli.OutputFormat("xml"), &keyVersionsOutput{})
	var formatErr cli.ErrInvalidOutputFormat
	require.ErrorAs(t, err, &formatErr)
}

func TestNewKeyVersionsCommand_Structure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyVersionsCommand(getFlags)

	if cmd.Use != "versions <key-id>" {
		t.Errorf("unexpected Use: %q", cmd.Use)
	}

	if cmd.Short != "List all versions of a key" {
		t.Errorf("unexpected Short: %q", cmd.Short)
	}

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.Args == nil {
		t.Error("Args should be set")
	}

	if cmd.RunE == nil {
		t.Error("RunE should be set")
	}
}

func TestNewKeyVersionsCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyVersionsCommand(getFlags)

	tests := []struct {
		flagName     string
		shorthand    string
		defaultValue string
	}{
		{"limit", "l", "50"},
		{"cursor", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.flagName, func(t *testing.T) {
			flag := cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("flag %q not found", tt.flagName)
				return
			}
			if flag.Shorthand != tt.shorthand {
				t.Errorf("flag %q shorthand: got %q, want %q", tt.flagName, flag.Shorthand, tt.shorthand)
			}
			if flag.DefValue != tt.defaultValue {
				t.Errorf("flag %q default: got %q, want %q", tt.flagName, flag.DefValue, tt.defaultValue)
			}
		})
	}
}

func TestErrListKeyVersionsFailed_Error(t *testing.T) {
	err := ErrListKeyVersionsFailed{KeyID: "my-key", Err: ErrInvalidKeyAlgorithm{Algorithm: "test"}}
	errStr := err.Error()

	if !strings.Contains(errStr, "failed to list versions") {
		t.Errorf("error message %q should contain 'failed to list versions'", errStr)
	}
	if !strings.Contains(errStr, "my-key") {
		t.Errorf("error message %q should contain 'my-key'", errStr)
	}
}

func TestKeyVersionsCommand_LongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newKeyVersionsCommand(getFlags)

	// Should mention versions
	if !strings.Contains(cmd.Long, "version") {
		t.Error("Long description should mention versions")
	}

	// Should mention rotation
	if !strings.Contains(cmd.Long, "rotation") {
		t.Error("Long description should mention rotation")
	}

	// Should contain examples
	if !strings.Contains(cmd.Long, "Examples:") {
		t.Error("Long description should contain examples")
	}

	// Should mention pagination
	if !strings.Contains(cmd.Long, "limit") {
		t.Error("Long description should mention pagination limit")
	}
}

func TestKeyVersionsCommand_InParentCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	parentCmd := NewKeyCommand(getFlags)

	var found bool
	for _, subcmd := range parentCmd.Commands() {
		if subcmd.Name() == "versions" {
			found = true
			break
		}
	}

	if !found {
		t.Error("versions subcommand not found in key command")
	}
}
