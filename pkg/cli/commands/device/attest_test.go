// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

const testEvidence = `{"quote":"AQID","signature":"BAUG","nonce":"BwgJ","pcrs":{"0":"AAAA"}}`

func writeEvidenceFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "quote.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestRunAttest(t *testing.T) {
	srv, flags := startProfileServer(t)
	path := writeEvidenceFile(t, testEvidence)

	for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
		require.NoError(t, runAttest(flags(format), "42", path), "a negative verdict is not an error")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, "42", srv.lastAttest.GetDeviceId())
	assert.Equal(t, testEvidence, string(srv.lastAttest.GetEvidence()), "the file's bytes are the evidence")
}

func TestRunAttest_Errors(t *testing.T) {
	srv, flags := startProfileServer(t)
	f := flags(cli.OutputFormatJSON)
	path := writeEvidenceFile(t, testEvidence)

	t.Run("InvalidID", func(t *testing.T) {
		for _, id := range []string{"0", "abc", "-1"} {
			assert.Equal(t, ErrInvalidDeviceID{ID: id}, runAttest(&cli.CommonFlags{}, id, path))
		}
	})

	t.Run("EvidenceRequired", func(t *testing.T) {
		assert.Equal(t, ErrAttestEvidenceRequired{}, runAttest(&cli.CommonFlags{}, "42", ""))
	})

	t.Run("EvidenceUnreadable", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.json")
		err := runAttest(&cli.CommonFlags{}, "42", missing)
		var readErr ErrAttestEvidenceReadFailed
		require.True(t, errors.As(err, &readErr), "err = %v", err)
		assert.Equal(t, missing, readErr.Path)
		assert.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("EvidenceEmpty", func(t *testing.T) {
		empty := writeEvidenceFile(t, "")
		assert.Equal(t, ErrAttestEvidenceEmpty{Path: empty}, runAttest(&cli.CommonFlags{}, "42", empty))
	})

	t.Run("UnknownDevice", func(t *testing.T) {
		err := runAttest(f, "4242", path)
		assert.Equal(t, ErrDeviceNotFound{ID: 4242}, err)
	})

	t.Run("ServerFailure", func(t *testing.T) {
		srv.mu.Lock()
		srv.fail = status.Error(codes.Unavailable, "verifier not configured")
		srv.mu.Unlock()
		err := runAttest(f, "42", path)
		var attestErr ErrAttestFailed
		require.True(t, errors.As(err, &attestErr), "err = %v", err)
		assert.Equal(t, uint64(42), attestErr.ID)
		assert.Contains(t, err.Error(), "verifier not configured", "the server's reason is shown")
		assert.NotErrorIs(t, err, common.ErrNotFound)
	})
}

func TestAttestCommand_Flags(t *testing.T) {
	cmd := newAttestCommand(nil)
	assert.Equal(t, "attest <id>", cmd.Use)
	assert.NotNil(t, cmd.Flags().Lookup("evidence-file"))
	assert.Error(t, cmd.Args(cmd, nil), "the device id is required")
}
