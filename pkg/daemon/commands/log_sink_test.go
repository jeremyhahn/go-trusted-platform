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

package commands

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// keepDefaultSlog restores the process-wide slog default the sink replaces.
func keepDefaultSlog(t *testing.T) {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
}

// TestInstallJSONLLogging_ReturnsTheTeedLogger proves the seam #169's
// console surfacing depends on: a record written through the RETURNED
// logger is queryable from the console's log store. serve.go used to keep
// the logger it passed in, so every webservice record — the admin claim's
// re-claim security event among them — bypassed the sink.
func TestInstallJSONLLogging_ReturnsTheTeedLogger(t *testing.T) {
	keepDefaultSlog(t)
	a := &app.App{LogDir: t.TempDir()}
	base := logging.NewLogger(slog.LevelInfo, io.Discard)

	teed, querier := installJSONLLogging(a, base)
	require.NotNil(t, querier)
	require.NotSame(t, base, teed)
	assert.Same(t, teed, a.Logger)

	teed.Security(context.Background(), logging.SecurityLogEntry{
		Timestamp: time.Now(),
		Severity:  logging.SeverityHigh,
		Category:  logging.CategoryAccessControl,
		Source:    logging.SourceAuthentication,
	})
	base.Info("written around the sink")

	got, err := querier.Query(jsonfile.Filter{})
	require.NoError(t, err)
	var messages []string
	for _, e := range got.Entries {
		messages = append(messages, e.Msg)
	}
	assert.Contains(t, messages, "security_log")
	assert.NotContains(t, messages, "written around the sink",
		"only the returned logger reaches the store")

	got, err = querier.Query(jsonfile.Filter{MinLevel: "SECURITY"})
	require.NoError(t, err)
	require.Len(t, got.Entries, 1)
	assert.Equal(t, "SECURITY", got.Entries[0].Level)
}

func TestInstallJSONLLogging_KeepsTheLoggerWhenTheSinkFails(t *testing.T) {
	keepDefaultSlog(t)
	// A regular file where the log directory should be: the sink cannot
	// create <LogDir>/jsonl.
	notADir := filepath.Join(t.TempDir(), "log")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	a := &app.App{LogDir: notADir}
	base := logging.NewLogger(slog.LevelInfo, io.Discard)

	teed, querier := installJSONLLogging(a, base)
	assert.Nil(t, querier)
	assert.Same(t, base, teed)
	assert.Nil(t, a.Logger, "a failed sink leaves the app untouched")
}

func TestInstallJSONLLogging_NoApp(t *testing.T) {
	base := logging.NewLogger(slog.LevelInfo, io.Discard)
	teed, querier := installJSONLLogging(nil, base)
	assert.Nil(t, querier)
	assert.Same(t, base, teed)
}
