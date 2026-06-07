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
	"log/slog"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/log/jsonfile"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// installJSONLLogging wires a JSON-lines slog handler into the
// platformd boot flow so /api/v1/platform/logs has data to read.
//
// The handler sits alongside the existing stderr/file logger as a
// MultiHandler child — nothing about the legacy logging story
// changes. Every record continues to land in trusted-data/log/<name>.log;
// a structured JSON-lines copy additionally lands in
// trusted-data/log/jsonl/platformd.jsonl with 64 MiB size rotation
// and a 14-day retention cap.
//
// Returns a Querier suitable for handing to the platform REST router
// via registry params. On failure (LogDir unwritable, etc.) the
// caller is logged and the function returns nil — the daemon
// continues without the WebUI Logs surface, which is preferable to
// taking the whole daemon down because logs couldn't be tee'd.
func installJSONLLogging(logger *logging.Logger) *jsonfile.Querier {
	if App == nil {
		return nil
	}
	dir := filepath.Join(App.LogDir, "jsonl")
	level := slog.LevelInfo
	if App.DebugFlag {
		level = slog.LevelDebug
	}
	h, err := jsonfile.NewHandler(jsonfile.Options{
		Dir:              dir,
		Service:          "platformd",
		Level:            level,
		MaxSize:          64 * 1024 * 1024, // 64 MiB
		MaxFiles:         16,
		MaxAge:           14 * 24 * time.Hour,
		SubscriberBuffer: 256,
	})
	if err != nil {
		logger.Warnf("jsonl log sink unavailable: %v", err)
		return nil
	}

	// Compose with the existing handler so the platformd.log file and
	// stderr stream continue to receive every record.
	existing := App.Logger.Slog().Handler()
	multi := logging.NewMultiHandler(existing, h)

	App.Logger = logging.WrapHandler(multi)
	slog.SetDefault(slog.New(multi))

	logger.Info("structured JSON-lines log sink installed", "dir", dir)
	return jsonfile.NewQuerier(h)
}
