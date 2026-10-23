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

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
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
// Returns the logger every component built afterwards must use, and a
// Querier suitable for handing to the platform REST router via registry
// params. The tee is a NEW logger: a component still holding the one
// passed in logs around the sink, and its records — the admin claim's
// re-claim security event among them — never reach the console Logs
// page. On failure (LogDir unwritable, etc.) the failure is logged and
// the given logger comes back with a nil Querier — the daemon continues
// without the WebUI Logs surface, which is preferable to taking the
// whole daemon down because logs couldn't be tee'd.
func installJSONLLogging(a *app.App, logger *logging.Logger) (*logging.Logger, *jsonfile.Querier) {
	if a == nil {
		return logger, nil
	}
	dir := filepath.Join(a.LogDir, "jsonl")
	level := slog.LevelInfo
	if a.DebugFlag {
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
		return logger, nil
	}

	// Compose with the existing handler so the platformd.log file and
	// stderr stream continue to receive every record.
	multi := logging.NewMultiHandler(logger.Slog().Handler(), h)

	teed := logging.WrapHandler(multi)
	a.Logger = teed
	slog.SetDefault(slog.New(multi))

	teed.Info("structured JSON-lines log sink installed", "dir", dir)
	return teed, jsonfile.NewQuerier(h)
}
