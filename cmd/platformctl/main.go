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

// Package main implements platformctl, the Trusted Platform CLI and
// desktop application for managing the platform daemon (platformd)
// via REST, gRPC, QUIC, MCP, and Unix socket transports.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands"
)

// version, gitCommit, and buildDate are set at build time via ldflags:
//
//	go build -ldflags "-X main.version=... -X main.gitCommit=... -X main.buildDate=..."
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

// logLevelMap provides O(1) lookup for parsing log level strings.
var logLevelMap = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// parseLogArgs extracts --log-level from os.Args before Cobra processes them.
// This allows the logger to be initialized prior to the GUI/CLI branch point.
func parseLogArgs() string {
	level := "info"
	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--log-level" && i+1 < len(os.Args):
			level = os.Args[i+1]
			i++
		case len(os.Args[i]) > len("--log-level=") && os.Args[i][:len("--log-level=")] == "--log-level=":
			level = os.Args[i][len("--log-level="):]
		}
	}
	return level
}

// isGUIOnly returns true when the only arguments are log flags,
// meaning the user intends to launch the GUI rather than execute
// a CLI subcommand.
func isGUIOnly() bool {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case arg == "--log-level":
			i++ // skip the value
			continue
		case len(arg) > len("--log-level=") && arg[:len("--log-level=")] == "--log-level=":
			continue
		default:
			return false
		}
	}
	return true
}

func main() {
	// Parse log flags from os.Args before Cobra to initialize logging
	// early, including for the GUI path which bypasses Cobra entirely.
	level := parseLogArgs()

	slogLevel, ok := logLevelMap[level]
	if !ok {
		slogLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	}))

	// When invoked with no subcommands (only log flags allowed) and a
	// graphical display is available, attempt to launch the GUI. If the
	// binary was built without the desktop tag, launchGUI returns
	// GUIUnavailableError and we fall through to the CLI.
	if isGUIOnly() && hasDisplay() {
		if err := launchGUI(logger); err != nil {
			var unavail *GUIUnavailableError
			if !errors.As(err, &unavail) {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			// GUI unavailable - fall through to CLI.
		} else {
			return
		}
	}

	// CLI mode
	if err := commands.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
