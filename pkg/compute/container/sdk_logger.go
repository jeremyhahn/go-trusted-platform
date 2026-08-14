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

package container

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// sdkLogger adapts the platform's *slog.Logger to the structured logger the
// go-quicbaas SDK container runtime constructors require.
//
// It is a pure adapter: every method forwards to slog. The printf-style
// variants the SDK interface declares are rendered with fmt.Sprintf and
// logged as the message, which is what slog does with a preformatted string.
type sdkLogger struct {
	log *slog.Logger
}

// Compile-time proof that the adapter satisfies the SDK logger seam.
var _ orchestration.Logger = (*sdkLogger)(nil)

// newSDKLogger wraps a slog logger for the go-quicbaas SDK. A nil logger
// resolves to slog.Default so the SDK constructors, which reject a nil
// logger, always receive a usable one.
func newSDKLogger(log *slog.Logger) *sdkLogger {
	if log == nil {
		log = slog.Default()
	}
	return &sdkLogger{log: log}
}

// Debug logs a debug-level message with structured key-value pairs.
func (l *sdkLogger) Debug(msg string, args ...any) { l.log.Debug(msg, args...) }

// Debugf logs a formatted debug-level message.
func (l *sdkLogger) Debugf(format string, args ...interface{}) {
	l.log.Debug(fmt.Sprintf(format, args...))
}

// Info logs an info-level message with structured key-value pairs.
func (l *sdkLogger) Info(msg string, args ...any) { l.log.Info(msg, args...) }

// Infof logs a formatted info-level message.
func (l *sdkLogger) Infof(format string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(format, args...))
}

// Warn logs a warning-level message with structured key-value pairs.
func (l *sdkLogger) Warn(msg string, args ...any) { l.log.Warn(msg, args...) }

// Warnf logs a formatted warning-level message.
func (l *sdkLogger) Warnf(format string, args ...interface{}) {
	l.log.Warn(fmt.Sprintf(format, args...))
}

// Error logs an error-level message with structured key-value pairs.
func (l *sdkLogger) Error(msg string, args ...any) { l.log.Error(msg, args...) }

// Errorf logs a formatted error-level message.
func (l *sdkLogger) Errorf(format string, args ...interface{}) {
	l.log.Error(fmt.Sprintf(format, args...))
}

// Fatal logs a fatal-level message and exits, as the SDK interface requires.
func (l *sdkLogger) Fatal(msg string) {
	l.log.Error(msg)
	os.Exit(1)
}

// Fatalf logs a formatted fatal-level message and exits.
func (l *sdkLogger) Fatalf(format string, args ...interface{}) {
	l.Fatal(fmt.Sprintf(format, args...))
}

// WithField returns a logger carrying one additional field.
func (l *sdkLogger) WithField(key string, value interface{}) orchestration.Logger {
	return &sdkLogger{log: l.log.With(key, value)}
}

// WithFields returns a logger carrying additional fields.
func (l *sdkLogger) WithFields(fields map[string]interface{}) orchestration.Logger {
	args := make([]any, 0, len(fields)*2)
	for key, value := range fields {
		args = append(args, key, value)
	}
	return &sdkLogger{log: l.log.With(args...)}
}

// WithError returns a logger carrying an error field.
func (l *sdkLogger) WithError(err error) orchestration.Logger {
	return &sdkLogger{log: l.log.With("error", err)}
}
