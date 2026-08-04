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

// Package logging is the platform's structured-logging facade. Logger is a
// thin wrapper around the shared stack logger (quicbaas.ConcreteLogger, the
// qrdb logger re-exported by the quicbaas SDK) that preserves the historical
// platform logging API — error/trace rendering, security log entries, the
// fatal stderr mirror, and nil-receiver safety — while all record emission
// flows through the shared logger. Platform-side slog.Handlers (JSON/text
// with xerrors trace rendering, MultiHandler fan-outs, JSON-lines sinks) are
// injected through the shared logger's handler seam, so the handler owns
// level gating and rendering.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/mdobak/go-xerrors"
)

// Format represents the log output format.
type Format string

const (
	// FormatJSON outputs logs in JSON format (default).
	FormatJSON Format = "json"
	// FormatText outputs logs in text format.
	FormatText Format = "text"
)

// ParseFormat parses a string into a Format, returning FormatJSON for invalid values.
func ParseFormat(s string) Format {
	switch s {
	case "text", "TEXT":
		return FormatText
	case "json", "JSON", "":
		return FormatJSON
	default:
		return FormatJSON
	}
}

// SecurityLogEntry defines the structure of a security log entry.
type SecurityLogEntry struct {
	Timestamp       time.Time `json:"timestamp"`
	Severity        string    `json:"severity"`
	Category        string    `json:"category"`
	Description     string    `json:"description"`
	Details         string    `json:"details,omitempty"`
	Source          string    `json:"source,omitempty"`
	OffenderAddress string    `json:"offender_address,omitempty"`
	OffenderID      string    `json:"offender_id,omitempty"`
}

const (
	// LevelTrace and LevelFatal alias the shared stack logger's custom
	// levels so both sides agree on the numeric values.
	LevelTrace = quicbaas.LogLevelTrace
	LevelFatal = quicbaas.LogLevelFatal

	// LevelSecurity is the platform's security-audit level. It sits above
	// LevelFatal and deliberately avoids slog.Level(16), which the shared
	// stack logger reserves for PANIC (a record at 16 passing through a
	// shared-logger handler would render with level "PANIC").
	LevelSecurity = slog.Level(20)

	SeverityLow      = "Low"
	SeverityMedium   = "Medium"
	SeverityHigh     = "High"
	SeverityCritical = "Critical"

	CategoryAccessControl    = "Access Control"
	CategoryAuthentication   = "Authentication"
	CategoryAuthorization    = "Authorization"
	CategoryDataBreach       = "Data Breach"
	CategoryMalwareDetection = "Malware Detection"
	CategoryNetworkSecurity  = "Network Security"
	CategoryPolicyViolation  = "Policy Violation"
	CategorySystemIntegrity  = "System Integrity"
	CategoryUserBehavior     = "User Behavior"

	SourceAccessControl  = "access_control"
	SourceAuthentication = "authentication"
	SourceDNS            = "dns"
	SourceNetwork        = "network"
	SourceSystem         = "system"
	SourceUserActivity   = "user_activity"
)

// Logger is the platform logging facade over the shared stack logger. The
// zero value is a safe no-op logger; use the New* constructors for a logger
// that emits records.
type Logger struct {
	shared *quicbaas.ConcreteLogger
}

// DefaultLogger creates a logger with debug level and JSON format writing to stderr.
func DefaultLogger() *Logger {
	return NewLoggerWithFormat(slog.LevelDebug, FormatJSON, nil)
}

// NewLogger creates a logger with the specified level and JSON format.
// This is maintained for backward compatibility. Use NewLoggerWithFormat for format control.
func NewLogger(level slog.Level, logWriter io.Writer) *Logger {
	return NewLoggerWithFormat(level, FormatJSON, logWriter)
}

// NewLoggerWithFormat creates a logger with the specified level, format, and writer.
// The format parameter controls whether output is JSON or text.
// If logWriter is nil, os.Stderr is used as the default.
func NewLoggerWithFormat(level slog.Level, format Format, logWriter io.Writer) *Logger {
	// Use os.Stderr as default if no writer provided
	if logWriter == nil {
		logWriter = os.Stderr
	}

	handlerOpts := &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceAttr,
	}

	var handler slog.Handler
	switch format {
	case FormatText:
		handler = slog.NewTextHandler(logWriter, handlerOpts)
	case FormatJSON:
		fallthrough
	default:
		handler = slog.NewJSONHandler(logWriter, handlerOpts)
	}

	return newSharedLogger(handler, levelString(level))
}

// NewFromSlog wraps an existing *slog.Logger in a platform Logger.
// This lets packages that receive a *slog.Logger from callers (e.g. the
// orchestrator) construct a logging.Logger without duplicating handler setup.
// Attributes bound with (*slog.Logger).With are preserved because they live
// in the logger's handler.
func NewFromSlog(l *slog.Logger) *Logger {
	if l == nil {
		return DefaultLogger()
	}
	return newSharedLogger(l.Handler(), "trace")
}

// newSharedLogger wraps a platform-side slog.Handler in the shared stack
// logger via its handler-injection seam. The handler owns level gating and
// rendering; the level string only seeds the shared logger's internal level
// tracking. Construction cannot fail for a non-nil handler and a valid level
// string, so an error here is a programming error and panics.
func newSharedLogger(h slog.Handler, level string) *Logger {
	shared, err := quicbaas.NewLoggerWithHandler(h, quicbaas.LogConfig{Level: level})
	if err != nil {
		panic(err)
	}
	return &Logger{shared: shared}
}

// levelString maps a slog.Level onto the shared logger's level vocabulary.
func levelString(level slog.Level) string {
	switch {
	case level <= LevelTrace:
		return "trace"
	case level <= slog.LevelDebug:
		return "debug"
	case level <= slog.LevelInfo:
		return "info"
	case level <= slog.LevelWarn:
		return "warn"
	case level <= slog.LevelError:
		return "error"
	case level <= LevelFatal:
		return "fatal"
	default:
		return "panic"
	}
}

// Debug logs a debug message with optional structured key-value pairs.
func (l *Logger) Debug(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Debug(message, args...)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Debugf(message, args...)
}

// Info logs an info message with optional structured key-value pairs.
func (l *Logger) Info(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Info(message, args...)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Infof(message, args...)
}

// Warn logs a warning message with optional structured key-value pairs.
func (l *Logger) Warn(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Warn(message, args...)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Warnf(message, args...)
}

// Error logs the error's message with an "error" attribute carrying the
// xerrors-wrapped error rendered as a {msg, trace} group.
func (l *Logger) Error(err error, args ...any) {
	if l == nil || l.shared == nil {
		// Error occurred before the logger was
		// initialized
		slog.Error(err.Error(), args...)
		return
	}
	xerr := xerrors.New(err)
	l.shared.Slog().LogAttrs(
		context.Background(),
		slog.LevelError,
		err.Error(),
		slog.Attr{Key: "error", Value: fmtErr(xerr)},
	)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(message string, args ...any) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Errorf(message, args...)
}

// Fatal logs at Error level and then terminates the process.
//
// The fatal message is mirrored to os.Stderr synchronously before calling
// os.Exit so that operators see WHY the daemon died even when the slog
// handler buffers to a file that never gets flushed. Prior behavior sent
// the message only through slog, which meant calls from background
// goroutines (e.g. webserver.startHTTP's bind failure) produced silent
// exit-255 crashes with zero diagnostic output. The os.Stderr write uses
// a "FATAL:" prefix + newline so it's unmistakable next to slog output.
func (l *Logger) Fatal(message string, args ...any) {
	if l == nil || l.shared == nil {
		fmt.Fprintf(os.Stderr, "FATAL: %s %v\n", message, args)
		os.Exit(-1)
	}
	l.shared.Error(message, args...)
	fmt.Fprintf(os.Stderr, "FATAL: %s %v\n", message, args)
	os.Exit(-1)
}

// Fatalf logs a formatted message at Error level, mirrors it to os.Stderr,
// and terminates the process. See Fatal for the mirror rationale.
func (l *Logger) Fatalf(message string, args ...any) {
	formatted := fmt.Sprintf(message, args...)
	if l == nil || l.shared == nil {
		fmt.Fprintf(os.Stderr, "FATAL: %s\n", formatted)
		os.Exit(-1)
	}
	l.shared.Error(formatted)
	fmt.Fprintf(os.Stderr, "FATAL: %s\n", formatted)
	os.Exit(-1)
}

// FatalError logs the error with trace rendering, mirrors it to os.Stderr,
// and terminates the process. See Fatal for the mirror rationale.
func (l *Logger) FatalError(err error) {
	if l == nil || l.shared == nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(-1)
	}
	l.Error(err)
	fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
	os.Exit(-1)
}

// Slog returns the underlying *slog.Logger for use with external libraries
// that require it directly. It returns nil for a nil or zero-value Logger.
func (l *Logger) Slog() *slog.Logger {
	if l == nil || l.shared == nil {
		return nil
	}
	return l.shared.Slog()
}

// Security logs a security issue with standardized fields to facilitate
// processing security issues by external systems.
func (l *Logger) Security(ctx context.Context, issue SecurityLogEntry) {
	if l == nil || l.shared == nil {
		return
	}
	l.shared.Slog().LogAttrs(
		ctx,
		LevelSecurity,
		"security_log",
		slog.Time("timestamp", issue.Timestamp),
		slog.String("severity", issue.Severity),
		slog.String("category", issue.Category),
		slog.String("description", issue.Description),
		slog.String("details", issue.Details),
		slog.String("source", issue.Source),
		slog.String("offender_address", issue.OffenderAddress),
		slog.String("offender_id", issue.OffenderID),
	)
}
