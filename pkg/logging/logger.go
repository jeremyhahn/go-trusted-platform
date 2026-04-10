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

package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

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
	LevelTrace    = slog.Level(-8)
	LevelFatal    = slog.Level(12)
	LevelSecurity = slog.Level(16)

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

type Logger struct {
	logger *slog.Logger
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

	return &Logger{
		logger: slog.New(handler),
	}
}

// Debug
func (l *Logger) Debug(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Debug(message, args...)
}

func (l *Logger) Debugf(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Debug(fmt.Sprintf(message, args...))
}

// Info
func (l *Logger) Info(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Info(message, args...)
}

func (l *Logger) Infof(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Info(fmt.Sprintf(message, args...))
}

// Warn
func (l *Logger) Warn(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Warn(message, args...)
}

func (l *Logger) Warnf(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Warn(fmt.Sprintf(message, args...))
}

// Error
func (l *Logger) Error(err error, args ...any) {
	if l == nil || l.logger == nil {
		// Error occurred before the logger was
		// initialized
		slog.Error(err.Error(), args...)
		return
	}
	xerr := xerrors.New(err)
	l.logger.Error(err.Error(), slog.Any("error", xerr))
}

func (l *Logger) Errorf(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Error(fmt.Sprintf(message, args...))
}

// Fatal
func (l *Logger) Fatal(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.Error(message, args...)
	os.Exit(-1)
}

func (l *Logger) Fatalf(message string, args ...any) {
	if l == nil || l.logger == nil {
		return
	}
	l.Fatal(fmt.Sprintf(message, args...))
}

func (l *Logger) FatalError(err error) {
	if l == nil || l.logger == nil {
		return
	}
	l.Error(err)
	os.Exit(-1)
}

// Slog returns the underlying *slog.Logger for use with
// external libraries that require it directly.
func (l *Logger) Slog() *slog.Logger {
	return l.logger
}

// Security logs a security issue with standardized fields to facilitate
// processing security issues by external systems.
func (l *Logger) Security(ctx context.Context, issue SecurityLogEntry) {
	if l == nil || l.logger == nil {
		return
	}
	l.logger.LogAttrs(
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

// LoggerWriter wraps a Logger to implement io.Writer interface.
// This allows the Logger to be used by external libraries that
// expect an io.Writer for logging output.
type LoggerWriter struct {
	logger *Logger
}

// NewLoggerWriter creates an io.Writer that logs to the provided Logger.
// Each Write call logs a single message at Info level.
func NewLoggerWriter(logger *Logger) io.Writer {
	return &LoggerWriter{logger: logger}
}

// Write implements io.Writer interface.
// It logs the data as an Info message, trimming any trailing newline.
func (w *LoggerWriter) Write(p []byte) (n int, err error) {
	// Trim trailing newline if present
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	if len(msg) > 0 {
		w.logger.Info(msg)
	}
	return len(p), nil
}
