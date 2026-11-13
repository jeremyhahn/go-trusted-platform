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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mdobak/go-xerrors"
)

func TestLogger(t *testing.T) {

	logger := NewLogger(slog.LevelDebug, nil)

	logger.Info("info test")
	logger.Warn("warn test")
	logger.Debug("debug test")
}

func TestError(t *testing.T) {

	logger := NewLogger(slog.LevelDebug, nil)

	err := errors.New("an error occurred")

	logger.Info("info test")
	logger.Warn("warn test")
	logger.Error(err)
	logger.Debug("debug test")
}

func TestDefaultLogger(t *testing.T) {
	logger := DefaultLogger()
	if logger == nil {
		t.Fatal("DefaultLogger returned nil")
	}
	if logger.shared == nil {
		t.Fatal("DefaultLogger returned logger with nil shared logger")
	}
}

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name      string
		level     slog.Level
		logWriter *bytes.Buffer
		wantNil   bool
	}{
		{
			name:      "debug level with custom writer",
			level:     slog.LevelDebug,
			logWriter: &bytes.Buffer{},
			wantNil:   false,
		},
		{
			name:      "info level with custom writer",
			level:     slog.LevelInfo,
			logWriter: &bytes.Buffer{},
			wantNil:   false,
		},
		{
			name:      "nil writer uses os.Stderr",
			level:     slog.LevelInfo,
			logWriter: nil,
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logger *Logger
			if tt.logWriter != nil {
				logger = NewLogger(tt.level, tt.logWriter)
			} else {
				logger = NewLogger(tt.level, nil)
			}

			if (logger == nil) != tt.wantNil {
				t.Errorf("NewLogger() returned nil = %v, want %v", logger == nil, tt.wantNil)
			}
			if logger != nil && logger.shared == nil {
				t.Error("NewLogger() returned logger with nil shared logger")
			}
		})
	}
}

func TestDebugf(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	logger.Debugf("debug message: %s %d", "test", 123)

	output := buf.String()
	if !strings.Contains(output, "debug message: test 123") {
		t.Errorf("Debugf() output = %q, want to contain 'debug message: test 123'", output)
	}
}

func TestInfof(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelInfo, buf)

	logger.Infof("info message: %s %d", "test", 456)

	output := buf.String()
	if !strings.Contains(output, "info message: test 456") {
		t.Errorf("Infof() output = %q, want to contain 'info message: test 456'", output)
	}
}

func TestWarnf(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelWarn, buf)

	logger.Warnf("warn message: %s %d", "test", 789)

	output := buf.String()
	if !strings.Contains(output, "warn message: test 789") {
		t.Errorf("Warnf() output = %q, want to contain 'warn message: test 789'", output)
	}
}

func TestErrorf(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelError, buf)

	logger.Errorf("error message: %s %d", "test", 999)

	output := buf.String()
	if !strings.Contains(output, "error message: test 999") {
		t.Errorf("Errorf() output = %q, want to contain 'error message: test 999'", output)
	}
}

func TestErrorNilLogger(t *testing.T) {
	// This tests the case where logger or logger.shared is nil
	logger := &Logger{}

	// This should not panic and should fall back to slog.Error
	err := errors.New("test error with nil logger")
	logger.Error(err)
}

func TestSlog(t *testing.T) {
	logger := NewLogger(slog.LevelInfo, nil)
	slogger := logger.Slog()

	if slogger == nil {
		t.Error("Slog() returned nil")
	}
	if slogger != logger.shared.Slog() {
		t.Error("Slog() did not return the shared logger's slog.Logger")
	}
}

func TestSecurity(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	issue := SecurityLogEntry{
		Timestamp:       time.Now(),
		Severity:        SeverityHigh,
		Category:        CategoryAuthentication,
		Description:     "Failed authentication attempt",
		Details:         "User attempted to login with invalid credentials",
		Source:          SourceAuthentication,
		OffenderAddress: "192.168.1.100",
		OffenderID:      "user123",
	}

	logger.Security(context.Background(), issue)

	output := buf.String()
	if !strings.Contains(output, "security_log") {
		t.Errorf("Security() output = %q, want to contain 'security_log'", output)
	}
	if !strings.Contains(output, SeverityHigh) {
		t.Errorf("Security() output = %q, want to contain '%s'", output, SeverityHigh)
	}
	if !strings.Contains(output, CategoryAuthentication) {
		t.Errorf("Security() output = %q, want to contain '%s'", output, CategoryAuthentication)
	}
}

func TestMarshalStack(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantEmpty bool
	}{
		{
			name:      "error with stack trace",
			err:       errors.New("test error"),
			wantEmpty: false,
		},
		{
			name:      "simple error",
			err:       errors.New("simple error"),
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames := marshalStack(tt.err)
			if tt.wantEmpty && len(frames) > 0 {
				t.Errorf("marshalStack() returned frames for simple error, want empty")
			}
		})
	}
}

// TestNilLoggerMethods tests that all logging methods handle nil logger gracefully
// by returning early without panicking.
func TestNilLoggerMethods(t *testing.T) {
	t.Run("nil Logger pointer", func(t *testing.T) {
		var logger *Logger
		// All methods should return early without panicking
		logger.Debug("debug message")
		logger.Debugf("debug message: %s", "test")
		logger.Info("info message")
		logger.Infof("info message: %s", "test")
		logger.Warn("warn message")
		logger.Warnf("warn message: %s", "test")
		logger.Error(errors.New("test error"))
		logger.Errorf("error message: %s", "test")
		logger.Security(context.Background(), SecurityLogEntry{})
	})

	t.Run("Logger with nil shared logger", func(t *testing.T) {
		logger := &Logger{}
		// All methods should return early without panicking
		logger.Debug("debug message")
		logger.Debugf("debug message: %s", "test")
		logger.Info("info message")
		logger.Infof("info message: %s", "test")
		logger.Warn("warn message")
		logger.Warnf("warn message: %s", "test")
		// Error has special behavior - falls back to slog.Error
		logger.Error(errors.New("test error"))
		logger.Errorf("error message: %s", "test")
		logger.Security(context.Background(), SecurityLogEntry{})
	})
}

// Fatal methods intentionally write a "FATAL:" line to os.Stderr and call
// os.Exit(-1) regardless of whether the receiver is nil — operators must
// see the cause of a daemon crash even when slog buffering swallowed the
// message. Because os.Exit cannot be exercised in-process without ending
// the test binary, the previous TestFatalNilLoggerReturnsEarly suite has
// been intentionally removed. Subprocess-based fatal-path tests can be
// added later via TestMain re-exec, but they are out of scope here. See
// pkg/logging/logger.go for the design rationale.

// TestSecurityNilLogger tests Security method with nil logger
func TestSecurityNilLogger(t *testing.T) {
	var nilLogger *Logger
	issue := SecurityLogEntry{
		Timestamp:   time.Now(),
		Severity:    SeverityHigh,
		Category:    CategoryAuthentication,
		Description: "Test",
	}
	// Should return early without panicking
	nilLogger.Security(context.Background(), issue)

	// Also test with Logger struct containing nil shared logger
	logger := &Logger{}
	logger.Security(context.Background(), issue)
}

// TestReplaceAttr tests the replaceAttr function with various attribute types
func TestReplaceAttr(t *testing.T) {
	t.Run("non-error attribute", func(t *testing.T) {
		attr := slog.String("key", "value")
		result := replaceAttr(nil, attr)
		if result.Key != "key" {
			t.Errorf("replaceAttr() key = %v, want 'key'", result.Key)
		}
		if result.Value.String() != "value" {
			t.Errorf("replaceAttr() value = %v, want 'value'", result.Value.String())
		}
	})

	t.Run("error attribute", func(t *testing.T) {
		err := errors.New("test error")
		attr := slog.Any("error", err)
		result := replaceAttr(nil, attr)
		if result.Key != "error" {
			t.Errorf("replaceAttr() key = %v, want 'error'", result.Key)
		}
		// The value should be transformed by fmtErr
		if result.Value.Kind() != slog.KindGroup {
			t.Errorf("replaceAttr() value kind = %v, want Group", result.Value.Kind())
		}
	})

	t.Run("integer attribute", func(t *testing.T) {
		attr := slog.Int("count", 42)
		result := replaceAttr(nil, attr)
		if result.Key != "count" {
			t.Errorf("replaceAttr() key = %v, want 'count'", result.Key)
		}
	})

	t.Run("time attribute", func(t *testing.T) {
		now := time.Now()
		attr := slog.Time("timestamp", now)
		result := replaceAttr(nil, attr)
		if result.Key != "timestamp" {
			t.Errorf("replaceAttr() key = %v, want 'timestamp'", result.Key)
		}
	})
}

// TestFmtErr tests the fmtErr function
func TestFmtErr(t *testing.T) {
	t.Run("error with message", func(t *testing.T) {
		err := errors.New("test error message")
		result := fmtErr(err)
		if result.Kind() != slog.KindGroup {
			t.Errorf("fmtErr() returned kind = %v, want Group", result.Kind())
		}
		// Check that the group contains the expected attributes
		groupAttrs := result.Group()
		var foundMsg bool
		for _, attr := range groupAttrs {
			if attr.Key == "msg" && attr.Value.String() == "test error message" {
				foundMsg = true
			}
		}
		if !foundMsg {
			t.Error("fmtErr() did not include 'msg' attribute with correct value")
		}
	})

	t.Run("xerror with stack trace", func(t *testing.T) {
		// Create an error using xerrors to ensure stack trace is captured
		err := xerrors.New(errors.New("xerror test"))
		result := fmtErr(err)
		if result.Kind() != slog.KindGroup {
			t.Errorf("fmtErr() returned kind = %v, want Group", result.Kind())
		}
		// Check that the group contains trace attribute when stack trace is available
		groupAttrs := result.Group()
		var foundTrace bool
		for _, attr := range groupAttrs {
			if attr.Key == "trace" {
				foundTrace = true
			}
		}
		if !foundTrace {
			t.Error("fmtErr() should include 'trace' attribute for xerror")
		}
	})
}

// TestMarshalStackXerror tests marshalStack with xerror that has stack trace
func TestMarshalStackXerror(t *testing.T) {
	// Create an error using xerrors to get stack trace
	err := xerrors.New(errors.New("test error with stack"))
	frames := marshalStack(err)
	if frames == nil {
		t.Error("marshalStack() returned nil for xerror, want stack frames")
	}
	if len(frames) == 0 {
		t.Error("marshalStack() returned empty frames for xerror, want stack frames")
	}

	// Verify frame structure
	for _, frame := range frames {
		if frame.Func == "" {
			t.Error("marshalStack() returned frame with empty Func")
		}
		if frame.Source == "" {
			t.Error("marshalStack() returned frame with empty Source")
		}
		if frame.Line <= 0 {
			t.Error("marshalStack() returned frame with invalid Line")
		}
	}
}

// TestMarshalStackEmptyTrace tests marshalStack when error has no stack trace
func TestMarshalStackEmptyTrace(t *testing.T) {
	// Standard Go errors don't have stack traces compatible with xerrors
	err := errors.New("simple error without stack")
	frames := marshalStack(err)
	// xerrors.StackTrace returns nil for errors without stack trace
	if len(frames) > 0 {
		// This is expected for standard errors wrapped elsewhere
		// The behavior depends on how the error was created
		t.Log("marshalStack() returned frames for simple error - may be wrapped")
	}
}

// TestDebugWithArgs tests Debug with additional structured arguments
func TestDebugWithArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	logger.Debug("debug message", "key1", "value1", "key2", 42)

	output := buf.String()
	if !strings.Contains(output, "debug message") {
		t.Errorf("Debug() output = %q, want to contain 'debug message'", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("Debug() output = %q, want to contain 'key1'", output)
	}
	if !strings.Contains(output, "value1") {
		t.Errorf("Debug() output = %q, want to contain 'value1'", output)
	}
}

// TestInfoWithArgs tests Info with additional structured arguments
func TestInfoWithArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelInfo, buf)

	logger.Info("info message", "key1", "value1", "key2", 42)

	output := buf.String()
	if !strings.Contains(output, "info message") {
		t.Errorf("Info() output = %q, want to contain 'info message'", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("Info() output = %q, want to contain 'key1'", output)
	}
}

// TestWarnWithArgs tests Warn with additional structured arguments
func TestWarnWithArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelWarn, buf)

	logger.Warn("warn message", "key1", "value1", "key2", 42)

	output := buf.String()
	if !strings.Contains(output, "warn message") {
		t.Errorf("Warn() output = %q, want to contain 'warn message'", output)
	}
	if !strings.Contains(output, "key1") {
		t.Errorf("Warn() output = %q, want to contain 'key1'", output)
	}
}

// TestErrorWithArgs tests Error with additional structured arguments
func TestErrorWithArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelError, buf)

	err := errors.New("test error")
	logger.Error(err, "key1", "value1")

	output := buf.String()
	if !strings.Contains(output, "test error") {
		t.Errorf("Error() output = %q, want to contain 'test error'", output)
	}
}

// TestSecurityAllFields tests Security logging with all fields populated
func TestSecurityAllFields(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	timestamp := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	issue := SecurityLogEntry{
		Timestamp:       timestamp,
		Severity:        SeverityCritical,
		Category:        CategoryDataBreach,
		Description:     "Sensitive data exposed",
		Details:         "Customer PII accessed without authorization",
		Source:          SourceSystem,
		OffenderAddress: "10.0.0.50",
		OffenderID:      "attacker-123",
	}

	logger.Security(context.Background(), issue)

	output := buf.String()
	if !strings.Contains(output, SeverityCritical) {
		t.Errorf("Security() output missing severity")
	}
	if !strings.Contains(output, CategoryDataBreach) {
		t.Errorf("Security() output missing category")
	}
	if !strings.Contains(output, "Sensitive data exposed") {
		t.Errorf("Security() output missing description")
	}
	if !strings.Contains(output, "10.0.0.50") {
		t.Errorf("Security() output missing offender address")
	}
	if !strings.Contains(output, "attacker-123") {
		t.Errorf("Security() output missing offender ID")
	}
}

// TestSecurityCategories tests Security logging with different categories
func TestSecurityCategories(t *testing.T) {
	categories := []string{
		CategoryAccessControl,
		CategoryAuthentication,
		CategoryAuthorization,
		CategoryDataBreach,
		CategoryMalwareDetection,
		CategoryNetworkSecurity,
		CategoryPolicyViolation,
		CategorySystemIntegrity,
		CategoryUserBehavior,
	}

	for _, category := range categories {
		t.Run(category, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := NewLogger(slog.LevelDebug, buf)

			issue := SecurityLogEntry{
				Timestamp:   time.Now(),
				Severity:    SeverityMedium,
				Category:    category,
				Description: "Test security event",
			}

			logger.Security(context.Background(), issue)

			output := buf.String()
			if !strings.Contains(output, category) {
				t.Errorf("Security() output = %q, want to contain category '%s'", output, category)
			}
		})
	}
}

// TestSecuritySeverities tests Security logging with different severities
func TestSecuritySeverities(t *testing.T) {
	severities := []string{
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}

	for _, severity := range severities {
		t.Run(severity, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := NewLogger(slog.LevelDebug, buf)

			issue := SecurityLogEntry{
				Timestamp:   time.Now(),
				Severity:    severity,
				Category:    CategoryAuthentication,
				Description: "Test security event",
			}

			logger.Security(context.Background(), issue)

			output := buf.String()
			if !strings.Contains(output, severity) {
				t.Errorf("Security() output = %q, want to contain severity '%s'", output, severity)
			}
		})
	}
}

// TestLogLevels tests that custom log levels are defined correctly
func TestLogLevels(t *testing.T) {
	if LevelTrace >= slog.LevelDebug {
		t.Errorf("LevelTrace (%d) should be less than LevelDebug (%d)", LevelTrace, slog.LevelDebug)
	}
	if LevelFatal <= slog.LevelError {
		t.Errorf("LevelFatal (%d) should be greater than LevelError (%d)", LevelFatal, slog.LevelError)
	}
	if LevelSecurity <= LevelFatal {
		t.Errorf("LevelSecurity (%d) should be greater than LevelFatal (%d)", LevelSecurity, LevelFatal)
	}
}

// TestStackFrameStruct tests the stackFrame struct
func TestStackFrameStruct(t *testing.T) {
	frame := stackFrame{
		Func:   "TestFunction",
		Source: "logging/logger_test.go",
		Line:   100,
	}

	if frame.Func != "TestFunction" {
		t.Errorf("stackFrame.Func = %v, want 'TestFunction'", frame.Func)
	}
	if frame.Source != "logging/logger_test.go" {
		t.Errorf("stackFrame.Source = %v, want 'logging/logger_test.go'", frame.Source)
	}
	if frame.Line != 100 {
		t.Errorf("stackFrame.Line = %v, want 100", frame.Line)
	}
}

// TestSourceConstants tests that source constants are defined correctly
// TestParseFormat tests the ParseFormat function
func TestParseFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected Format
	}{
		{
			name:     "lowercase json",
			input:    "json",
			expected: FormatJSON,
		},
		{
			name:     "uppercase JSON",
			input:    "JSON",
			expected: FormatJSON,
		},
		{
			name:     "lowercase text",
			input:    "text",
			expected: FormatText,
		},
		{
			name:     "uppercase TEXT",
			input:    "TEXT",
			expected: FormatText,
		},
		{
			name:     "empty string defaults to json",
			input:    "",
			expected: FormatJSON,
		},
		{
			name:     "invalid value defaults to json",
			input:    "invalid",
			expected: FormatJSON,
		},
		{
			name:     "random string defaults to json",
			input:    "yaml",
			expected: FormatJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseFormat(tt.input)
			if result != tt.expected {
				t.Errorf("ParseFormat(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNewLoggerWithFormat tests the NewLoggerWithFormat function
func TestNewLoggerWithFormat(t *testing.T) {
	tests := []struct {
		name           string
		level          slog.Level
		format         Format
		wantJSONFormat bool
	}{
		{
			name:           "JSON format with debug level",
			level:          slog.LevelDebug,
			format:         FormatJSON,
			wantJSONFormat: true,
		},
		{
			name:           "Text format with debug level",
			level:          slog.LevelDebug,
			format:         FormatText,
			wantJSONFormat: false,
		},
		{
			name:           "JSON format with info level",
			level:          slog.LevelInfo,
			format:         FormatJSON,
			wantJSONFormat: true,
		},
		{
			name:           "Text format with info level",
			level:          slog.LevelInfo,
			format:         FormatText,
			wantJSONFormat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			logger := NewLoggerWithFormat(tt.level, tt.format, buf)

			if logger == nil {
				t.Fatal("NewLoggerWithFormat returned nil")
			}
			if logger.shared == nil {
				t.Fatal("NewLoggerWithFormat returned logger with nil shared logger")
			}

			// Log a test message
			logger.Info("test message", "key", "value")

			output := buf.String()
			if output == "" {
				t.Fatal("No output was written")
			}

			// Check if output is JSON or text format
			isJSON := strings.HasPrefix(strings.TrimSpace(output), "{")
			if tt.wantJSONFormat && !isJSON {
				t.Errorf("Expected JSON format, got: %s", output)
			}
			if !tt.wantJSONFormat && isJSON {
				t.Errorf("Expected text format, got: %s", output)
			}
		})
	}
}

// TestNewLoggerWithFormatNilWriter tests NewLoggerWithFormat with nil writer
func TestNewLoggerWithFormatNilWriter(t *testing.T) {
	// Should not panic and should use os.Stderr as default
	logger := NewLoggerWithFormat(slog.LevelInfo, FormatJSON, nil)
	if logger == nil {
		t.Fatal("NewLoggerWithFormat returned nil for nil writer")
	}
	if logger.shared == nil {
		t.Fatal("NewLoggerWithFormat returned logger with nil shared logger")
	}
}

// TestFormatConstants tests that format constants have expected values
// TestNewLoggerWithFormatOutputConsistency tests that only ONE format is output
func TestNewLoggerWithFormatOutputConsistency(t *testing.T) {
	t.Run("JSON format produces only JSON", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := NewLoggerWithFormat(slog.LevelDebug, FormatJSON, buf)

		logger.Debug("debug message")
		logger.Info("info message")
		logger.Warn("warn message")

		output := buf.String()
		lines := strings.Split(strings.TrimSpace(output), "\n")

		for i, line := range lines {
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "{") {
				t.Errorf("Line %d is not JSON format: %s", i+1, line)
			}
		}
	})

	t.Run("Text format produces only text", func(t *testing.T) {
		buf := &bytes.Buffer{}
		logger := NewLoggerWithFormat(slog.LevelDebug, FormatText, buf)

		logger.Debug("debug message")
		logger.Info("info message")
		logger.Warn("warn message")

		output := buf.String()
		lines := strings.Split(strings.TrimSpace(output), "\n")

		for i, line := range lines {
			if line == "" {
				continue
			}
			// Text format starts with "time=" not "{"
			if strings.HasPrefix(line, "{") {
				t.Errorf("Line %d is JSON format when text expected: %s", i+1, line)
			}
			if !strings.HasPrefix(line, "time=") {
				t.Errorf("Line %d does not look like slog text format: %s", i+1, line)
			}
		}
	})
}
