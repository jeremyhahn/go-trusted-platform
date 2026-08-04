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
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// TestSharedLevelAliases pins the facade's level constants to the shared
// stack logger's values so the two sides can never drift apart.
func TestSharedLevelAliases(t *testing.T) {
	if LevelTrace != quicbaas.LogLevelTrace {
		t.Errorf("LevelTrace = %d, want shared %d", LevelTrace, quicbaas.LogLevelTrace)
	}
	if LevelFatal != quicbaas.LogLevelFatal {
		t.Errorf("LevelFatal = %d, want shared %d", LevelFatal, quicbaas.LogLevelFatal)
	}
}

// TestLevelSecurityAvoidsSharedPanic guards against the level collision the
// shared logger documents: slog.Level(16) renders as "PANIC" in shared
// handlers, so the platform security level must not sit there.
func TestLevelSecurityAvoidsSharedPanic(t *testing.T) {
	if LevelSecurity == quicbaas.LogLevelPanic {
		t.Fatalf("LevelSecurity (%d) collides with the shared logger's PANIC level", LevelSecurity)
	}
	if LevelSecurity <= LevelFatal {
		t.Errorf("LevelSecurity (%d) should be greater than LevelFatal (%d)", LevelSecurity, LevelFatal)
	}
}

// TestSecurityLevelRendering verifies the security level renders with its
// numeric offset and never as the shared logger's "PANIC" name.
func TestSecurityLevelRendering(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	logger.Security(t.Context(), SecurityLogEntry{
		Severity:    SeverityLow,
		Category:    CategoryUserBehavior,
		Description: "level rendering check",
	})

	output := buf.String()
	if strings.Contains(output, "PANIC") {
		t.Errorf("Security() rendered PANIC level: %q", output)
	}
	if !strings.Contains(output, "ERROR+12") {
		t.Errorf("Security() output = %q, want level ERROR+12", output)
	}
}

// TestLevelString exercises every branch of the slog.Level to shared level
// vocabulary mapping.
func TestLevelString(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{LevelTrace, "trace"},
		{slog.Level(-10), "trace"},
		{slog.LevelDebug, "debug"},
		{slog.LevelInfo, "info"},
		{slog.LevelWarn, "warn"},
		{slog.LevelError, "error"},
		{LevelFatal, "fatal"},
		{LevelSecurity, "panic"},
	}
	for _, tt := range tests {
		if got := levelString(tt.level); got != tt.want {
			t.Errorf("levelString(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// TestNewFromSlogNil verifies the nil fallback constructs a usable logger.
func TestNewFromSlogNil(t *testing.T) {
	logger := NewFromSlog(nil)
	if logger == nil || logger.shared == nil {
		t.Fatal("NewFromSlog(nil) did not return a usable default logger")
	}
}

// TestNewFromSlogPreservesHandlerAndAttrs verifies bound attributes survive
// the facade because they live in the wrapped handler.
func TestNewFromSlogPreservesHandlerAndAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	base := slog.New(slog.NewJSONHandler(buf, nil)).With("component", "orchestrator")

	logger := NewFromSlog(base)
	logger.Info("hello")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if record["component"] != "orchestrator" {
		t.Errorf("bound attr lost: %v", record)
	}
	if record["msg"] != "hello" {
		t.Errorf("msg = %v, want hello", record["msg"])
	}
}

// TestWrapHandlerRoundTrip verifies the platformd boot fan-out contract:
// WrapHandler(h).Slog().Handler() must return h so log_sink.go can rewrap
// and extend the handler chain.
func TestWrapHandlerRoundTrip(t *testing.T) {
	buf := &bytes.Buffer{}
	child := slog.NewJSONHandler(buf, nil)
	multi := NewMultiHandler(child)

	logger := WrapHandler(multi)
	if logger.Slog().Handler() != slog.Handler(multi) {
		t.Fatal("WrapHandler did not preserve handler identity")
	}

	logger.Info("fan-out check")
	if !strings.Contains(buf.String(), "fan-out check") {
		t.Errorf("record did not reach the multi-handler child: %q", buf.String())
	}
}

// TestWrapHandlerNilPanics verifies a nil handler is rejected at
// construction time instead of producing a logger that panics on first use.
func TestWrapHandlerNilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WrapHandler(nil) did not panic")
		}
	}()
	WrapHandler(nil)
}

// TestSlogNilSafety verifies Slog returns nil for nil and zero-value
// receivers rather than panicking.
func TestSlogNilSafety(t *testing.T) {
	var nilLogger *Logger
	if nilLogger.Slog() != nil {
		t.Error("nil Logger Slog() should return nil")
	}
	if (&Logger{}).Slog() != nil {
		t.Error("zero-value Logger Slog() should return nil")
	}
}

// TestErrorRendersTraceGroup verifies Error emits the xerrors {msg, trace}
// group under the "error" key — the output contract consumed by log
// tooling.
func TestErrorRendersTraceGroup(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	logger.Error(errors.New("boom"))

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if record["msg"] != "boom" {
		t.Errorf("msg = %v, want boom", record["msg"])
	}
	group, ok := record["error"].(map[string]any)
	if !ok {
		t.Fatalf("error attr is not a group: %v", record["error"])
	}
	if group["msg"] != "boom" {
		t.Errorf("error.msg = %v, want boom", group["msg"])
	}
	if _, ok := group["trace"]; !ok {
		t.Error("error.trace missing — xerrors stack rendering lost")
	}
}

// TestErrorAttrReplacedInArgs verifies the handler still rewrites plain
// error-valued attributes passed as structured args into {msg, trace}
// groups (the replaceAttr contract).
func TestErrorAttrReplacedInArgs(t *testing.T) {
	buf := &bytes.Buffer{}
	logger := NewLogger(slog.LevelDebug, buf)

	logger.Warn("operation failed", "cause", errors.New("disk full"))

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	group, ok := record["cause"].(map[string]any)
	if !ok {
		t.Fatalf("cause attr is not a group: %v", record["cause"])
	}
	if group["msg"] != "disk full" {
		t.Errorf("cause.msg = %v, want disk full", group["msg"])
	}
}

// TestZeroValueLoggerIsNoOp verifies the documented zero-value contract
// relied on by importer tests (e.g. pkg/dns) that construct &Logger{}.
func TestZeroValueLoggerIsNoOp(t *testing.T) {
	logger := &Logger{}
	logger.Debug("d")
	logger.Debugf("d %s", "f")
	logger.Info("i")
	logger.Infof("i %s", "f")
	logger.Warn("w")
	logger.Warnf("w %s", "f")
	logger.Error(errors.New("e"))
	logger.Errorf("e %s", "f")
	logger.Security(t.Context(), SecurityLogEntry{})
	if logger.Slog() != nil {
		t.Error("zero-value Slog() should be nil")
	}
}

// fatalHelperEnv selects the fatal-path scenario executed by
// TestFatalHelperProcess in the child process.
const fatalHelperEnv = "TP_LOGGING_FATAL_HELPER"

// TestFatalHelperProcess is not a real test: it is the child-process entry
// point for the subprocess fatal-path tests below. It returns immediately
// when the selector env var is unset (normal test runs).
func TestFatalHelperProcess(t *testing.T) {
	mode := os.Getenv(fatalHelperEnv)
	if mode == "" {
		return
	}
	logger := NewLogger(slog.LevelDebug, os.Stdout)
	var nilLogger *Logger
	switch mode {
	case "fatal":
		logger.Fatal("fatal message", "key", "value")
	case "fatalf":
		logger.Fatalf("fatalf message: %d", 42)
	case "fatalerror":
		logger.FatalError(errors.New("fatal error message"))
	case "fatal-nil":
		nilLogger.Fatal("nil fatal message")
	case "fatalf-nil":
		nilLogger.Fatalf("nil fatalf message: %d", 7)
	case "fatalerror-nil":
		nilLogger.FatalError(errors.New("nil fatal error message"))
	}
	// Every mode must exit before reaching this point.
	os.Exit(3)
}

// runFatalHelper re-executes the test binary running only the helper with
// the requested mode and returns the exit code plus captured stderr and
// stdout.
func runFatalHelper(t *testing.T, mode string) (exitCode int, stderr, stdout string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestFatalHelperProcess$")
	cmd.Env = append(os.Environ(), fatalHelperEnv+"="+mode)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		t.Fatalf("fatal helper mode %q exited 0, want non-zero", mode)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("fatal helper mode %q failed to run: %v", mode, err)
	}
	return exitErr.ExitCode(), errBuf.String(), outBuf.String()
}

// TestFatalPaths verifies every fatal variant mirrors a FATAL: line to
// stderr, logs through slog when a logger exists, and exits with -1 (255).
func TestFatalPaths(t *testing.T) {
	tests := []struct {
		mode       string
		wantStderr string
		wantStdout string
	}{
		{"fatal", "FATAL: fatal message [key value]", "fatal message"},
		{"fatalf", "FATAL: fatalf message: 42", "fatalf message: 42"},
		{"fatalerror", "FATAL: fatal error message", "fatal error message"},
		{"fatal-nil", "FATAL: nil fatal message", ""},
		{"fatalf-nil", "FATAL: nil fatalf message: 7", ""},
		{"fatalerror-nil", "FATAL: nil fatal error message", ""},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			exitCode, stderr, stdout := runFatalHelper(t, tt.mode)
			if exitCode != 255 {
				t.Errorf("exit code = %d, want 255 (os.Exit(-1))", exitCode)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want to contain %q", stderr, tt.wantStderr)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout = %q, want slog record containing %q", stdout, tt.wantStdout)
			}
		})
	}
}
