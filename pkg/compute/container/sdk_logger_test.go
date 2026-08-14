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
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// newCapturingLogger returns an SDK logger adapter writing to buf.
func newCapturingLogger(buf *bytes.Buffer) *sdkLogger {
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return newSDKLogger(slog.New(handler))
}

func TestSDKLogger_ForwardsEveryLevel(t *testing.T) {
	testCases := []struct {
		name  string
		emit  func(*sdkLogger)
		level string
		body  string
	}{
		{"debug", func(l *sdkLogger) { l.Debug("dbg", "k", "v") }, "DEBUG", "dbg"},
		{"debugf", func(l *sdkLogger) { l.Debugf("dbg %d", 1) }, "DEBUG", "dbg 1"},
		{"info", func(l *sdkLogger) { l.Info("inf", "k", "v") }, "INFO", "inf"},
		{"infof", func(l *sdkLogger) { l.Infof("inf %d", 2) }, "INFO", "inf 2"},
		{"warn", func(l *sdkLogger) { l.Warn("wrn", "k", "v") }, "WARN", "wrn"},
		{"warnf", func(l *sdkLogger) { l.Warnf("wrn %d", 3) }, "WARN", "wrn 3"},
		{"error", func(l *sdkLogger) { l.Error("err", "k", "v") }, "ERROR", "err"},
		{"errorf", func(l *sdkLogger) { l.Errorf("err %d", 4) }, "ERROR", "err 4"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.emit(newCapturingLogger(&buf))

			out := buf.String()
			if !strings.Contains(out, tc.level) {
				t.Errorf("output %q does not carry level %s", out, tc.level)
			}
			if !strings.Contains(out, tc.body) {
				t.Errorf("output %q does not carry message %q", out, tc.body)
			}
		})
	}
}

func TestSDKLogger_StructuredDerivation(t *testing.T) {
	t.Run("WithField", func(t *testing.T) {
		var buf bytes.Buffer
		newCapturingLogger(&buf).WithField("container", "c1").Info("hello")
		if !strings.Contains(buf.String(), "container=c1") {
			t.Errorf("field missing from %q", buf.String())
		}
	})

	t.Run("WithFields", func(t *testing.T) {
		var buf bytes.Buffer
		newCapturingLogger(&buf).
			WithFields(map[string]interface{}{"pcr": 14}).
			Info("hello")
		if !strings.Contains(buf.String(), "pcr=14") {
			t.Errorf("field missing from %q", buf.String())
		}
	})

	t.Run("WithError", func(t *testing.T) {
		var buf bytes.Buffer
		newCapturingLogger(&buf).WithError(errors.New("boom")).Error("failed")
		if !strings.Contains(buf.String(), "boom") {
			t.Errorf("error field missing from %q", buf.String())
		}
	})

	t.Run("nil logger resolves to the default", func(t *testing.T) {
		// The SDK constructors reject a nil logger, so the adapter must
		// never hand one over.
		if newSDKLogger(nil).log == nil {
			t.Fatal("nil logger must resolve to slog.Default")
		}
	})
}

// TestSDKLogger_FatalExits runs the adapter's Fatal in a subprocess: the SDK
// logger contract requires it to terminate the process, which cannot be
// observed in-process.
func TestSDKLogger_FatalExits(t *testing.T) {
	if os.Getenv("TP_SDK_LOGGER_FATAL") == "1" {
		newSDKLogger(slog.Default()).Fatalf("fatal %s", "now")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSDKLogger_FatalExits")
	cmd.Env = append(os.Environ(), "TP_SDK_LOGGER_FATAL=1")

	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Fatalf must terminate the process, got %v", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1", exitErr.ExitCode())
	}
}
