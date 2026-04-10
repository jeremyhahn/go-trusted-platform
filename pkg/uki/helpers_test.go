package uki

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func testLogger(t *testing.T) *logging.Logger {
	t.Helper()
	return logging.NewLogger(slog.LevelError, io.Discard)
}
