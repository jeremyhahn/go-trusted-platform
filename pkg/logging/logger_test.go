package logging

import (
	"errors"
	"log/slog"
	"testing"
)

func TestLogger(t *testing.T) {

	logger := NewLogger(slog.LevelDebug, nil)

	logger.Info("info test")
	logger.Warn("warn test")
	// logger.Error("error test")
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
