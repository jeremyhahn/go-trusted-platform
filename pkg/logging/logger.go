package logging

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/mdobak/go-xerrors"
	slogmulti "github.com/samber/slog-multi"
	"github.com/spf13/afero"
)

const (
	LevelTrace = slog.Level(-8)
	LevelFatal = slog.Level(12)
)

type Logger struct {
	logger *slog.Logger
}

func DefaultLogger() *Logger {
	return NewLogger(slog.LevelDebug, nil)
}

func NewLogger(level slog.Level, logFile afero.File) *Logger {

	var logger *slog.Logger

	if level == slog.LevelDebug {

		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		}))

	} else {

		logfileHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		})

		stdoutHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		})

		logger = slog.New(
			slogmulti.Fanout(logfileHandler, stdoutHandler),
		)
	}

	return &Logger{
		logger: logger,
	}
}

// Debug
func (l *Logger) Debug(message string, args ...any) {
	l.logger.Debug(message, args...)
}

func (l *Logger) Debugf(message string, args ...any) {
	l.logger.Debug(fmt.Sprintf(message, args...))
}

// Info
func (l *Logger) Info(message string, args ...any) {
	l.logger.Info(message, args...)
}

func (l *Logger) Infof(message string, args ...any) {
	l.logger.Info(fmt.Sprintf("%s", args...))
}

// Warn
func (l *Logger) Warn(message string, args ...any) {
	l.logger.Warn(message, args...)
}

func (l *Logger) Warnf(message string, args ...any) {
	l.logger.Warn(fmt.Sprintf("%s", args...))
}

// Error
func (l *Logger) Error(err error, args ...any) {
	if l == nil || l.logger == nil {
		// Error occurred before the logger was
		// initialized
		slog.Error(err.Error())
		return
	}
	xerr := xerrors.New(err)
	l.logger.Error(err.Error(), slog.Any("error", xerr))
}

func (l *Logger) Errorf(message string, args ...any) {
	l.logger.Error(fmt.Sprintf(message, args...))
}

func (l *Logger) MaybeError(err error, args ...any) {
	l.logger.Warn(err.Error(), args...)
}

// Fatal
func (l *Logger) Fatal(message string, args ...any) {
	l.logger.Error(message, args...)
	os.Exit(-1)
}

func (l *Logger) Fatalf(message string, args ...any) {
	l.Fatal(fmt.Sprintf(message, args...))
}

func (l *Logger) FatalError(err error) {
	l.Error(err)
	os.Exit(-1)
}
