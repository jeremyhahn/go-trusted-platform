package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mdobak/go-xerrors"
	slogmulti "github.com/samber/slog-multi"
	"github.com/spf13/afero"
)

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

func DefaultLogger() *Logger {
	return NewLogger(slog.LevelDebug, nil)
}

func NewLogger(level slog.Level, logFile afero.File) *Logger {

	var logger *slog.Logger

	logfileHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceAttr,
	})

	if level == slog.LevelDebug {

		textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: replaceAttr,
		})

		// stdoutHandler := slog.NewJSONHandler(logFile, &slog.HandlerOptions{
		// 	Level:       level,
		// 	ReplaceAttr: replaceAttr,
		// })

		logger = slog.New(
			slogmulti.Fanout(logfileHandler, textHandler),
		)

	} else {

		logger = slog.New(logfileHandler)
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
		slog.Error(err.Error(), args)
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

// Logs a security issue with standardized fields to faciliate
// processing security issues by external systems.
func (l *Logger) Security(issue SecurityLogEntry) {
	l.logger.LogAttrs(
		context.TODO(),
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
