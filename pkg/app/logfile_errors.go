package app

import "fmt"

// LogDirInvalidError is returned when the configured log directory cannot
// name a directory. It is raised before any filesystem call.
type LogDirInvalidError struct {
	Dir    string
	Reason string
}

// Error returns the error message.
func (e LogDirInvalidError) Error() string {
	return fmt.Sprintf("app: invalid log directory %q: %s", e.Dir, e.Reason)
}

// LogDirCreateError is returned when the log directory cannot be created.
type LogDirCreateError struct {
	Dir   string
	Cause error
}

// Error returns the error message.
func (e LogDirCreateError) Error() string {
	return fmt.Sprintf("app: failed to create log directory %q: %v", e.Dir, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogDirCreateError) Unwrap() error { return e.Cause }

// LogFileOpenError is returned when the platform log file cannot be opened
// (created if missing) and closed again.
type LogFileOpenError struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e LogFileOpenError) Error() string {
	return fmt.Sprintf("app: failed to open log file %q: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogFileOpenError) Unwrap() error { return e.Cause }
