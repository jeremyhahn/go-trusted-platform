package app

import (
	"fmt"
	"os"
)

// RuntimeUserLookupError is returned when the configured runtime user does
// not exist on the host.
type RuntimeUserLookupError struct {
	User  string
	Cause error
}

// Error returns the error message.
func (e RuntimeUserLookupError) Error() string {
	return fmt.Sprintf("app: runtime user %q not found: %v", e.User, e.Cause)
}

// Unwrap returns the underlying cause.
func (e RuntimeUserLookupError) Unwrap() error { return e.Cause }

// RuntimeUserUIDError is returned when the runtime user's UID is not a decimal
// in 0..4294967294; the cause is a *strconv.NumError or an IDRangeError.
type RuntimeUserUIDError struct {
	User  string
	UID   string
	Cause error
}

// Error returns the error message.
func (e RuntimeUserUIDError) Error() string {
	return fmt.Sprintf("app: runtime user %q has an invalid UID %q: %v", e.User, e.UID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e RuntimeUserUIDError) Unwrap() error { return e.Cause }

// RuntimeUserGIDError is returned when the runtime user's GID is not a decimal
// in 0..4294967294; the cause is a *strconv.NumError or an IDRangeError.
type RuntimeUserGIDError struct {
	User  string
	GID   string
	Cause error
}

// Error returns the error message.
func (e RuntimeUserGIDError) Error() string {
	return fmt.Sprintf("app: runtime user %q has an invalid GID %q: %v", e.User, e.GID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e RuntimeUserGIDError) Unwrap() error { return e.Cause }

// SetgroupsError is returned when the supplementary groups cannot be reduced
// to the runtime user's primary group.
type SetgroupsError struct {
	GID   int
	Cause error
}

// Error returns the error message.
func (e SetgroupsError) Error() string {
	return fmt.Sprintf("app: setgroups([%d]) failed: %v", e.GID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e SetgroupsError) Unwrap() error { return e.Cause }

// SetgidError is returned when the process cannot change to the runtime
// user's group.
type SetgidError struct {
	GID   int
	Cause error
}

// Error returns the error message.
func (e SetgidError) Error() string {
	return fmt.Sprintf("app: setgid(%d) failed: %v", e.GID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e SetgidError) Unwrap() error { return e.Cause }

// SetuidError is returned when the process cannot change to the runtime user.
type SetuidError struct {
	UID   int
	Cause error
}

// Error returns the error message.
func (e SetuidError) Error() string {
	return fmt.Sprintf("app: setuid(%d) failed: %v", e.UID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e SetuidError) Unwrap() error { return e.Cause }

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

// LogFileChownError is returned when the log file's owner cannot be set.
type LogFileChownError struct {
	Path  string
	UID   int
	GID   int
	Cause error
}

// Error returns the error message.
func (e LogFileChownError) Error() string {
	return fmt.Sprintf("app: failed to chown log file %q to %d:%d: %v", e.Path, e.UID, e.GID, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogFileChownError) Unwrap() error { return e.Cause }

// LogFileChmodError is returned when the log file's mode cannot be set.
type LogFileChmodError struct {
	Path  string
	Mode  os.FileMode
	Cause error
}

// Error returns the error message.
func (e LogFileChmodError) Error() string {
	return fmt.Sprintf("app: failed to chmod log file %q to %v: %v", e.Path, e.Mode, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogFileChmodError) Unwrap() error { return e.Cause }

// LogFileStatError is returned when the log file's owner cannot be read.
type LogFileStatError struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e LogFileStatError) Error() string {
	return fmt.Sprintf("app: failed to read the owner of log file %q: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogFileStatError) Unwrap() error { return e.Cause }

// LogFileNotRegularError is returned when the log path names something other
// than a regular file, such as a FIFO or device node, which root must not
// hand to the runtime user.
type LogFileNotRegularError struct {
	Path string
}

// Error returns the error message.
func (e LogFileNotRegularError) Error() string {
	return fmt.Sprintf("app: log file %q is not a regular file", e.Path)
}

// LogFileCloseError is returned when the prepared log file cannot be closed.
type LogFileCloseError struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e LogFileCloseError) Error() string {
	return fmt.Sprintf("app: failed to close log file %q: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e LogFileCloseError) Unwrap() error { return e.Cause }

// LogFileOwnerError is returned when the requested log file owner is not a
// UID and GID the kernel applies: negative, or beyond 4294967294.
type LogFileOwnerError struct {
	UID int
	GID int
}

// Error returns the error message.
func (e LogFileOwnerError) Error() string {
	return fmt.Sprintf("app: log file owner %d:%d is outside 0..%d", e.UID, e.GID, uint64(maxID))
}

// IDRangeError is returned when a UID or GID is 4294967295, which the
// kernel reserves to mean "leave unchanged".
type IDRangeError struct {
	ID uint64
}

// Error returns the error message.
func (e IDRangeError) Error() string {
	return fmt.Sprintf("app: id %d is outside 0..%d", e.ID, uint64(maxID))
}
