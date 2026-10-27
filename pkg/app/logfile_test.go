package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOpError is the failure an injected operation returns when told to fail.
type fakeOpError struct{ op string }

func (e fakeOpError) Error() string { return "fake " + e.op + " failure" }

func TestLogFileName(t *testing.T) {
	saved := Name
	t.Cleanup(func() { Name = saved })

	Name = "trusted-platform"
	assert.Equal(t, "trusted-platform.log", logFileName())

	Name = ""
	assert.Equal(t, "platformd.log", logFileName(), "an unset Name must not produce a hidden .log")
}

func TestValidateLogDir(t *testing.T) {
	assert.NoError(t, validateLogDir("/var/log/platform"))
}

func TestValidateLogDir_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		dir    string
		reason string
	}{
		{name: "empty", dir: "", reason: "empty"},
		{name: "whitespace", dir: "  \t", reason: "empty"},
		{name: "NUL byte", dir: "/var/log\x00/platform", reason: "contains a NUL byte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var target LogDirInvalidError
			require.ErrorAs(t, validateLogDir(tt.dir), &target)
			assert.Equal(t, tt.dir, target.Dir)
			assert.Equal(t, tt.reason, target.Reason)
		})
	}
}

func TestLogErrors_Messages(t *testing.T) {
	cause := fakeOpError{op: "cause"}
	tests := []struct {
		err  error
		want []string
	}{
		{LogDirCreateError{Dir: "/l", Cause: cause}, []string{"create log directory", "/l"}},
		{LogFileOpenError{Path: "/l/p.log", Cause: cause}, []string{"open log file", "/l/p.log"}},
	}
	for _, tt := range tests {
		msg := tt.err.Error()
		for _, want := range tt.want {
			assert.Contains(t, msg, want)
		}
		assert.Contains(t, msg, cause.Error(), "%T must carry its cause", tt.err)
		assert.ErrorIs(t, tt.err, cause, "%T must unwrap to its cause", tt.err)
	}

	msg := LogDirInvalidError{Dir: "", Reason: "empty"}.Error()
	assert.Contains(t, msg, "log directory")
	assert.Contains(t, msg, "empty")
}

func assertErrorType(t *testing.T, err error, want error) {
	t.Helper()
	for e := err; e != nil; e = errors.Unwrap(e) {
		if reflect.TypeOf(e) == reflect.TypeOf(want) {
			return
		}
	}
	t.Fatalf("error %v (%T) is not a %T", err, err, want)
}
