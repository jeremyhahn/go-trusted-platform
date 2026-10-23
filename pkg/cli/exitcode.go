package cli

import "errors"

// ExitGenericFailure is the process exit code of any command failure that
// does not carry its own code.
const ExitGenericFailure = 1

// ExitError carries the process exit code a command failure maps to, for
// verbs whose documented exit codes distinguish failures (docs/vpn/cli.md).
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return "command failed"
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	return e.Err
}

// ExitCode maps a command's error to the process exit code: 0 for nil, the
// code of an ExitError anywhere in the chain, and ExitGenericFailure for
// everything else.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) && exit.Code != 0 {
		return exit.Code
	}
	return ExitGenericFailure
}
