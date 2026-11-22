//go:build integration

package diskimage

// MissingInputError reports a required suite input that is unset or absent.
type MissingInputError struct {
	Variable string
	Path     string
	Err      error
}

func (e *MissingInputError) Error() string {
	if e.Variable != "" && e.Path == "" {
		return "diskimage suite: " + e.Variable + " is not set (run `make integration-test-diskimage`, which builds the inputs)"
	}
	return "diskimage suite: " + e.Variable + "=" + e.Path + ": " + e.Err.Error()
}

func (e *MissingInputError) Unwrap() error { return e.Err }
