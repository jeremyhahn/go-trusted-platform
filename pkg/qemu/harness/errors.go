package harness

// TPMError reports a failed step of StartTPM.
type TPMError struct {
	Step string
	Err  error
}

func (e *TPMError) Error() string { return "harness: " + e.Step + ": " + e.Err.Error() }
func (e *TPMError) Unwrap() error { return e.Err }

// SerialError reports an unreadable serial transcript.
type SerialError struct {
	Path string
	Err  error
}

func (e *SerialError) Error() string {
	return "harness: reading serial transcript " + e.Path + ": " + e.Err.Error()
}
func (e *SerialError) Unwrap() error { return e.Err }

// SerialTimeoutError reports a milestone the guest never printed; Tail is
// the end of what it did print.
type SerialTimeoutError struct {
	Path   string
	Needle string
	Tail   string
}

func (e *SerialTimeoutError) Error() string {
	return "harness: timed out waiting for " + quote(e.Needle) + " in " + e.Path + "; transcript ends with:\n" + e.Tail
}

// ConsoleError reports a failed console operation.
type ConsoleError struct {
	Op  string
	Err error
}

func (e *ConsoleError) Error() string { return "harness: console: " + e.Op + ": " + e.Err.Error() }
func (e *ConsoleError) Unwrap() error { return e.Err }

// ConsoleTimeoutError reports output the console never produced;
// Transcript is what it did produce.
type ConsoleTimeoutError struct {
	Needle     string
	Transcript string
}

func (e *ConsoleTimeoutError) Error() string {
	return "harness: console: timed out waiting for " + quote(e.Needle) + "; received:\n" + e.Transcript
}

// quote wraps s in double quotes without importing strconv for it.
func quote(s string) string { return `"` + s + `"` }
