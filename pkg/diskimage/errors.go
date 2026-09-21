package diskimage

// UnknownTargetError reports a --target this builder has no entry for.
type UnknownTargetError struct {
	Target  string
	Targets []string
}

// Error implements error.
func (e *UnknownTargetError) Error() string {
	msg := "diskimage: unknown target " + e.Target + " (known:"
	for _, t := range e.Targets {
		msg += " " + t
	}
	return msg + ")"
}

// PreflightError reports a build-host requirement that is not met, with
// the remedy.
type PreflightError struct {
	Check  string
	Remedy string
}

// Error implements error.
func (e *PreflightError) Error() string {
	return "diskimage: " + e.Check + " (" + e.Remedy + ")"
}

// StageError reports a failure while preparing the media the installer
// consumes.
type StageError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *StageError) Error() string {
	return "diskimage: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *StageError) Unwrap() error { return e.Err }

// AssembleError reports a failure inside the container while the installer
// is laying out the image.
type AssembleError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *AssembleError) Error() string {
	return "diskimage: assemble: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *AssembleError) Unwrap() error { return e.Err }

// LoopDeviceError reports a failure obtaining or naming the loop device the
// image is attached to.
type LoopDeviceError struct {
	Op  string
	Err error
}

// Error implements error.
func (e *LoopDeviceError) Error() string {
	return "diskimage: loop device: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *LoopDeviceError) Unwrap() error { return e.Err }

// InspectError reports an image that cannot be read or is not a platform
// image.
type InspectError struct {
	Path   string
	Reason string
	Err    error
}

// Error implements error.
func (e *InspectError) Error() string {
	msg := "diskimage: inspect " + e.Path + ": " + e.Reason
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying error.
func (e *InspectError) Unwrap() error { return e.Err }

// BootError reports a failed step of Boot, the emulated boot of an image.
type BootError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *BootError) Error() string {
	return "diskimage: boot: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *BootError) Unwrap() error { return e.Err }
