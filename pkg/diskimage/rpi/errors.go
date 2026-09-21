package rpi

// UnknownModelError reports a Raspberry Pi model this target has no entry for.
type UnknownModelError struct {
	Model  string
	Models []string
}

// Error implements error.
func (e *UnknownModelError) Error() string {
	msg := "rpi: unknown model " + e.Model + " (known:"
	for _, m := range e.Models {
		msg += " " + m
	}
	return msg + ")"
}

// PackageMissingError reports a prefetched apk the target needs but the
// media does not carry.
type PackageMissingError struct {
	Package string
	Dir     string
}

// Error implements error.
func (e *PackageMissingError) Error() string {
	return "rpi: package " + e.Package + " is not in the prefetched repository " + e.Dir + " (is it in the target's extra packages?)"
}

// PackageError reports an unreadable or malformed apk.
type PackageError struct {
	Package string
	Err     error
}

// Error implements error.
func (e *PackageError) Error() string {
	return "rpi: package " + e.Package + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *PackageError) Unwrap() error { return e.Err }

// FirmwareMissingError reports a boot file the Pi firmware needs that no
// package or U-Boot artifact provided.
type FirmwareMissingError struct {
	File string
}

// Error implements error.
func (e *FirmwareMissingError) Error() string {
	return "rpi: boot firmware file " + e.File + " was not produced"
}

// StageError reports a failure while laying out the boot-firmware directory.
type StageError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *StageError) Error() string {
	return "rpi: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *StageError) Unwrap() error { return e.Err }
