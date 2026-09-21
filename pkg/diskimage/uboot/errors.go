package uboot

// ArtifactMissingError reports a U-Boot build output that is not where the
// builder writes it; Hint names the make target that produces it.
type ArtifactMissingError struct {
	Path string
	Hint string
}

// Error implements error.
func (e *ArtifactMissingError) Error() string {
	return "uboot: artifact " + e.Path + " is missing (" + e.Hint + ")"
}

// ChecksumMismatchError reports an artifact whose SHA256SUMS entry does not
// match its content, or an artifact that has no entry at all.
type ChecksumMismatchError struct {
	Path   string
	Reason string
}

// Error implements error.
func (e *ChecksumMismatchError) Error() string {
	return "uboot: " + e.Path + ": " + e.Reason
}

// ManifestError reports an unreadable or inconsistent manifest.json.
type ManifestError struct {
	Path string
	Err  error
}

// Error implements error.
func (e *ManifestError) Error() string {
	return "uboot: manifest " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ManifestError) Unwrap() error { return e.Err }

// InputError reports a build input (certificate, fragment, overlay source)
// that cannot be read.
type InputError struct {
	Path string
	Err  error
}

// Error implements error.
func (e *InputError) Error() string {
	return "uboot: build input " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *InputError) Unwrap() error { return e.Err }

// BuildError reports a failed container build or run step.
type BuildError struct {
	Step string
	Err  error
}

// Error implements error.
func (e *BuildError) Error() string {
	return "uboot: " + e.Step + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *BuildError) Unwrap() error { return e.Err }
