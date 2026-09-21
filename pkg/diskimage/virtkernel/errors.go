package virtkernel

// ManifestError reports an unreadable or inconsistent manifest.json.
type ManifestError struct {
	Path string
	Err  error
}

func (e *ManifestError) Error() string {
	return "virtkernel: manifest " + e.Path + ": " + e.Err.Error()
}
func (e *ManifestError) Unwrap() error { return e.Err }

// InputError reports a builder input that cannot be hashed into the cache key.
type InputError struct {
	Path string
	Err  error
}

func (e *InputError) Error() string { return "virtkernel: input " + e.Path + ": " + e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

// BuildError reports a failed step of Build.
type BuildError struct {
	Step string
	Err  error
}

func (e *BuildError) Error() string { return "virtkernel: " + e.Step + ": " + e.Err.Error() }
func (e *BuildError) Unwrap() error { return e.Err }
