package quirks

import "fmt"

// ErrUnknownManufacturer is returned when Resolve is called with an empty
// manufacturer string and no default can be found. In practice Resolve always
// falls back to Default(), so callers never receive this error from the public
// API; it exists for internal validation helpers.
type ErrUnknownManufacturer struct {
	Manufacturer string
}

func (e *ErrUnknownManufacturer) Error() string {
	return fmt.Sprintf("quirks: unknown manufacturer %q; using generic defaults", e.Manufacturer)
}
