// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package trust

import (
	"fmt"
	"strings"

	xkmsresolver "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/resolver"
)

// =============================================================================
// Type aliases for generic resolver errors
//
// All call sites that use errors.As / errors.Is with these types keep
// working unchanged because the underlying concrete type is the same.
// =============================================================================

// ErrFetchFailed indicates a CA bundle fetch strategy failed.
type ErrFetchFailed = xkmsresolver.ErrFetchFailed

// ErrCABundleEmpty indicates a fetched or provided CA bundle contained
// no data.
type ErrCABundleEmpty = xkmsresolver.ErrCABundleEmpty

// ErrCABundleParse indicates a CA bundle contained no parseable PEM
// certificates.
type ErrCABundleParse = xkmsresolver.ErrCABundleParse

// ErrWriteFailed indicates a filesystem write failed while installing a
// CA bundle.
type ErrWriteFailed = xkmsresolver.ErrWriteFailed

// ErrPinNotFound indicates no SPKI pin is available for the endpoint:
// the PinStore has no entry and the scope carries no static pin.
type ErrPinNotFound = xkmsresolver.ErrPinNotFound

// ErrCAFileRead indicates the ca-file strategy could not read its CA
// bundle file.
type ErrCAFileRead = xkmsresolver.ErrCAFileRead

// ErrEndpointInvalid indicates the caller-supplied endpoint (or the
// scope's server-url fallback) could not be parsed into host and port.
type ErrEndpointInvalid = xkmsresolver.ErrEndpointInvalid

// ErrTOFUPinStoreRequired indicates the tofu strategy was configured but
// no TOFUPinStore was injected at construction time.
type ErrTOFUPinStoreRequired = xkmsresolver.ErrTOFUPinStoreRequired

// Attempt records the outcome of a single strategy attempt within a
// resolution chain.
type Attempt = xkmsresolver.Attempt

// =============================================================================
// Platform-specific errors
//
// These exist either because they have no generic equivalent (ErrNilConfig,
// ErrNilLogger) or because they carry the platform Class type instead of the
// generic scope string (ErrClassNotConfigured, ErrInvalidConfig,
// ErrStrategyNotAllowed, ErrNoStrategySucceeded).
//
// ErrClassNotConfigured is additionally aliased to its generic counterpart
// below so that errors.As traversals on errors returned by the generic
// resolver also match the platform name.
// =============================================================================

// ErrNilConfig indicates a nil *Config was passed to NewResolver.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "trust: config is required"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrNilConfig) Is(target error) bool {
	_, ok := target.(ErrNilConfig)
	return ok
}

// ErrNilLogger indicates a nil logger was passed to NewResolver.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "trust: logger is required"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrNilLogger) Is(target error) bool {
	_, ok := target.(ErrNilLogger)
	return ok
}

// ErrClassNotConfigured indicates the requested trust class has no
// ScopeConfig. It is also exposed as an alias for ErrScopeNotConfigured
// so that call sites using either type work correctly.
type ErrClassNotConfigured struct {
	Class Class
}

func (e *ErrClassNotConfigured) Error() string {
	return fmt.Sprintf("trust: class %q is not configured", e.Class)
}

// ErrScopeNotConfigured is a type alias for ErrClassNotConfigured so
// that errors.As against either name succeeds.
type ErrScopeNotConfigured = ErrClassNotConfigured

// ErrInvalidConfig indicates a scope configuration field is missing or
// malformed.
type ErrInvalidConfig struct {
	Class  Class
	Field  string
	Reason string
}

func (e *ErrInvalidConfig) Error() string {
	return fmt.Sprintf("trust: invalid config for class %q field %q: %s", e.Class, e.Field, e.Reason)
}

// ErrStrategyNotAllowed indicates a strategy appears in a class's chain
// that the class does not permit.
type ErrStrategyNotAllowed struct {
	Class    Class
	Strategy Strategy
}

func (e *ErrStrategyNotAllowed) Error() string {
	return fmt.Sprintf("trust: strategy %q is not allowed for class %q", e.Strategy, e.Class)
}

// ErrNoStrategySucceeded indicates every strategy in a class's chain
// failed. Attempts records each failure in chain order.
type ErrNoStrategySucceeded struct {
	Class    Class
	Endpoint string
	Attempts []Attempt
}

func (e *ErrNoStrategySucceeded) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "trust: no strategy succeeded for class %q", e.Class)
	if e.Endpoint != "" {
		fmt.Fprintf(&b, " endpoint %q", e.Endpoint)
	}
	for _, attempt := range e.Attempts {
		fmt.Fprintf(&b, "; %s: %v", attempt.Strategy, attempt.Err)
	}
	return b.String()
}

// Unwrap returns each attempt's error so errors.Is and errors.As traverse
// the full chain.
func (e *ErrNoStrategySucceeded) Unwrap() []error {
	errs := make([]error, 0, len(e.Attempts))
	for _, attempt := range e.Attempts {
		if attempt.Err != nil {
			errs = append(errs, attempt.Err)
		}
	}
	return errs
}

// ErrNilAnchorSource indicates NewAnchor was given no AnchorSource. An
// anchor with nothing behind it could only ever refuse, so it is not built.
type ErrNilAnchorSource struct{}

// Error implements the error interface.
func (e ErrNilAnchorSource) Error() string {
	return "trust: platform anchor requires a source"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrNilAnchorSource) Is(target error) bool {
	_, ok := target.(ErrNilAnchorSource)
	return ok
}

// ErrAnchorUnavailable indicates the platform anchor could not be read from
// its source: the control plane's CA is not initialised, a node has not
// enrolled yet (so it holds no IDevID issuing chain), or a provisioned bundle
// file is missing or unreadable. Cause says which.
type ErrAnchorUnavailable struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrAnchorUnavailable) Error() string {
	return fmt.Sprintf("trust: platform anchor unavailable: %v", e.Cause)
}

// Unwrap returns the source's error.
func (e *ErrAnchorUnavailable) Unwrap() error { return e.Cause }

// ErrAnchorEmpty indicates the platform anchor's source yielded no CA
// certificate. A pool with no roots verifies nothing, so it is refused
// rather than returned.
type ErrAnchorEmpty struct{}

// Error implements the error interface.
func (e ErrAnchorEmpty) Error() string {
	return "trust: platform anchor source yielded no CA certificate"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrAnchorEmpty) Is(target error) bool {
	_, ok := target.(ErrAnchorEmpty)
	return ok
}

// ErrAnchorFileUnset indicates a FileAnchorSource was constructed with no
// path, so it can never answer.
type ErrAnchorFileUnset struct{}

// Error implements the error interface.
func (e ErrAnchorFileUnset) Error() string {
	return "trust: platform anchor bundle file has no configured path"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrAnchorFileUnset) Is(target error) bool {
	_, ok := target.(ErrAnchorFileUnset)
	return ok
}
