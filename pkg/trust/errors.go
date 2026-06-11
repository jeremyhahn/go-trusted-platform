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
// ErrClassNotConfigured and ErrPlatformCAUnavailable are additionally aliased
// to their generic counterparts below so that errors.As traversals on errors
// returned by the generic resolver also match the platform names.
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

// ErrPlatformCAUnavailable indicates the platform-ca strategy was
// requested but no CABundleProvider was injected.
//
// This is the platform-named alias of the generic ErrProviderCAUnavailable.
// Both names trigger errors.Is correctly because the underlying value is
// the same xkmsresolver type.
type ErrPlatformCAUnavailable = xkmsresolver.ErrProviderCAUnavailable

// ErrProviderCAUnavailable is re-exported so call sites that use the
// generic name also compile without change.
type ErrProviderCAUnavailable = xkmsresolver.ErrProviderCAUnavailable

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
