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

package platform

import "fmt"

var (
	// ErrNilConfig is returned when a nil configuration is provided.
	ErrNilConfig = fmt.Errorf("platform registry: configuration is required")

	// ErrNilLogger is returned when a nil logger is provided.
	ErrNilLogger = fmt.Errorf("platform registry: logger is required")
)

// ErrRegistryClosed is returned when operations are attempted on a closed registry.
type ErrRegistryClosed struct{}

func (e ErrRegistryClosed) Error() string {
	return "platform registry: registry is closed"
}

// ErrRegistryNotStarted is returned when services are accessed before Start().
type ErrRegistryNotStarted struct{}

func (e ErrRegistryNotStarted) Error() string {
	return "platform registry: registry is not started"
}

// ErrAdapterCreationFailed is returned when an SDK adapter fails to create.
type ErrAdapterCreationFailed struct {
	Adapter string
	Cause   error
}

func (e ErrAdapterCreationFailed) Error() string {
	return fmt.Sprintf("platform registry: failed to create %s adapter: %v", e.Adapter, e.Cause)
}

func (e ErrAdapterCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrAdapterStartFailed is returned when an SDK adapter fails to start.
type ErrAdapterStartFailed struct {
	Adapter string
	Cause   error
}

func (e ErrAdapterStartFailed) Error() string {
	return fmt.Sprintf("platform registry: failed to start %s adapter: %v", e.Adapter, e.Cause)
}

func (e ErrAdapterStartFailed) Unwrap() error {
	return e.Cause
}

// ErrAdapterNotConfigured is returned when attempting to access an unconfigured adapter.
type ErrAdapterNotConfigured struct {
	Adapter string
}

func (e ErrAdapterNotConfigured) Error() string {
	return fmt.Sprintf("platform registry: %s adapter is not configured", e.Adapter)
}

// ErrPlatformPolicyFailed is returned when the platform policy digest cannot be retrieved.
type ErrPlatformPolicyFailed struct {
	Cause error
}

func (e ErrPlatformPolicyFailed) Error() string {
	return fmt.Sprintf("platform: failed to retrieve platform policy digest: %v", e.Cause)
}

func (e ErrPlatformPolicyFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceUnavailable is returned when a service is temporarily unavailable.
type ErrServiceUnavailable struct {
	Service string
	Reason  string
}

func (e ErrServiceUnavailable) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("platform registry: service %s is unavailable: %s", e.Service, e.Reason)
	}
	return fmt.Sprintf("platform registry: service %s is unavailable", e.Service)
}
