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

package health

import "fmt"

// ErrHealthCheckFailed is returned when a health check fails to complete successfully.
type ErrHealthCheckFailed struct {
	Component string
	Cause     error
}

func (e ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("health check failed for component %q: %v", e.Component, e.Cause)
	}
	return fmt.Sprintf("health check failed for component %q", e.Component)
}

func (e ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}

// ErrComponentNotFound is returned when attempting to access a component that is not registered.
type ErrComponentNotFound struct {
	Name string
}

func (e ErrComponentNotFound) Error() string {
	return fmt.Sprintf("component not found: %q", e.Name)
}

// ErrCheckerNotRegistered is returned when a required health checker is not registered.
type ErrCheckerNotRegistered struct {
	Name string
}

func (e ErrCheckerNotRegistered) Error() string {
	return fmt.Sprintf("health checker not registered: %q", e.Name)
}

// ErrCheckTimeout is returned when a health check exceeds its timeout.
type ErrCheckTimeout struct {
	Component string
	Timeout   string
}

func (e ErrCheckTimeout) Error() string {
	return fmt.Sprintf("health check timeout for component %q after %s", e.Component, e.Timeout)
}

// ErrRegistryFull is returned when attempting to register a checker when the registry is at capacity.
type ErrRegistryFull struct {
	MaxCheckers int
}

func (e ErrRegistryFull) Error() string {
	return fmt.Sprintf("health registry full: maximum %d checkers allowed", e.MaxCheckers)
}

// ErrCheckerAlreadyRegistered is returned when attempting to register a checker with a name that already exists.
type ErrCheckerAlreadyRegistered struct {
	Name string
}

func (e ErrCheckerAlreadyRegistered) Error() string {
	return fmt.Sprintf("health checker already registered: %q", e.Name)
}

// ErrInvalidCheckerName is returned when a checker name is invalid.
type ErrInvalidCheckerName struct {
	Name   string
	Reason string
}

func (e ErrInvalidCheckerName) Error() string {
	return fmt.Sprintf("invalid health checker name %q: %s", e.Name, e.Reason)
}

// ErrConnectionFailed is returned when a health checker cannot connect to its target.
type ErrConnectionFailed struct {
	Component string
	Target    string
	Cause     error
}

func (e ErrConnectionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("connection failed for %q to %q: %v", e.Component, e.Target, e.Cause)
	}
	return fmt.Sprintf("connection failed for %q to %q", e.Component, e.Target)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrResourceUnavailable is returned when a required resource is unavailable.
type ErrResourceUnavailable struct {
	Resource string
	Reason   string
}

func (e ErrResourceUnavailable) Error() string {
	return fmt.Sprintf("resource unavailable: %s: %s", e.Resource, e.Reason)
}

// ErrRegistryClosed is returned when operations are attempted on a closed registry.
type ErrRegistryClosed struct{}

func (e ErrRegistryClosed) Error() string {
	return "health registry is closed"
}

// ErrInvalidThreshold is returned when threshold configuration is invalid.
type ErrInvalidThreshold struct {
	Field  string
	Reason string
}

func (e ErrInvalidThreshold) Error() string {
	return fmt.Sprintf("invalid threshold for %s: %s", e.Field, e.Reason)
}

// ErrProbeNotConfigured is returned when a probe is accessed but not configured.
type ErrProbeNotConfigured struct {
	ProbeType ProbeType
}

func (e ErrProbeNotConfigured) Error() string {
	return fmt.Sprintf("probe not configured: %s", e.ProbeType)
}
