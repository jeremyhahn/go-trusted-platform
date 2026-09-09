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

package gateway

import (
	"fmt"
	"time"
)

// Sentinel errors for gateway operations.
var (
	// ErrGatewayNotFound is returned when a gateway is not found.
	ErrGatewayNotFound = &errGatewayNotFound{}

	// ErrGatewayAlreadyExists is returned when a gateway already exists.
	ErrGatewayAlreadyExists = &errGatewayAlreadyExists{}

	// ErrGatewayNotRunning is returned when operations require a running gateway.
	ErrGatewayNotRunning = &errGatewayNotRunning{}

	// ErrGatewayAlreadyRunning is returned when start is called on a running gateway.
	ErrGatewayAlreadyRunning = &errGatewayAlreadyRunning{}

	// ErrConfigNil is returned when a nil configuration is provided.
	ErrConfigNil = &errConfigNil{}

	// ErrConfigurationInvalid is returned when configuration is invalid.
	ErrConfigurationInvalid = &errConfigurationInvalid{}

	// ErrUplinkNotFound is returned when an uplink port is not found.
	ErrUplinkNotFound = &errUplinkNotFound{}

	// ErrIPv6PoolExhausted is returned when the IPv6 address pool is exhausted.
	ErrIPv6PoolExhausted = &errIPv6PoolExhausted{}

	// ErrIPv4PoolExhausted is returned when the IPv4 address pool is exhausted.
	ErrIPv4PoolExhausted = &errIPv4PoolExhausted{}

	// ErrShutdownTimeout is returned when graceful shutdown times out.
	ErrShutdownTimeout = &errShutdownTimeout{}

	// ErrBGPSpeakerNil is returned when the BGP speaker is nil.
	ErrBGPSpeakerNil = &errBGPSpeakerNil{}

	// ErrLoggerNil is returned when a nil logger is provided.
	ErrLoggerNil = &errLoggerNil{}

	// ErrNoServicesEnabled is returned when no services are enabled in the config.
	ErrNoServicesEnabled = &errNoServicesEnabled{}
)

type errGatewayNotFound struct{}

func (e *errGatewayNotFound) Error() string { return "gateway not found" }

type errGatewayAlreadyExists struct{}

func (e *errGatewayAlreadyExists) Error() string { return "gateway already exists" }

type errGatewayNotRunning struct{}

func (e *errGatewayNotRunning) Error() string { return "gateway not running" }

type errGatewayAlreadyRunning struct{}

func (e *errGatewayAlreadyRunning) Error() string { return "gateway already running" }

type errConfigNil struct{}

func (e *errConfigNil) Error() string { return "configuration is nil" }

type errConfigurationInvalid struct{}

func (e *errConfigurationInvalid) Error() string { return "invalid configuration" }

type errUplinkNotFound struct{}

func (e *errUplinkNotFound) Error() string { return "uplink port not found" }

type errIPv6PoolExhausted struct{}

func (e *errIPv6PoolExhausted) Error() string { return "IPv6 address pool exhausted" }

type errIPv4PoolExhausted struct{}

func (e *errIPv4PoolExhausted) Error() string { return "IPv4 address pool exhausted" }

type errShutdownTimeout struct{}

func (e *errShutdownTimeout) Error() string { return "shutdown timeout exceeded" }

type errBGPSpeakerNil struct{}

func (e *errBGPSpeakerNil) Error() string { return "BGP speaker is nil" }

type errLoggerNil struct{}

func (e *errLoggerNil) Error() string { return "logger is nil" }

type errNoServicesEnabled struct{}

func (e *errNoServicesEnabled) Error() string { return "no services enabled in gateway configuration" }

// ErrServiceStartFailed is returned when a service handler fails to start.
type ErrServiceStartFailed struct {
	Service string
	Cause   error
}

func (e *ErrServiceStartFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to start service %s: %v", e.Service, e.Cause)
	}
	return fmt.Sprintf("failed to start service %s", e.Service)
}

func (e *ErrServiceStartFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceStopFailed is returned when a service handler fails to stop.
type ErrServiceStopFailed struct {
	Service string
	Cause   error
}

func (e *ErrServiceStopFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to stop service %s: %v", e.Service, e.Cause)
	}
	return fmt.Sprintf("failed to stop service %s", e.Service)
}

func (e *ErrServiceStopFailed) Unwrap() error {
	return e.Cause
}

// ErrServiceAlreadyActive is returned when trying to start an already active service.
type ErrServiceAlreadyActive struct {
	Service string
}

func (e *ErrServiceAlreadyActive) Error() string {
	return fmt.Sprintf("service already active: %s", e.Service)
}

// ErrServiceNotActive is returned when an operation requires a service that is not active.
type ErrServiceNotActive struct {
	Service string
}

func (e *ErrServiceNotActive) Error() string {
	return fmt.Sprintf("service not active: %s", e.Service)
}

// ErrReputationTooLow is returned when node reputation is below the minimum.
type ErrReputationTooLow struct {
	Required float64
	Actual   float64
}

func (e *ErrReputationTooLow) Error() string {
	return fmt.Sprintf("reputation too low: required %.2f, actual %.2f", e.Required, e.Actual)
}

// ErrAgeTooYoung is returned when node age is below the minimum.
type ErrAgeTooYoung struct {
	RequiredDays int
	ActualDays   int
}

func (e *ErrAgeTooYoung) Error() string {
	return fmt.Sprintf("node age too young: required %d days, actual %d days", e.RequiredDays, e.ActualDays)
}

// ErrUptimeTooLow is returned when node uptime is below the minimum.
type ErrUptimeTooLow struct {
	RequiredPct float64
	ActualPct   float64
}

func (e *ErrUptimeTooLow) Error() string {
	return fmt.Sprintf("uptime too low: required %.1f%%, actual %.1f%%", e.RequiredPct, e.ActualPct)
}

// ErrOnboardingFailed is returned when gateway onboarding fails.
type ErrOnboardingFailed struct {
	GatewayID string
	Cause     error
}

func (e *ErrOnboardingFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("gateway onboarding failed for %s: %v", e.GatewayID, e.Cause)
	}
	return fmt.Sprintf("gateway onboarding failed for %s", e.GatewayID)
}

func (e *ErrOnboardingFailed) Unwrap() error {
	return e.Cause
}

// ErrHealthCheckFailed is returned when a health check fails.
type ErrHealthCheckFailed struct {
	GatewayID string
	Reason    string
	Cause     error
}

func (e *ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("health check failed for gateway %s: %s: %v", e.GatewayID, e.Reason, e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("health check failed for gateway %s: %s", e.GatewayID, e.Reason)
	}
	return fmt.Sprintf("health check failed for gateway %s", e.GatewayID)
}

func (e *ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}

// ErrUplinkOperationFailed is returned when an uplink operation fails.
type ErrUplinkOperationFailed struct {
	UplinkName string
	Operation  string
	Cause      error
}

func (e *ErrUplinkOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("uplink %s operation %q failed: %v", e.UplinkName, e.Operation, e.Cause)
	}
	return fmt.Sprintf("uplink %s operation %q failed", e.UplinkName, e.Operation)
}

func (e *ErrUplinkOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrIPPoolOperationFailed is returned when an IP pool operation fails.
type ErrIPPoolOperationFailed struct {
	Pool      string
	Operation string
	Cause     error
}

func (e *ErrIPPoolOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("IP pool %s operation %q failed: %v", e.Pool, e.Operation, e.Cause)
	}
	return fmt.Sprintf("IP pool %s operation %q failed", e.Pool, e.Operation)
}

func (e *ErrIPPoolOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrGatewayOperationFailed is returned when a gateway operation fails.
type ErrGatewayOperationFailed struct {
	GatewayID string
	Operation string
	Cause     error
}

func (e *ErrGatewayOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("gateway %s operation %q failed: %v", e.GatewayID, e.Operation, e.Cause)
	}
	return fmt.Sprintf("gateway %s operation %q failed", e.GatewayID, e.Operation)
}

func (e *ErrGatewayOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrRequirementsNotMet is returned when gateway requirements are not met.
type ErrRequirementsNotMet struct {
	GatewayID string
	Checks    []RequirementCheck
}

func (e *ErrRequirementsNotMet) Error() string {
	if len(e.Checks) == 0 {
		return fmt.Sprintf("gateway %s: requirements not met", e.GatewayID)
	}
	return fmt.Sprintf("gateway %s: %d requirement(s) not met", e.GatewayID, len(e.Checks))
}

// RequirementCheck represents a single requirement check result.
type RequirementCheck struct {
	Name     string
	Required string
	Actual   string
	Passed   bool
}

// ErrStartupFailed is returned when gateway startup fails.
type ErrStartupFailed struct {
	GatewayID string
	Phase     string
	Cause     error
}

func (e *ErrStartupFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("gateway %s startup failed during %s: %v", e.GatewayID, e.Phase, e.Cause)
	}
	return fmt.Sprintf("gateway %s startup failed during %s", e.GatewayID, e.Phase)
}

func (e *ErrStartupFailed) Unwrap() error {
	return e.Cause
}

// ErrRollbackIncomplete reports a startup failure whose rollback also
// failed: Cause is what stopped the start, Rollback is what the rollback
// could not undo (a base pipeline left on the bridge). Both are named so
// the operator fixes the first and knows about the second.
type ErrRollbackIncomplete struct {
	Cause    error
	Rollback error
}

func (e *ErrRollbackIncomplete) Error() string {
	return fmt.Sprintf("%v (rollback incomplete: %v)", e.Cause, e.Rollback)
}

// Unwrap exposes both branches to errors.Is and errors.As: the failure
// that stopped the start and the failure that left the rollback undone.
func (e *ErrRollbackIncomplete) Unwrap() []error {
	return []error{e.Cause, e.Rollback}
}

// ErrShutdownFailed is returned when gateway shutdown fails.
type ErrShutdownFailed struct {
	GatewayID string
	Phase     string
	Cause     error
}

func (e *ErrShutdownFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("gateway %s shutdown failed during %s: %v", e.GatewayID, e.Phase, e.Cause)
	}
	return fmt.Sprintf("gateway %s shutdown failed during %s", e.GatewayID, e.Phase)
}

func (e *ErrShutdownFailed) Unwrap() error {
	return e.Cause
}

// ErrBGPOperationFailed is returned when a BGP operation fails.
type ErrBGPOperationFailed struct {
	Operation string
	Cause     error
}

func (e *ErrBGPOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("BGP operation %q failed: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("BGP operation %q failed", e.Operation)
}

func (e *ErrBGPOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrContextCanceled is returned when an operation is canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e *ErrContextCanceled) Error() string {
	return fmt.Sprintf("operation %q canceled", e.Operation)
}

// ErrTimeout is returned when an operation times out.
type ErrTimeout struct {
	Operation string
	Duration  time.Duration
}

func (e *ErrTimeout) Error() string {
	return fmt.Sprintf("operation %q timed out after %v", e.Operation, e.Duration)
}

// ErrInvalidState is returned when the gateway is in an invalid state for the operation.
type ErrInvalidState struct {
	Expected GatewayState
	Actual   GatewayState
}

func (e *ErrInvalidState) Error() string {
	return fmt.Sprintf("invalid gateway state: expected %s, got %s", e.Expected, e.Actual)
}

// ErrServiceNotFound is returned when a service is not found.
type ErrServiceNotFound struct {
	ServiceID string
}

func (e *ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceID)
}

// ErrServiceAlreadyExists is returned when a service already exists.
type ErrServiceAlreadyExists struct {
	ServiceID string
}

func (e *ErrServiceAlreadyExists) Error() string {
	return fmt.Sprintf("service already exists: %s", e.ServiceID)
}

// ErrDeviceNotFound is returned when a device is not found.
type ErrDeviceNotFound struct {
	DeviceID string
}

func (e *ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %s", e.DeviceID)
}

// ErrDeviceAlreadyExists is returned when a device already exists.
type ErrDeviceAlreadyExists struct {
	DeviceID string
}

func (e *ErrDeviceAlreadyExists) Error() string {
	return fmt.Sprintf("device already exists: %s", e.DeviceID)
}

// ErrCapacityExceeded is returned when capacity limits are exceeded.
type ErrCapacityExceeded struct {
	Resource string
	Limit    int
	Current  int
}

func (e *ErrCapacityExceeded) Error() string {
	return fmt.Sprintf("capacity exceeded for %s: limit %d, current %d", e.Resource, e.Limit, e.Current)
}

// ErrTunnelConfigInvalid is returned when tunnel configuration is invalid.
type ErrTunnelConfigInvalid struct {
	TunnelName string
	Reason     string
}

func (e *ErrTunnelConfigInvalid) Error() string {
	return fmt.Sprintf("invalid tunnel config %q: %s", e.TunnelName, e.Reason)
}

// ErrNilServiceHandler is returned when a nil or unnamed service handler is
// registered on a gateway.
type ErrNilServiceHandler struct{}

func (e *ErrNilServiceHandler) Error() string {
	return "gateway: nil or unnamed service handler"
}

// ErrServiceUnavailable is the start-time refusal for a config section the
// gateway cannot run: the section is enabled, no builder exists for it, and
// Reason names the blocker. It replaces the bool stubs that reported such
// services running (#568).
type ErrServiceUnavailable struct {
	Service string
	Reason  string
}

func (e *ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("gateway service %q is enabled but cannot run: %s", e.Service, e.Reason)
}

// ErrListenerInventory reports a listener address the host filter
// inventory could not turn into a rule.
type ErrListenerInventory struct {
	Listener string
	Address  string
	Cause    error
}

func (e *ErrListenerInventory) Error() string {
	return fmt.Sprintf("listener %q address %q: %v", e.Listener, e.Address, e.Cause)
}

func (e *ErrListenerInventory) Unwrap() error {
	return e.Cause
}

// ErrListenerPort reports a listener port that is not a 16-bit number.
type ErrListenerPort struct {
	Port string
}

func (e *ErrListenerPort) Error() string {
	return fmt.Sprintf("port %q out of range", e.Port)
}

// ErrHostFWConfigInvalid wraps a host filter configuration error with the
// section it came from.
type ErrHostFWConfigInvalid struct {
	Cause error
}

func (e *ErrHostFWConfigInvalid) Error() string {
	return fmt.Sprintf("gateway hostfw configuration invalid: %v", e.Cause)
}

func (e *ErrHostFWConfigInvalid) Unwrap() error {
	return e.Cause
}

// ErrServiceUnhealthy reports a supervised service whose owning process is
// down, failed its restart budget, or reports the service unhealthy (#557).
// Cause is the supervisor's own typed error.
type ErrServiceUnhealthy struct {
	Service string
	Cause   error
}

func (e *ErrServiceUnhealthy) Error() string {
	return fmt.Sprintf("gateway service %q is unhealthy: %v", e.Service, e.Cause)
}

func (e *ErrServiceUnhealthy) Unwrap() error {
	return e.Cause
}
