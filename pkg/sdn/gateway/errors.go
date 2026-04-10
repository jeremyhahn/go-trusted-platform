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

// ErrModeNotSupported is returned when a gateway mode is not supported.
type ErrModeNotSupported struct {
	Mode GatewayMode
}

func (e *ErrModeNotSupported) Error() string {
	return fmt.Sprintf("gateway mode not supported: %s", e.Mode)
}

// ErrModeActivationFailed is returned when mode activation fails.
type ErrModeActivationFailed struct {
	Mode  GatewayMode
	Cause error
}

func (e *ErrModeActivationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to activate gateway mode %s: %v", e.Mode, e.Cause)
	}
	return fmt.Sprintf("failed to activate gateway mode %s", e.Mode)
}

func (e *ErrModeActivationFailed) Unwrap() error {
	return e.Cause
}

// ErrModeDeactivationFailed is returned when mode deactivation fails.
type ErrModeDeactivationFailed struct {
	Mode  GatewayMode
	Cause error
}

func (e *ErrModeDeactivationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to deactivate gateway mode %s: %v", e.Mode, e.Cause)
	}
	return fmt.Sprintf("failed to deactivate gateway mode %s", e.Mode)
}

func (e *ErrModeDeactivationFailed) Unwrap() error {
	return e.Cause
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

// ErrModeNotActive is returned when an operation requires a mode that is not active.
type ErrModeNotActive struct {
	Mode GatewayMode
}

func (e *ErrModeNotActive) Error() string {
	return fmt.Sprintf("gateway mode not active: %s", e.Mode)
}

// ErrModeAlreadyActive is returned when trying to activate an already active mode.
type ErrModeAlreadyActive struct {
	Mode GatewayMode
}

func (e *ErrModeAlreadyActive) Error() string {
	return fmt.Sprintf("gateway mode already active: %s", e.Mode)
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
