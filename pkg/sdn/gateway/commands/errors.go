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

package commands

import "errors"

var (
	// ErrMissingBGPConfig is returned when BGP configuration is required but not provided.
	ErrMissingBGPConfig = errors.New("gatewayd: missing BGP configuration")

	// ErrGatewayStartFailed is returned when the gateway fails to start.
	ErrGatewayStartFailed = errors.New("gatewayd: failed to start gateway")

	// ErrGatewayShutdownFailed is returned when the gateway fails to shutdown gracefully.
	ErrGatewayShutdownFailed = errors.New("gatewayd: failed to shutdown gateway gracefully")

	// ErrConfigLoadFailed is returned when the gateway configuration cannot be loaded.
	ErrConfigLoadFailed = errors.New("gatewayd: failed to load configuration")
)

// ErrNothingEnabled is returned when neither the gateway nor the proxy
// section enables any service.
var ErrNothingEnabled = errors.New("gatewayd: no services enabled in configuration")

// ErrGatewayDisabled is returned when the gateway section is explicitly
// disabled while the proxy section is enabled; the proxy service runs
// inside the gateway node and requires it.
var ErrGatewayDisabled = errors.New("gatewayd: gateway section disabled; the proxy service requires an enabled gateway")

// ErrTrustRequiredForGRPC is returned when the platformd connection uses
// the grpc protocol without a configured trust: section to anchor TLS
// verification.
var ErrTrustRequiredForGRPC = errors.New("gatewayd: platformd grpc protocol requires a configured trust: section")

// ErrConfigSection wraps a configuration-section unmarshal failure.
type ErrConfigSection struct {
	// Section is the top-level configuration key.
	Section string
	// Cause is the underlying decode error.
	Cause error
}

// Error implements the error interface.
func (e *ErrConfigSection) Error() string {
	return "gatewayd: parsing configuration section " + e.Section + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrConfigSection) Unwrap() error { return e.Cause }
