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
