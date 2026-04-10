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

package barrier

import "fmt"

// ErrBarrierInitFailed is returned when barrier initialization fails.
type ErrBarrierInitFailed struct {
	Err error
}

func (e ErrBarrierInitFailed) Error() string {
	return fmt.Sprintf("barrier initialization failed: %v", e.Err)
}

// ErrBarrierStatusFailed is returned when barrier status retrieval fails.
type ErrBarrierStatusFailed struct {
	Err error
}

func (e ErrBarrierStatusFailed) Error() string {
	return fmt.Sprintf("failed to get barrier status: %v", e.Err)
}

// ErrBarrierUnsealFailed is returned when barrier unseal fails.
type ErrBarrierUnsealFailed struct {
	Err error
}

func (e ErrBarrierUnsealFailed) Error() string {
	return fmt.Sprintf("barrier unseal failed: %v", e.Err)
}

// ErrBarrierSealFailed is returned when barrier seal fails.
type ErrBarrierSealFailed struct {
	Err error
}

func (e ErrBarrierSealFailed) Error() string {
	return fmt.Sprintf("barrier seal failed: %v", e.Err)
}

// ErrBarrierRekeyFailed is returned when barrier rekey fails.
type ErrBarrierRekeyFailed struct {
	Err error
}

func (e ErrBarrierRekeyFailed) Error() string {
	return fmt.Sprintf("barrier rekey failed: %v", e.Err)
}

// ErrInvalidThreshold is returned when the threshold value is invalid.
type ErrInvalidThreshold struct {
	Threshold int32
	Shares    int32
}

func (e ErrInvalidThreshold) Error() string {
	return fmt.Sprintf("invalid threshold: threshold (%d) must be <= shares (%d)", e.Threshold, e.Shares)
}

// ErrInvalidShares is returned when the shares value is invalid.
type ErrInvalidShares struct {
	Shares int32
}

func (e ErrInvalidShares) Error() string {
	return fmt.Sprintf("invalid shares: must be >= 1, got %d", e.Shares)
}

// ErrMissingSecret is returned when a required secret is not provided.
type ErrMissingSecret struct{}

func (e ErrMissingSecret) Error() string {
	return "secret is required: provide --secret flag"
}
