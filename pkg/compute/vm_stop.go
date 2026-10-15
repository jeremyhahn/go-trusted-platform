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

package compute

import (
	"context"
	"errors"
	"time"
)

// MaxStopTimeout bounds StopOptions.Timeout. The instance stays locked while
// its guest is given time to power down, so the wait cannot be unbounded.
const MaxStopTimeout = time.Hour

// ErrInvalidStopOptions is returned when StopOptions carry a value no
// orchestrator can honour.
var ErrInvalidStopOptions = errors.New("invalid stop options")

// StopOptions tunes how an instance is powered off. The zero value is the
// orchestrator's default stop.
type StopOptions struct {
	// Force kills the instance at once instead of asking the guest to
	// power down.
	Force bool

	// Timeout is how long the guest gets to power down before it is
	// terminated. Zero means the orchestrator default.
	Timeout time.Duration
}

// IsDefault reports whether opts asks for nothing beyond a default stop.
func (opts StopOptions) IsDefault() bool {
	return opts == StopOptions{}
}

// Validate refuses a negative or over-long timeout, and a timeout on a
// forced stop, which does not wait for the guest at all.
func (opts StopOptions) Validate() error {
	switch {
	case opts.Timeout < 0:
		return &SentinelCauseError{Sentinel: ErrInvalidStopOptions, Cause: &MessageError{Msg: "timeout must not be negative"}}
	case opts.Timeout > MaxStopTimeout:
		return &SentinelCauseError{Sentinel: ErrInvalidStopOptions, Cause: &MessageError{Msg: "timeout must not exceed " + MaxStopTimeout.String()}}
	case opts.Force && opts.Timeout > 0:
		return &SentinelCauseError{Sentinel: ErrInvalidStopOptions, Cause: &MessageError{Msg: "a forced stop does not wait, so it takes no timeout"}}
	}
	return nil
}

// VMStopper is implemented by orchestrators that can honour StopOptions.
// The QEMU orchestrator kills the process for a forced stop and otherwise
// gives the guest the timeout to answer the ACPI power button.
type VMStopper interface {
	StopWithOptions(ctx context.Context, instanceID string, opts StopOptions) error
}

// StopWithOptions stops an instance under opts. An orchestrator without
// VMStopper can only do a default stop; anything else is refused with
// ErrUnsupportedOperation rather than silently ignored.
func StopWithOptions(ctx context.Context, o StartStopper, instanceID string, opts StopOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	if stopper, ok := o.(VMStopper); ok {
		return stopper.StopWithOptions(ctx, instanceID, opts)
	}
	if !opts.IsDefault() {
		return &SentinelCauseError{Sentinel: ErrUnsupportedOperation, Cause: &MessageError{Msg: "stop options are not supported by this compute orchestrator"}}
	}
	return o.Stop(ctx, instanceID)
}
