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

import "context"

// StartStopper is the part of an orchestrator Reboot needs.
type StartStopper interface {
	Start(ctx context.Context, instanceID string) error
	Stop(ctx context.Context, instanceID string) error
}

// Reboot restarts an instance by stopping it and starting it again. Every
// protocol surface reboots through it so they all behave the same. The
// returned error keeps the orchestrator's sentinel for errors.Is.
func Reboot(ctx context.Context, o StartStopper, instanceID string) error {
	return RebootWithOptions(ctx, o, instanceID, StopOptions{})
}

// RebootWithOptions is Reboot with the stop half run under opts, so a forced
// reboot kills the instance instead of waiting for the guest to power down.
func RebootWithOptions(ctx context.Context, o StartStopper, instanceID string, opts StopOptions) error {
	if err := StopWithOptions(ctx, o, instanceID, opts); err != nil {
		return &WrappedError{Msg: "failed to stop instance for reboot", Err: err}
	}
	if err := o.Start(ctx, instanceID); err != nil {
		return &WrappedError{Msg: "failed to start instance for reboot", Err: err}
	}
	return nil
}
