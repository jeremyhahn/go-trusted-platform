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

import "time"

// DefaultStopTimeout is how long a graceful stop or reboot gives the guest to
// power down when the request carries no timeout (docs/compute/api.md §2).
const DefaultStopTimeout = 30 * time.Second

// StopReplyMargin is the time a stop or reboot gets beyond the guest's
// power-down window to answer: the process exit, a reboot's start and the
// reply itself.
const StopReplyMargin = 30 * time.Second

// StopGuestWait is the longest a stop waits for the guest to power down
// before it terminates it: nothing when forced, otherwise timeoutSeconds or
// DefaultStopTimeout.
func StopGuestWait(force bool, timeoutSeconds uint32) time.Duration {
	switch {
	case force:
		return 0
	case timeoutSeconds > 0:
		return time.Duration(timeoutSeconds) * time.Second
	default:
		return DefaultStopTimeout
	}
}

// StopReplyWindow is the longest a stop or reboot takes to answer: the
// guest's power-down window plus StopReplyMargin. The daemon holds a stop's
// reply open this long, and a client waits this long for it.
func StopReplyWindow(force bool, timeoutSeconds uint32) time.Duration {
	return StopGuestWait(force, timeoutSeconds) + StopReplyMargin
}
