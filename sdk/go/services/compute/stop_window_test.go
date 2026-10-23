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
	"testing"
	"time"
)

func TestStopReplyWindow(t *testing.T) {
	tests := []struct {
		name           string
		force          bool
		timeoutSeconds uint32
		wantGuestWait  time.Duration
		wantWindow     time.Duration
	}{
		{"default stop waits the default", false, 0, 30 * time.Second, time.Minute},
		{"timeout replaces the default", false, 120, 2 * time.Minute, 150 * time.Second},
		{"forced stop does not wait", true, 0, 0, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StopGuestWait(tt.force, tt.timeoutSeconds); got != tt.wantGuestWait {
				t.Errorf("StopGuestWait() = %v, want %v", got, tt.wantGuestWait)
			}
			if got := StopReplyWindow(tt.force, tt.timeoutSeconds); got != tt.wantWindow {
				t.Errorf("StopReplyWindow() = %v, want %v", got, tt.wantWindow)
			}
		})
	}
}

// A forced stop that also carries a timeout is refused by the daemon; the
// window still never waits for the guest, so a client is not held longer.
func TestStopReplyWindowForcedIgnoresTimeout(t *testing.T) {
	if got := StopReplyWindow(true, 600); got != StopReplyMargin {
		t.Errorf("StopReplyWindow(force, 600) = %v, want %v", got, StopReplyMargin)
	}
}
