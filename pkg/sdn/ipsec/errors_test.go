// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"errors"
	"testing"
)

func TestErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	for _, tt := range []struct {
		err  error
		want string
	}{
		{&PeerError{Peer: addr(peer4), Op: "load-conn", Err: cause}, "ipsec: load-conn 10.20.0.30: boom"},
		{&OpError{Op: "xfrm install", Err: cause}, "ipsec: xfrm install: boom"},
		{&CommandError{Command: "load-conn", Err: cause}, "vici load-conn: boom"},
		{&CommandError{Command: "load-token", Reason: "no such key", Err: cause}, "vici load-token: boom: no such key"},
	} {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
		if !errors.Is(tt.err, cause) {
			t.Errorf("%T does not unwrap to its cause", tt.err)
		}
	}
}
