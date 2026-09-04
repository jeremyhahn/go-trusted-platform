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

package ipxe

import (
	"testing"
	"time"
)

// ipxeDeadline bounds how long a test waits for a listener that must eventually
// bind. It is a liveness backstop, not a timing assumption: these tests advance
// on the bind signal itself, so a loaded machine only makes them slower, and the
// deadline is reached only when a listener has genuinely failed to come up.
const ipxeDeadline = 10 * time.Second

// newBoundSignal returns the channel to hand to a sub-server's Start as its
// bound argument. It must be buffered: signalBound sends without blocking and
// drops the signal if nobody is ready to receive, so an unbuffered channel would
// silently lose the very event the caller is waiting for.
func newBoundSignal() chan struct{} {
	return make(chan struct{}, 1)
}

// awaitBound blocks until a sub-server reports its listener bound.
//
// DHCPServer, HTTPServer and TFTPServer have all taken a `bound chan<- struct{}`
// since they were written, and each signals it at the exact point its listener
// is up. The tests passed nil and slept instead — "give server time to start",
// 50 to 500ms — which is what made them fail under load on PRs that touched
// nothing here (issue #260).
func awaitBound(t *testing.T, bound <-chan struct{}, what string) {
	t.Helper()

	select {
	case <-bound:
	case <-time.After(ipxeDeadline):
		t.Fatalf("%s did not bind within %s", what, ipxeDeadline)
	}
}

// awaitReady blocks until every listener of a composite Server has bound.
// Server.Ready() has always exposed this; the tests slept past it.
func awaitReady(t *testing.T, s *Server) {
	t.Helper()

	select {
	case <-s.Ready():
	case <-time.After(ipxeDeadline):
		t.Fatalf("PXE server did not become ready within %s", ipxeDeadline)
	}
}
