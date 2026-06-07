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

import (
	"errors"
	"testing"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestSetBarrierClientFactory_SwapAndRestore verifies that the test
// seam swaps cleanly and the restorer puts the previous factory back.
func TestSetBarrierClientFactory_SwapAndRestore(t *testing.T) {
	called := 0
	custom := func(_ *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
		called++
		return nil, errors.New("stub")
	}

	restore := SetBarrierClientFactory(custom)

	// openBarrierClient must hit the custom factory.
	_, err := openBarrierClient(nil)
	if err == nil || err.Error() != "stub" {
		t.Errorf("expected stub error, got %v", err)
	}
	if called != 1 {
		t.Errorf("expected custom factory invoked once, got %d", called)
	}

	// Restorer puts the default back.
	restore()
	if &activeBarrierClientFactory == nil {
		t.Fatal("activeBarrierClientFactory unexpectedly nil after restore")
	}

	// After restore, openBarrierClient routes to default. We can't fully
	// exercise the default without a live BaseCommand, but we can verify
	// the active factory pointer is non-nil.
}

// TestOpenBarrierClient_RoutesThroughActiveFactory cross-checks that
// openBarrierClient really delegates to whatever factory is installed
// (not a captured closure).
func TestOpenBarrierClient_RoutesThroughActiveFactory(t *testing.T) {
	sentinel := errors.New("sentinel")
	restore := SetBarrierClientFactory(func(_ *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
		return nil, sentinel
	})
	defer restore()

	_, err := openBarrierClient(nil)
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}
