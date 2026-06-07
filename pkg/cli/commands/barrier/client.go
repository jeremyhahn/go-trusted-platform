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
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// barrierClientFactory builds a quicbaas QRDBBarrierClient from a
// BaseCommand. Tests override this so the canonical verbs can be
// exercised without dialing a live quicbaasd.
type barrierClientFactory func(base *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error)

// activeBarrierClientFactory is the factory currently in use. The
// default factory dials quicbaasd via the platform SDK Client.
var activeBarrierClientFactory barrierClientFactory = defaultBarrierClientFactory

// SetBarrierClientFactory installs a new barrier client factory and
// returns a restorer that the caller invokes via defer. Intended for
// in-process tests; production code MUST NOT call this.
func SetBarrierClientFactory(f barrierClientFactory) func() {
	prev := activeBarrierClientFactory
	activeBarrierClientFactory = f
	return func() { activeBarrierClientFactory = prev }
}

// defaultBarrierClientFactory dials quicbaasd via the platform SDK
// Client and returns the QRDBBarrierClient from the Security service.
func defaultBarrierClientFactory(base *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
	q, err := base.Client().QuicBaaS()
	if err != nil {
		return nil, err
	}
	bc, err := q.Security().Barrier()
	if err != nil {
		return nil, err
	}
	return bc, nil
}

// openBarrierClient is the convenience wrapper used by verb handlers
// to acquire a barrier client. It delegates to the active factory so
// tests can swap it out atomically.
func openBarrierClient(base *cli.BaseCommand) (quicbaassdk.QRDBBarrierClient, error) {
	return activeBarrierClientFactory(base)
}
