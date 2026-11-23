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

package app

import (
	"context"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// loadOrInitCAForActivate brings the CA up for ActivateCA. Tests replace it
// to publish a CA without a key store.
var loadOrInitCAForActivate = func(ctx context.Context, app *App) error {
	return app.LoadOrInitCA(ctx, nil)
}

// ActivateCA loads or initializes the CA and hands it to inject (the
// embedded QuicBaaS). When inject fails, App.CA and the embedded ceremony CA
// go back to what they were before the call and the error is returned: a CA
// that readers saw while the embedded server refused it would split them,
// with heartbeat, NTS and the ceremony on the new CA while gRPC, REST, QUIC,
// attestation and boot read the daemon holder, which stays empty on the
// failure. A later call loads the stored CA and tries the injection again.
func (app *App) ActivateCA(
	ctx context.Context,
	inject func(quicbaasca.CACertificateAuthority) error,
) (quicbaasca.CACertificateAuthority, error) {
	prev := app.CurrentCA()
	prevQB := app.quicBaaSActiveCA()
	if err := loadOrInitCAForActivate(ctx, app); err != nil {
		return nil, err
	}
	ca := app.CurrentCA()
	if err := inject(ca); err != nil {
		app.publishCA(prev)
		app.restoreQuicBaaSCA(prevQB)
		return nil, err
	}
	return ca, nil
}

// quicBaaSActiveCA returns the embedded QuicBaaS ceremony CA, or nil when the
// App has no QuicBaaS factory.
func (app *App) quicBaaSActiveCA() xkmssdk.TrustedCA {
	factory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok || factory == nil {
		return nil
	}
	return factory.ActiveCA()
}

// restoreQuicBaaSCA puts prev back as the embedded QuicBaaS ceremony CA; a
// no-op when the App has no QuicBaaS factory.
func (app *App) restoreQuicBaaSCA(prev xkmssdk.TrustedCA) {
	factory, ok := app.daoFactory.(*quicbaas.Factory)
	if !ok || factory == nil {
		return
	}
	factory.RestoreCA(prev)
}
