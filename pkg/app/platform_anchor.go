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
	"crypto/x509"

	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// PlatformAnchor returns the platform CA as a verification anchor: what a
// platform service on this node verifies another platform service against.
//
// Its source is the root of the chain that issued this node's IDevID. On the
// control plane that is its own CA. On an enrolled node it is the control
// plane's CA, reachable because enrollment imports the issuing chain into the
// node's certificate store (go-xkms#556, #653). One rule covers both, and it
// needs no configuration: a platform-issued certificate chains to the
// platform CA and to nothing else.
//
// The source is read on every verification, so a node that enrolls after
// start-up is anchored from then on. Before it enrolls, verification fails
// with *trust.ErrAnchorUnavailable rather than trusting anything else.
func (app *App) PlatformAnchor() (*trust.Anchor, error) {
	return trust.NewAnchor(trust.AnchorSourceFunc(app.platformAnchorCertificates))
}

// platformAnchorCertificates resolves the root of this node's IDevID
// issuing chain.
func (app *App) platformAnchorCertificates(_ context.Context) ([]*x509.Certificate, error) {
	if app.TPM == nil || app.CA == nil {
		return nil, ErrPlatformAnchorNoIdentity{}
	}
	idevid, err := app.TPM.IDevIDCertificate()
	if err != nil {
		return nil, err
	}
	root, err := app.CA.RootCertificate(idevid)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{root}, nil
}
