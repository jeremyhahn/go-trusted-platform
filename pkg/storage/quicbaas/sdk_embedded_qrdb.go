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

package quicbaas

import (
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// EmbeddedQRDBWiringError is returned when the platform cannot construct
// the QRDBEmbeddedServicers payload required by WithEmbeddedQRDB. The
// Stage field identifies which dependency was missing or which call
// failed so callers can surface the wiring issue without guessing.
type EmbeddedQRDBWiringError struct {
	Stage string
	Cause error
}

// Error implements the error interface.
func (e *EmbeddedQRDBWiringError) Error() string {
	if e.Cause == nil {
		return "embedded qrdb wiring: " + e.Stage + " unavailable"
	}
	return "embedded qrdb wiring: " + e.Stage + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause for errors.Is/As traversal.
func (e *EmbeddedQRDBWiringError) Unwrap() error {
	return e.Cause
}

// buildEmbeddedQRDBServicers assembles the QRDBEmbeddedServicers value that
// the SDK's WithEmbeddedQRDB option expects.
//
// Node path: KV and Admin come directly from the embedded engine node's
// service graph via GetQRDBKVServicer/GetQRDBAdminServicer; the node's SDK
// client provides barrier, ceremony, and credential servicers via its
// embedded transport. This mirrors the canonical go-quicbaas
// cmd/quicbaas/embedded_qrdb.go wiring and no longer depends on the removed
// EmbeddedTransportForShard / BaasKVAdapter / BaasAdminAdapter machinery.
//
// Ceremony, credential, and barrier servicers come directly from the qrdb
// node: the embedded ceremony transport threads the per-request SOPin/UserPin
// from the ceremony-initialize request into the service layer, and the
// data-plane barrier persists InitializedAt across warm boots, so no
// platform-side configurator or persistence wrapper is required.
//
// Returns EmbeddedQRDBWiringError when a required component is missing. Safe
// to call only after EmbeddedServer.Start() has returned — the caller must
// hold a started server reference.
func buildEmbeddedQRDBServicers(es *EmbeddedServer) (quicbaas.QRDBEmbeddedServicers, error) {
	if es == nil {
		return quicbaas.QRDBEmbeddedServicers{}, &EmbeddedQRDBWiringError{Stage: "embedded server"}
	}
	srv := es.Server()
	if srv == nil {
		return quicbaas.QRDBEmbeddedServicers{}, &EmbeddedQRDBWiringError{Stage: "embedded server not started"}
	}

	// Node path: the in-process qrdb engine node's KV and Admin servicers are
	// the canonical service-layer implementations backed by the embedded
	// engine. All barrier/ceremony/credential operations route through the
	// node's SDK client embedded transport without any intermediate
	// BaasTransport layer.
	kv := srv.GetQRDBKVServicer()
	admin := srv.GetQRDBAdminServicer()
	if kv == nil || admin == nil {
		return quicbaas.QRDBEmbeddedServicers{}, &EmbeddedQRDBWiringError{Stage: "qrdb node services"}
	}

	servicers := quicbaas.QRDBEmbeddedServicers{
		KV:    kv,
		Admin: admin,
	}

	// Wire the user store and the unified-login UserAuthFactor service from
	// the node so factor enrollment resolves against the exact store the
	// login ceremony reads.
	if userSvc := srv.GetQRDBUserServicer(); userSvc != nil {
		servicers.User = userSvc
	}
	if uafSvc := srv.GetQRDBUserAuthFactorServicer(); uafSvc != nil {
		servicers.UserAuthFactor = uafSvc
	}

	// Default ceremony / credential / barrier services come from the node's
	// bootstrap ceremony stack and data-plane barrier.
	if stack := srv.GetCeremonyServices(); stack != nil {
		servicers.Ceremony = stack.Ceremony
		servicers.Credential = stack.Credential
		if stack.Barrier != nil {
			servicers.Barrier = stack.Barrier
		}
	}
	if dp := srv.GetDataPlaneBarrierService(); dp != nil {
		servicers.Barrier = dp
	}

	// Wire the lazy ceremony CA adapter so the qrdb embedded transport can
	// dispatch CeremonyInitialize against the platform CA. The adapter
	// resolves the underlying CA on every call so it can be installed before
	// App.LoadCA() / App.InitCA() completes.
	if ca := es.CeremonyCA(); ca != nil {
		servicers.CeremonyCA = ca
	}

	return servicers, nil
}

// embeddedQRDBOption returns the SDK option that wires the in-process
// qrdb sub-client against the embedded server's services. Returns a
// wrapped EmbeddedQRDBWiringError when the servicers cannot be assembled,
// so callers can surface the wiring failure to the user rather than
// silently dropping back to a network qrdb client that has no listener
// to dial in embedded mode.
func embeddedQRDBOption(es *EmbeddedServer) (quicbaas.Option, error) {
	servicers, err := buildEmbeddedQRDBServicers(es)
	if err != nil {
		return nil, err
	}
	return quicbaas.WithEmbeddedQRDB(servicers), nil
}
