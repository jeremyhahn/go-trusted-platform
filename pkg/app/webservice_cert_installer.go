// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"context"
	"sync"
)

// WebServiceCertInstaller puts a newly issued certificate into service on a
// running listener.
type WebServiceCertInstaller func(ctx context.Context) error

// RegisterWebServiceCertInstaller records how to put a renewed certificate into
// service for one webservice. The running server registers its own reloader at
// startup; issuance calls it after a successful reissue.
//
// Without this seam, renewal is issuance only. The listener's TLS config is a
// static snapshot taken at startup, so a certificate replaced in the CA is not
// the certificate clients receive — the sweep would reissue every day, the
// endpoint would keep serving the original, and TLS would break when that one
// expired.
func (app *App) RegisterWebServiceCertInstaller(wsName string, install WebServiceCertInstaller) {
	if install == nil {
		return
	}
	reg := app.ensureCertInstallers()
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.installers[wsName] = install
}

// ensureCertInstallers lazily creates the registry.
//
// Creation is serialised on a package-level mutex rather than assuming
// registration only ever happens on the boot goroutine. It does today -- serve.go
// registers each webservice in sequence -- but that is an assumption about a
// caller, and a later caller registering from elsewhere would corrupt the map
// with no visible symptom until a sweep read it.
func (app *App) ensureCertInstallers() *certInstallerRegistry {
	certInstallerInit.Lock()
	defer certInstallerInit.Unlock()
	if app.certInstallers == nil {
		app.certInstallers = &certInstallerRegistry{
			installers: make(map[string]WebServiceCertInstaller),
		}
	}
	return app.certInstallers
}

// loadCertInstallers reads the registry pointer under the lock that publishes
// it. A plain field read here would race with ensureCertInstallers.
//
// The pointer is guarded rather than made an atomic.Pointer because App is
// copied elsewhere (testConfig, which also yaml.Marshals it) and atomic.Pointer
// carries a noCopy, which would make every one of those copies a vet failure.
// The registry is touched once per issuance, so the lock costs nothing.
func (app *App) loadCertInstallers() *certInstallerRegistry {
	certInstallerInit.Lock()
	defer certInstallerInit.Unlock()
	return app.certInstallers
}

// certInstallPolicy says whether putting the certificate into service is
// required for the issuance to count as successful.
type certInstallPolicy int

const (
	// installOptional is the BOOT path. InitWebServer issues before the listener
	// exists, so there is no installer to call yet and none is expected; the
	// listener picks the certificate up when it starts.
	installOptional certInstallPolicy = iota

	// installRequired is the RENEWAL path. A certificate the listener does not
	// serve has not been renewed in any sense a client can observe, so reporting
	// success would be a lie the sweep then records as "renewed" -- exactly the
	// fail-open this installation step exists to close.
	installRequired
)

// installWebServiceCert puts the freshly issued certificate into service.
//
// Under installRequired a missing or failing installer is returned as an error
// so the renewal target is recorded failed and retried, rather than reported
// renewed while the endpoint keeps serving the expiring certificate.
func (app *App) installWebServiceCert(
	ctx context.Context, wsName string, policy certInstallPolicy) error {

	var (
		install WebServiceCertInstaller
		ok      bool
	)
	// The POINTER is read under the same lock that publishes it. Guarding only
	// the inner map is not enough: the scheduler starts before the webservers
	// register their installers, so a renewal can read this field while boot is
	// still assigning it -- a data race on the pointer itself, whatever the map
	// underneath is protected by.
	if reg := app.loadCertInstallers(); reg != nil {
		reg.mu.RLock()
		install, ok = reg.installers[wsName]
		reg.mu.RUnlock()
	}

	if !ok {
		err := ErrCertInstallerMissing{Webservice: wsName}
		if policy == installRequired {
			return err
		}
		app.Logger.Debug("cert issuance: no installer registered yet; the listener "+
			"will pick this certificate up when it starts", "webservice", wsName)
		return nil
	}
	if err := install(ctx); err != nil {
		wrapped := ErrCertInstallFailed{Webservice: wsName, Cause: err}
		if policy == installRequired {
			return wrapped
		}
		app.Logger.Error(wrapped, "cert issuance: the new certificate could not be "+
			"put into service; the listener still serves the previous one",
			"webservice", wsName)
		return nil
	}
	app.Logger.Info("cert issuance: new certificate is now served by the live listener",
		"webservice", wsName)
	return nil
}

// certInstallerRegistry holds the installers. Referenced by POINTER from App so
// App itself stays copyable.
type certInstallerRegistry struct {
	mu         sync.RWMutex
	installers map[string]WebServiceCertInstaller
}

// certInstallerInit guards publication AND reads of the registry pointer.
var certInstallerInit sync.Mutex
