// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Renewal that never reaches the listener is not renewal.
//
// The listener's TLS config is a static snapshot taken at startup
// (ca.ServerTLSConfig returns Certificates: []tls.Certificate{...}), so a
// certificate replaced in the CA is not the certificate clients receive. Left
// unwired, the sweep reissues every single day — the endpoint keeps serving the
// original, so the next sweep reads the same near-expiry certificate — while
// that certificate marches to expiry and TLS breaks.

func TestInstallWebServiceCert_InvokesTheRegisteredInstaller(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}
	calls := 0
	a.RegisterWebServiceCertInstaller("api", func(context.Context) error {
		calls++
		return nil
	})

	if err := a.installWebServiceCert(context.Background(), "api", installRequired); err != nil {
		t.Fatalf("install: %v", err)
	}

	if calls != 1 {
		t.Errorf("installer ran %d times, want 1. The renewed certificate was never "+
			"put into service, so the listener keeps serving the old one.", calls)
	}
}

// The renewal path must FAIL when the certificate cannot be put into service.
// Returning nil makes the sweep record the target "renewed" while the endpoint
// still serves the expiring certificate — the exact fail-open this step exists
// to close.

func TestInstallWebServiceCert_RenewalFailsWhenInstallerIsMissing(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}

	err := a.installWebServiceCert(context.Background(), "never-registered", installRequired)

	var want ErrCertInstallerMissing
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrCertInstallerMissing. Without it the sweep "+
			"reports a renewal that the listener never received.", err)
	}
}

func TestInstallWebServiceCert_RenewalFailsWhenInstallerErrors(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}
	a.RegisterWebServiceCertInstaller("api", func(context.Context) error {
		return errors.New("listener not ready")
	})

	err := a.installWebServiceCert(context.Background(), "api", installRequired)

	var want ErrCertInstallFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %v, want ErrCertInstallFailed", err)
	}
	if !errors.As(err, &want) || want.Cause == nil {
		t.Error("the underlying cause was dropped, so the job history cannot say " +
			"why the certificate was not installed")
	}
	if !strings.Contains(err.Error(), "listener not ready") {
		t.Errorf("the cause is not surfaced in the message: %q", err)
	}
}

// Boot is the opposite case: InitWebServer issues BEFORE the listener exists, so
// there is no installer yet and none is expected. Failing there would stop a
// node from booting over a listener that has not started.

func TestInstallWebServiceCert_BootToleratesAMissingInstaller(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}

	if err := a.installWebServiceCert(context.Background(), "not-yet", installOptional); err != nil {
		t.Errorf("boot issuance must tolerate a missing installer, got %v", err)
	}
}

func TestInstallWebServiceCert_BootToleratesAFailingInstaller(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}
	a.RegisterWebServiceCertInstaller("api", func(context.Context) error {
		return errors.New("listener not ready")
	})

	if err := a.installWebServiceCert(context.Background(), "api", installOptional); err != nil {
		t.Errorf("boot issuance must not fail on an install error, got %v", err)
	}
}

func TestRegisterWebServiceCertInstaller_ReplacesAndIgnoresNil(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}

	first, second := 0, 0
	a.RegisterWebServiceCertInstaller("api", func(context.Context) error { first++; return nil })
	a.RegisterWebServiceCertInstaller("api", func(context.Context) error { second++; return nil })
	_ = a.installWebServiceCert(context.Background(), "api", installRequired)

	if first != 0 || second != 1 {
		t.Errorf("re-registration did not replace the installer (first=%d second=%d); "+
			"a restarted listener would keep reloading the dead one", first, second)
	}

	// A nil installer must not be stored, or installWebServiceCert would panic
	// in the boot path.
	a.RegisterWebServiceCertInstaller("nil-one", nil)
	_ = a.installWebServiceCert(context.Background(), "nil-one", installOptional)
}

// TestCertInstallerRegistry_ConcurrentRegisterAndLookup is a race-detector test.
//
// The scheduler starts before the webservers register their installers, so a
// renewal sweep can look one up while boot is still assigning the registry
// pointer. Guarding only the inner map leaves the POINTER itself racy, which the
// race detector reports and which is undefined behaviour regardless.
//
// Run under -race this fails if the pointer is read outside the publishing lock.
func TestCertInstallerRegistry_ConcurrentRegisterAndLookup(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			a.RegisterWebServiceCertInstaller(
				"ws-"+strconv.Itoa(n),
				func(context.Context) error { return nil },
			)
		}(i)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			// installOptional: a lookup that misses is fine here; the point is
			// that the lookup itself must not race the registration.
			_ = a.installWebServiceCert(context.Background(), "ws-"+strconv.Itoa(n), installOptional)
		}(i)
	}

	close(start)
	wg.Wait()
}
