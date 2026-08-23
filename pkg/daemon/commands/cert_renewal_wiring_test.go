// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package commands

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// The wiring itself is one call; what needs pinning is that it DEGRADES rather
// than crashes, because it runs inside platformd's boot path. A panic here
// would take down a serving node over a scheduler that merely is not enabled.

func TestInitCertManagement_NoSchedulerDoesNotAbortBoot(t *testing.T) {
	// A zero App has no DAO factory, so CertManagementScheduler() returns nil —
	// the standalone / scheduler-disabled deployment shape.
	a := &app.App{Hostname: "node-01"}

	if got := a.CertManagementScheduler(); got != nil {
		t.Fatalf("precondition: expected a nil scheduler on a bare App, got %T", got)
	}

	// Must return normally. The boot path has no error to propagate to, so a
	// panic or a fatal here is the failure mode that matters.
	initCertManagement(context.Background(), logging.DefaultLogger(), a)
}

func TestInitCertManagement_NoHostnameDoesNotAbortBoot(t *testing.T) {
	// NodeAffinity needs a stable identifier; without one the job would either
	// be rejected or, worse, run on every node in the fleet.
	a := &app.App{}
	initCertManagement(context.Background(), logging.DefaultLogger(), a)
}

func TestInitCertManagement_NilAppIsSurvivable(t *testing.T) {
	// Defensive: boot ordering changes have caused nil dereferences in this
	// path before. Reaching this call with a half-built App must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("wiring panicked instead of degrading: %v", r)
		}
	}()
	initCertManagement(context.Background(), logging.DefaultLogger(), &app.App{})
}

func TestInitCertManagement_NilAppDoesNotAbortBoot(t *testing.T) {
	// runDaemonOnly is reached with a nil App when App.Init() failed — that is
	// precisely why the daemon-only path exists. Dereferencing here would turn
	// a degraded boot into a panic during startup.
	initCertManagement(context.Background(), logging.DefaultLogger(), nil)
}
