// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Until issue #31 this function had ZERO production callers, so its outcome was
// never asserted — the existing happy-path test checked only that it returned
// no error. These pin what it must actually DO, since the whole defect was that
// nothing renewed certificates.

func TestInitCertManagement_SchedulesTheRenewalSweep(t *testing.T) {
	sched := newFakeScheduler()
	a := &App{Logger: logging.DefaultLogger()}

	if err := a.InitCertManagement(context.Background(), sched, "node-A"); err != nil {
		t.Fatalf("InitCertManagement: %v", err)
	}

	if sched.registerCalls == 0 {
		t.Error("no renewal handler was registered — the sweep would have nothing to run")
	}
	if len(sched.jobs) == 0 {
		t.Fatal("no job was scheduled — certificates would still never be renewed, " +
			"which is the exact defect this wiring exists to fix")
	}

	job := sched.jobs[0]
	if job.NodeAffinity != "node-A" {
		t.Errorf("NodeAffinity = %q, want %q — without it every node in a fleet "+
			"would renew the same targets", job.NodeAffinity, "node-A")
	}
	if job.Schedule == "" {
		t.Error("the job has no schedule, so it would never fire")
	}
}

func TestInitCertManagement_IsIdempotentAcrossRestarts(t *testing.T) {
	// platformd re-runs this on every boot. The registration is documented as
	// idempotent; documented is not the same as verified, and a second boot
	// duplicating the job would mean two sweeps racing the same targets.
	sched := newFakeScheduler()
	a := &App{Logger: logging.DefaultLogger()}
	ctx := context.Background()

	if err := a.InitCertManagement(ctx, sched, "node-A"); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	afterFirst := len(sched.jobs)

	if err := a.InitCertManagement(ctx, sched, "node-A"); err != nil {
		t.Fatalf("second boot must not fail — platformd restarts are routine: %v", err)
	}

	if len(sched.jobs) != afterFirst {
		t.Errorf("a restart added %d more job(s) (total %d); duplicate sweeps would race "+
			"the same certificate targets", len(sched.jobs)-afterFirst, len(sched.jobs))
	}
}

func TestInitCertManagement_RejectsMissingInputs(t *testing.T) {
	a := &App{Logger: logging.DefaultLogger()}
	ctx := context.Background()

	t.Run("nil scheduler", func(t *testing.T) {
		if err := a.InitCertManagement(ctx, nil, "node-A"); err == nil {
			t.Error("a nil scheduler must be reported, not silently skipped — " +
				"silently skipping is how renewal went missing in the first place")
		}
	})

	t.Run("empty node id", func(t *testing.T) {
		err := a.InitCertManagement(ctx, newFakeScheduler(), "")
		if err == nil {
			t.Fatal("an empty node ID must be refused: NodeAffinity would be blank")
		}
		if !strings.Contains(strings.ToLower(err.Error()), "node") {
			t.Errorf("the error should name the missing node ID, got %q", err)
		}
	})
}
