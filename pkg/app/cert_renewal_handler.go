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
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/scheduler"
)

// CertRenewalHandlerName is the registered handler name for the
// platform-wide cert renewal sweep job. One job per node, named
// "platform.cert-renewal.<nodeID>", references this handler.
const CertRenewalHandlerName = "platform.cert-renewal"

// DefaultCertRenewalSchedule is the cron expression used when none
// is configured. 02:00 daily — middle of the night for most ops
// timezones, well outside business-hours windows.
const DefaultCertRenewalSchedule = "0 2 * * *"

// DefaultCertRenewalThreshold is the time-until-expiry under which a
// cert is considered "due for renewal". 30 days matches the
// industry-standard ACME renewal window (well before the standard
// 90-day cert expiry).
const DefaultCertRenewalThreshold = 30 * 24 * time.Hour

// DefaultCertRenewalTimeout caps how long a single sweep may take.
// 30 minutes accommodates a slow ACME exchange + multi-target
// reissuance across the registry.
const DefaultCertRenewalTimeout = 30 * time.Minute

// SchedulerService is the narrow subset of the scheduler engine that
// the cert-renewal wiring uses. *scheduler.SchedulerEngine satisfies
// this interface; tests substitute a fake.
type SchedulerService interface {
	RegisterHandler(name string, handler scheduler.JobHandler) error
	ScheduleJob(ctx context.Context, job *scheduler.Job) error
	ListJobs(ctx context.Context, query *scheduler.JobQuery) ([]*scheduler.Job, error)
}

// CertRenewalRegistration bundles the inputs needed to register the
// cert renewal handler + per-node recurring job at platformd boot.
type CertRenewalRegistration struct {
	// Scheduler is the embedded scheduler engine.
	Scheduler SchedulerService

	// Registry holds the cert targets to sweep on each tick.
	Registry *CertTargetRegistry

	// NodeID identifies this node for affinity binding. The created
	// job's Name and NodeAffinity both reference this value so it
	// fires only on this node regardless of cluster leadership.
	NodeID string

	// Schedule is the cron expression. Empty falls back to
	// DefaultCertRenewalSchedule.
	Schedule string

	// Threshold is the time-until-expiry under which a cert is
	// considered due. Zero falls back to DefaultCertRenewalThreshold.
	Threshold time.Duration

	// Timeout caps a single sweep. Zero falls back to
	// DefaultCertRenewalTimeout.
	Timeout time.Duration

	// MaxRetries is the per-tick retry count on transient failures.
	// Zero falls back to 3.
	MaxRetries int32

	// Logger receives structured renewal events. May be nil.
	Logger *slog.Logger
}

// renewalJobName composes the per-node cert-renewal job name. The
// NodeID is appended so each node owns a distinct job entry; the
// scheduler's NodeAffinity gate ensures only the owning node executes.
func renewalJobName(nodeID string) string {
	return CertRenewalHandlerName + "." + nodeID
}

// RegisterCertRenewal registers the cert renewal handler and creates
// (idempotently) the per-node recurring job. Safe to call on every
// platformd boot — if the job already exists, it is left alone.
//
// Returns an error if any step fails. On success, the scheduler will
// invoke the handler on every tick of the configured schedule, and
// the handler will sweep the registry's CertTargets reissuing those
// within Threshold of expiry.
func RegisterCertRenewal(ctx context.Context, opts CertRenewalRegistration) error {
	if opts.Scheduler == nil {
		return ErrCertRenewalMissingScheduler
	}
	if opts.Registry == nil {
		return ErrCertRenewalMissingRegistry
	}
	if opts.NodeID == "" {
		return ErrCertRenewalMissingNodeID
	}

	threshold := opts.Threshold
	if threshold <= 0 {
		threshold = DefaultCertRenewalThreshold
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultCertRenewalTimeout
	}
	schedule := opts.Schedule
	if schedule == "" {
		schedule = DefaultCertRenewalSchedule
	}
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	// 1. Register the handler. If it's already registered (e.g., a
	// re-run of boot logic in tests), we accept the duplicate-handler
	// error as benign.
	handler := buildCertRenewalHandler(opts.Registry, threshold, opts.Logger)
	if err := opts.Scheduler.RegisterHandler(CertRenewalHandlerName, handler); err != nil {
		if !isAlreadyRegistered(err) {
			return ErrCertRenewalRegisterHandler{Cause: err}
		}
	}

	// 2. Idempotently create the per-node job. If a matching entry
	// already exists in the scheduler store (booted previously), do
	// nothing.
	jobName := renewalJobName(opts.NodeID)
	existing, err := opts.Scheduler.ListJobs(ctx, &scheduler.JobQuery{
		OwnerType: scheduler.OwnerTypeSystem,
		OwnerID:   opts.NodeID,
		Handler:   CertRenewalHandlerName,
	})
	if err != nil {
		return ErrCertRenewalListJobs{Cause: err}
	}
	for _, j := range existing {
		if j.Name == jobName {
			if opts.Logger != nil {
				opts.Logger.Info("cert-renewal: existing job preserved",
					"job_id", j.ID, "name", j.Name, "node_id", opts.NodeID)
			}
			return nil
		}
	}

	job := &scheduler.Job{
		Name:         jobName,
		Description:  "Periodic platform certificate renewal sweep for node " + opts.NodeID,
		OwnerType:    scheduler.OwnerTypeSystem,
		OwnerID:      opts.NodeID,
		Type:         scheduler.JobTypeRecurring,
		Schedule:     schedule,
		Handler:      CertRenewalHandlerName,
		Timeout:      timeout,
		MaxRetries:   maxRetries,
		NodeAffinity: opts.NodeID,
		Status:       scheduler.JobStatusPending,
	}
	if err := opts.Scheduler.ScheduleJob(ctx, job); err != nil {
		return ErrCertRenewalScheduleJob{Cause: err}
	}
	if opts.Logger != nil {
		opts.Logger.Info("cert-renewal: job scheduled",
			"name", job.Name,
			"node_id", opts.NodeID,
			"schedule", schedule,
			"threshold", threshold,
			"timeout", timeout)
	}
	return nil
}

// buildCertRenewalHandler returns a scheduler.JobHandler that
// snapshots the registry, evaluates each target against the
// expiry threshold, and reissues those that are due.
//
// The handler is deliberately tolerant: a per-target failure does
// not abort the sweep; per-target outcomes are aggregated into the
// JobResult for audit. The job-level error is non-nil only when
// the handler itself cannot run at all (e.g., the registry was
// destroyed mid-sweep).
func buildCertRenewalHandler(reg *CertTargetRegistry, threshold time.Duration, logger *slog.Logger) scheduler.JobHandler {
	return func(ctx context.Context, job *scheduler.Job) (*scheduler.JobResult, error) {
		results := runCertRenewalSweep(ctx, reg, threshold, time.Now(), logger)
		payload, _ := json.Marshal(results)
		ok := true
		for _, r := range results {
			if r.Error != "" {
				ok = false
				break
			}
		}
		return &scheduler.JobResult{
			Success: ok,
			Message: summarizeResults(results),
			Output:  payload,
		}, nil
	}
}

// renewalResult captures a single target's per-tick outcome. The
// slice is JSON-encoded into the job's result payload so the
// scheduler's GetJobHistory call returns an audit trail.
type renewalResult struct {
	Name      string    `json:"name"`
	Kind      CertKind  `json:"kind"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	DaysLeft  float64   `json:"days_left,omitempty"`
	Action    string    `json:"action"` // "renewed", "skipped", "failed"
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// runCertRenewalSweep iterates the registry and acts on each target.
// Pure function — testable without a scheduler engine. now is
// injected for deterministic time in tests.
func runCertRenewalSweep(
	ctx context.Context,
	reg *CertTargetRegistry,
	threshold time.Duration,
	now time.Time,
	logger *slog.Logger,
) []renewalResult {
	if reg == nil {
		return nil
	}
	targets := reg.Snapshot()
	if len(targets) == 0 {
		return nil
	}
	results := make([]renewalResult, 0, len(targets))
	for _, t := range targets {
		result := evaluateAndReissue(ctx, t, threshold, now, logger)
		results = append(results, result)
	}
	// Deterministic order for downstream consumers.
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results
}

// evaluateAndReissue inspects a single target: reads its current
// cert, computes time-until-expiry, and either skips (not due) or
// invokes Reissue (due). Errors at any step are captured into the
// result's Error field — they do NOT propagate to abort the sweep.
func evaluateAndReissue(
	ctx context.Context,
	target *CertTarget,
	threshold time.Duration,
	now time.Time,
	logger *slog.Logger,
) renewalResult {
	r := renewalResult{
		Name:      target.Name,
		Kind:      target.Kind,
		Timestamp: now,
	}
	cert, err := target.Current(ctx)
	if err != nil {
		r.Action = "failed"
		r.Error = "current: " + err.Error()
		if logger != nil {
			logger.Warn("cert-renewal: cannot read current cert",
				"target", target.Name, "err", err)
		}
		return r
	}
	if cert == nil {
		r.Action = "failed"
		r.Error = "current: nil certificate"
		return r
	}
	r.NotAfter = cert.NotAfter
	until := cert.NotAfter.Sub(now)
	r.DaysLeft = until.Hours() / 24

	if until > threshold {
		r.Action = "skipped"
		if logger != nil {
			logger.Debug("cert-renewal: not due",
				"target", target.Name,
				"days_left", r.DaysLeft,
				"threshold_days", threshold.Hours()/24)
		}
		return r
	}

	if err := target.Reissue(ctx); err != nil {
		r.Action = "failed"
		r.Error = "reissue: " + err.Error()
		if logger != nil {
			logger.Error("cert-renewal: reissue failed",
				"target", target.Name, "err", err)
		}
		return r
	}
	r.Action = "renewed"
	if logger != nil {
		logger.Info("cert-renewal: renewed",
			"target", target.Name, "days_left_at_renewal", r.DaysLeft)
	}
	return r
}

// summarizeResults builds a one-line summary of a sweep's outcomes
// suitable for the JobResult.Message field and operator inspection.
func summarizeResults(results []renewalResult) string {
	if len(results) == 0 {
		return "no cert targets"
	}
	var renewed, skipped, failed int
	for _, r := range results {
		switch r.Action {
		case "renewed":
			renewed++
		case "skipped":
			skipped++
		case "failed":
			failed++
		}
	}
	return fmt.Sprintf("cert-renewal sweep: %d renewed, %d skipped, %d failed (of %d targets)",
		renewed, skipped, failed, len(results))
}

// isAlreadyRegistered reports whether err is the scheduler's
// "handler already registered" condition. The scheduler returns
// InvalidJobError for this in current revisions; we string-match
// to avoid a hard dependency on the error type's stability.
func isAlreadyRegistered(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already registered") || strings.Contains(msg, "duplicate handler")
}
