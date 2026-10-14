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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
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
// the cert-renewal wiring uses. *quicbaas.SchedulerEngine satisfies
// this interface; tests substitute a fake.
type SchedulerService interface {
	RegisterHandler(name string, handler quicbaas.JobHandler) error
	ScheduleJob(ctx context.Context, job *quicbaas.Job) error
	ListJobs(ctx context.Context, query *quicbaas.JobQuery) ([]*quicbaas.Job, error)
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

	// Now is the clock each sweep measures time-to-expiry against: time.Now
	// in production; tests replace it to move a certificate into or out of
	// the renewal window without sleeping (#284). Nil falls back to time.Now.
	Now func() time.Time
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
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// 1. Register the handler. If it's already registered (e.g., a
	// re-run of boot logic in tests), we accept the duplicate-handler
	// error as benign.
	handler := buildCertRenewalHandler(opts.Registry, threshold, now, opts.Logger)
	if err := opts.Scheduler.RegisterHandler(CertRenewalHandlerName, handler); err != nil {
		if !isAlreadyRegistered(err) {
			return ErrCertRenewalRegisterHandler{Cause: err}
		}
	}

	// 2. Idempotently create the per-node job. If a matching entry
	// already exists in the scheduler store (booted previously), do
	// nothing.
	jobName := renewalJobName(opts.NodeID)
	existing, err := opts.Scheduler.ListJobs(ctx, &quicbaas.JobQuery{
		OwnerType: quicbaas.OwnerTypeSystem,
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
			// Preserving is not the same as reconciling. The stored job keeps the
			// schedule, timeout and retry count it was created with, so changing
			// any of them and restarting has NO effect -- and nothing said so.
			//
			// The renewal threshold is different: it lives in the handler closure,
			// which is rebuilt every boot, so that one does take effect.
			//
			// Updating the stored job needs quicbaas.JobUpdateParams, which
			// sdk/go does not re-export (filed upstream). Until it does, the
			// drift is at least reported instead of silently ignored.
			reportCertRenewalJobDrift(j, schedule, timeout, maxRetries, opts)
			return nil
		}
	}

	job := &quicbaas.Job{
		Name:         jobName,
		Description:  "Periodic platform certificate renewal sweep for node " + opts.NodeID,
		OwnerType:    quicbaas.OwnerTypeSystem,
		OwnerID:      opts.NodeID,
		Type:         quicbaas.JobTypeRecurring,
		Schedule:     schedule,
		Handler:      CertRenewalHandlerName,
		Timeout:      timeout,
		MaxRetries:   maxRetries,
		NodeAffinity: opts.NodeID,
		Status:       quicbaas.JobStatusPending,
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

// buildCertRenewalHandler returns a quicbaas.JobHandler that
// snapshots the registry, evaluates each target against the
// expiry threshold, and reissues those that are due.
//
// The handler is deliberately tolerant: a per-target failure does
// not abort the sweep; per-target outcomes are aggregated into the
// JobResult for audit. The job-level error is non-nil only when
// the handler itself cannot run at all (e.g., the registry was
// destroyed mid-sweep).
func buildCertRenewalHandler(reg *CertTargetRegistry, threshold time.Duration, now func() time.Time, logger *slog.Logger) quicbaas.JobHandler {
	return func(ctx context.Context, job *quicbaas.Job) (*quicbaas.JobResult, error) {
		results, sweepErr := runCertRenewalSweep(ctx, reg, threshold, now(), logger)
		payload, _ := json.Marshal(results)
		ok := true
		for _, r := range results {
			if r.Error != "" {
				ok = false
				break
			}
		}

		if sweepErr != nil {
			// An incomplete sweep is not a success, however healthy the targets
			// it did manage to reach. Returned as an error so the scheduler
			// applies its own cancellation and retry semantics rather than
			// recording a clean tick over work that never ran.
			return &quicbaas.JobResult{
				Success: false,
				Message: sweepErr.Error() + "; " + summarizeResults(results),
				Output:  payload,
			}, sweepErr
		}

		return &quicbaas.JobResult{
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
	Name     string    `json:"name"`
	Kind     CertKind  `json:"kind"`
	NotAfter time.Time `json:"not_after,omitempty"`
	DaysLeft float64   `json:"days_left,omitempty"`
	Action   string    `json:"action"` // "renewed", "skipped", "failed"
	// DueReason explains a renewal that expiry alone does not account for --
	// e.g. a BMC reissued with years left because its certificate did not chain
	// to a trusted issuer. Without it the audit trail shows a rotation with no
	// visible cause.
	DueReason string    `json:"due_reason,omitempty"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// runCertRenewalSweep iterates the registry and acts on each target.
// Pure function — testable without a scheduler engine. now is
// injected for deterministic time in tests.
// runCertRenewalSweep returns the per-target results and, when the sweep did not
// finish, the reason it stopped. A non-nil error means the results are PARTIAL:
// some targets were never evaluated, so their certificates are in an unknown
// state and the job must not be reported successful.
func runCertRenewalSweep(
	ctx context.Context,
	reg *CertTargetRegistry,
	threshold time.Duration,
	now time.Time,
	logger *slog.Logger,
) ([]renewalResult, error) {
	if reg == nil {
		return nil, nil
	}
	targets := reg.Snapshot()
	if len(targets) == 0 {
		return nil, nil
	}
	results := make([]renewalResult, 0, len(targets))
	for _, t := range targets {
		// Stop on cancellation instead of running the remaining targets to
		// failure. The job carries a timeout and the daemon can shut down
		// mid-sweep; without this every target left in the list is recorded
		// "failed" for a reason that has nothing to do with its certificate,
		// and the audit trail reads as a fleet-wide outage.
		if err := ctx.Err(); err != nil {
			if logger != nil {
				logger.Warn("cert-renewal: sweep cancelled; remaining targets not evaluated",
					"evaluated", len(results), "total", len(targets), "err", err)
			}
			sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
			// Reported as an error, not just a short list. The handler derives
			// Success from the results, so a truncated sweep that returned
			// silently would be indistinguishable from a complete one -- the job
			// would claim success while some certificates were never even
			// checked, and the scheduler would not retry the work.
			return results, ErrCertRenewalSweepIncomplete{
				Evaluated: len(results),
				Total:     len(targets),
				Cause:     err,
			}
		}
		results = append(results, safeEvaluate(ctx, t, threshold, now, logger))
	}
	// Deterministic order for downstream consumers.
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results, nil
}

// safeEvaluate runs evaluateAndReissue with the target's callbacks isolated.
//
// Current and Reissue call out to deployers, ACME clients and BMC transports.
// A panic in any of them would otherwise abort the whole sweep, so a single
// misbehaving device would silently stop certificate renewal for every other
// target on the node -- the same failure mode already designed out of the boot
// path. The panic is recorded as a failure rather than swallowed, so it stays
// visible in the job history instead of looking like a skipped target.
func safeEvaluate(
	ctx context.Context,
	target *CertTarget,
	threshold time.Duration,
	now time.Time,
	logger *slog.Logger,
) (r renewalResult) {
	defer func() {
		if p := recover(); p != nil {
			r = renewalResult{
				Name:      target.Name,
				Kind:      target.Kind,
				Timestamp: now,
				Action:    "failed",
				Error:     fmt.Sprintf("panic: %v", p),
			}
			if logger != nil {
				logger.Error("cert-renewal: target panicked; other targets continue",
					"target", target.Name, "panic", p)
			}
		}
	}()
	return evaluateAndReissue(ctx, target, threshold, now, logger)
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
	if err != nil || cert == nil {
		readErr := err
		if readErr == nil {
			readErr = ErrNilCurrentCertificate{}
		}
		// An endpoint that serves nothing readable is the one most likely to
		// NEED issuing -- a BMC still on a factory image, or one whose deploy
		// failed at boot. Give the target a say before writing it off, or it can
		// never converge: "failed" alone means the sweep re-reads and re-fails
		// every day forever.
		if target.DueOverride != nil {
			if due, reason := target.DueOverride(ctx, nil, readErr); due {
				r.DueReason = reason
				return reissueTarget(ctx, target, r, logger, reason)
			}
		}
		r.Action = "failed"
		r.Error = "current: " + readErr.Error()
		if logger != nil {
			logger.Warn("cert-renewal: cannot read current cert",
				"target", target.Name, "err", readErr)
		}
		return r
	}
	r.NotAfter = cert.NotAfter
	until := cert.NotAfter.Sub(now)
	r.DaysLeft = until.Hours() / 24

	dueReason := "expiry"
	due := until <= threshold
	if !due && target.DueOverride != nil {
		// A target may be due for reasons expiry cannot express -- see
		// CertTarget.DueOverride. Consulted only when expiry has not already
		// made it due, so the common path is unchanged.
		if overrideDue, reason := target.DueOverride(ctx, cert, nil); overrideDue {
			due, dueReason = true, reason
		}
	}

	if !due {
		r.Action = "skipped"
		if logger != nil {
			logger.Debug("cert-renewal: not due",
				"target", target.Name,
				"days_left", r.DaysLeft,
				"threshold_days", threshold.Hours()/24)
		}
		return r
	}

	r.DueReason = dueReason
	return reissueTarget(ctx, target, r, logger, dueReason)
}

// reissueTarget runs the reissuance and records its outcome. Shared by the
// expiry/override path and the unreadable-certificate path so both report
// identically.
func reissueTarget(
	ctx context.Context,
	target *CertTarget,
	r renewalResult,
	logger *slog.Logger,
	reason string,
) renewalResult {
	if err := target.Reissue(ctx); err != nil {
		r.Action = "failed"
		r.Error = "reissue: " + err.Error()
		if logger != nil {
			logger.Error("cert-renewal: reissue failed",
				"target", target.Name, "reason", reason, "err", err)
		}
		return r
	}
	r.Action = "renewed"
	if logger != nil {
		logger.Info("cert-renewal: renewed",
			"target", target.Name, "days_left_at_renewal", r.DaysLeft,
			"reason", reason)
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

// reportCertRenewalJobDrift warns when the stored renewal job no longer matches
// the spec this boot asked for.
//
// It cannot fix the drift: reconciling requires the scheduler's UpdateJob, whose
// JobUpdateParams type is not re-exported through go-quicbaas/sdk/go, and the
// platform may only import sdk/go. Reporting is the honest half -- an operator
// who edits the schedule and restarts otherwise has no way to learn that the
// old one is still in force.
func reportCertRenewalJobDrift(
	existing *quicbaas.Job,
	schedule string,
	timeout time.Duration,
	maxRetries int32,
	opts CertRenewalRegistration,
) {
	if opts.Logger == nil {
		return
	}
	var drift []any
	if existing.Schedule != schedule {
		drift = append(drift, "stored_schedule", existing.Schedule, "configured_schedule", schedule)
	}
	if existing.Timeout != timeout {
		drift = append(drift, "stored_timeout", existing.Timeout, "configured_timeout", timeout)
	}
	if existing.MaxRetries != maxRetries {
		drift = append(drift, "stored_max_retries", existing.MaxRetries, "configured_max_retries", maxRetries)
	}
	if len(drift) == 0 {
		return
	}
	drift = append(drift, "job_id", existing.ID, "node_id", opts.NodeID)
	opts.Logger.Warn("cert-renewal: the stored job does not match this node's "+
		"configuration and CANNOT be updated in place; the stored values remain in "+
		"force. Delete the job to have it recreated from the current configuration.",
		drift...)
}
