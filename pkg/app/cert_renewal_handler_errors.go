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
	"errors"
	"fmt"
)

// ErrCertRenewalMissingScheduler indicates RegisterCertRenewal was
// called without a SchedulerService.
var ErrCertRenewalMissingScheduler = errors.New("app: cert-renewal registration requires a SchedulerService")

// ErrCertRenewalMissingRegistry indicates RegisterCertRenewal was
// called without a CertTargetRegistry.
var ErrCertRenewalMissingRegistry = errors.New("app: cert-renewal registration requires a CertTargetRegistry")

// ErrCertRenewalMissingNodeID indicates RegisterCertRenewal was
// called without a NodeID. NodeID drives both the per-node job name
// and the scheduler NodeAffinity field, both required for correct
// per-node dispatch in clusters.
var ErrCertRenewalMissingNodeID = errors.New("app: cert-renewal registration requires a NodeID")

// ErrCertRenewalRegisterHandler wraps a failure during handler
// registration with the scheduler engine.
type ErrCertRenewalRegisterHandler struct {
	Cause error
}

func (e ErrCertRenewalRegisterHandler) Error() string {
	return fmt.Sprintf("app: cert-renewal handler registration failed: %v", e.Cause)
}

func (e ErrCertRenewalRegisterHandler) Unwrap() error { return e.Cause }

// ErrCertRenewalListJobs wraps a failure listing existing jobs
// during the idempotent job-creation check.
type ErrCertRenewalListJobs struct {
	Cause error
}

func (e ErrCertRenewalListJobs) Error() string {
	return fmt.Sprintf("app: cert-renewal listjobs failed during idempotent boot: %v", e.Cause)
}

func (e ErrCertRenewalListJobs) Unwrap() error { return e.Cause }

// ErrCertRenewalScheduleJob wraps a failure scheduling the per-node
// renewal job.
type ErrCertRenewalScheduleJob struct {
	Cause error
}

func (e ErrCertRenewalScheduleJob) Error() string {
	return fmt.Sprintf("app: cert-renewal job scheduling failed: %v", e.Cause)
}

func (e ErrCertRenewalScheduleJob) Unwrap() error { return e.Cause }
