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

// ErrInitBMCCertMissingNodeID indicates initBMCCertManagement was
// called without a NodeID. Required because NodeID drives both the
// cert target name and the scheduler NodeAffinity field.
var ErrInitBMCCertMissingNodeID = errors.New("app: initBMCCertManagement requires NodeID")

// ErrInitBMCCertMissingRegistry indicates initBMCCertManagement was
// called without a *CertTargetRegistry.
var ErrInitBMCCertMissingRegistry = errors.New("app: initBMCCertManagement requires Registry")

// ErrInitBMCCertMissingScheduler indicates initBMCCertManagement was
// called without a SchedulerService.
var ErrInitBMCCertMissingScheduler = errors.New("app: initBMCCertManagement requires Scheduler")

// ErrInitBMCCertIssue wraps a failure in the initial cert issuance
// step. Wraps the underlying cause so callers can errors.Is / .As
// down to the specific issuance error (ErrBMCACMEIssuance,
// ErrBMCLocalIssuance, ErrBMCDeploy, etc.).
type ErrInitBMCCertIssue struct {
	DeviceID string
	Cause    error
}

func (e ErrInitBMCCertIssue) Error() string {
	return fmt.Sprintf("app: BMC cert init failed for %s: %v", e.DeviceID, e.Cause)
}

func (e ErrInitBMCCertIssue) Unwrap() error { return e.Cause }

// ErrInitBMCCertRegister wraps a failure registering the issued
// target in the registry.
type ErrInitBMCCertRegister struct {
	DeviceID string
	Cause    error
}

func (e ErrInitBMCCertRegister) Error() string {
	return fmt.Sprintf("app: BMC cert target registration failed for %s: %v", e.DeviceID, e.Cause)
}

func (e ErrInitBMCCertRegister) Unwrap() error { return e.Cause }
