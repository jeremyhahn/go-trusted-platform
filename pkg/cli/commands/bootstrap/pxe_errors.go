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

package bootstrap

import "fmt"

// ErrPXEConfigRequired is returned when the --config flag is missing.
type ErrPXEConfigRequired struct{}

func (e ErrPXEConfigRequired) Error() string {
	return "bootstrap: --config flag is required"
}

// ErrPXEConfigLoadFailed is returned when the bootstrap config file cannot be loaded.
type ErrPXEConfigLoadFailed struct {
	Path  string
	Cause error
}

func (e ErrPXEConfigLoadFailed) Error() string {
	return fmt.Sprintf("bootstrap: failed to load config %s: %v", e.Path, e.Cause)
}

func (e ErrPXEConfigLoadFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEConfigValidationFailed is returned when the bootstrap config is invalid.
type ErrPXEConfigValidationFailed struct {
	Cause error
}

func (e ErrPXEConfigValidationFailed) Error() string {
	return fmt.Sprintf("bootstrap: config validation failed: %v", e.Cause)
}

func (e ErrPXEConfigValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrOrchestratorCreationFailed is returned when the orchestrator cannot be created.
type ErrOrchestratorCreationFailed struct {
	Cause error
}

func (e ErrOrchestratorCreationFailed) Error() string {
	return fmt.Sprintf("bootstrap: failed to create orchestrator: %v", e.Cause)
}

func (e ErrOrchestratorCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrPXERunFailed is returned when the bootstrap run operation fails.
type ErrPXERunFailed struct {
	Cause error
}

func (e ErrPXERunFailed) Error() string {
	return fmt.Sprintf("bootstrap: run failed: %v", e.Cause)
}

func (e ErrPXERunFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEDiscoveryFailed is returned when bootstrap discovery fails.
type ErrPXEDiscoveryFailed struct {
	Cause error
}

func (e ErrPXEDiscoveryFailed) Error() string {
	return fmt.Sprintf("bootstrap: discovery failed: %v", e.Cause)
}

func (e ErrPXEDiscoveryFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEDeployFailed is returned when bootstrap container deployment fails.
type ErrPXEDeployFailed struct {
	Cause error
}

func (e ErrPXEDeployFailed) Error() string {
	return fmt.Sprintf("bootstrap: deploy failed: %v", e.Cause)
}

func (e ErrPXEDeployFailed) Unwrap() error {
	return e.Cause
}

// ErrPXETeardownFailed is returned when bootstrap container teardown fails.
type ErrPXETeardownFailed struct {
	Cause error
}

func (e ErrPXETeardownFailed) Error() string {
	return fmt.Sprintf("bootstrap: teardown failed: %v", e.Cause)
}

func (e ErrPXETeardownFailed) Unwrap() error {
	return e.Cause
}

// ErrDeployerCreationFailed is returned when the deployer cannot be created.
type ErrDeployerCreationFailed struct {
	Host  string
	Cause error
}

func (e ErrDeployerCreationFailed) Error() string {
	return fmt.Sprintf("bootstrap: failed to create the deployer for host %s: %v", e.Host, e.Cause)
}

func (e ErrDeployerCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEDryRunFailed indicates the dry-run validation failed.
type ErrPXEDryRunFailed struct {
	Cause error
}

func (e ErrPXEDryRunFailed) Error() string {
	return "bootstrap dry-run failed: " + e.Cause.Error()
}

func (e ErrPXEDryRunFailed) Unwrap() error {
	return e.Cause
}

// ErrProbeInvalidFlag is returned when a `bootstrap probe` flag cannot be
// used as given.
type ErrProbeInvalidFlag struct {
	Flag   string
	Reason string
}

func (e *ErrProbeInvalidFlag) Error() string {
	if e.Flag == "" {
		return "bootstrap probe: " + e.Reason
	}
	return "bootstrap probe: " + e.Flag + ": " + e.Reason
}

// ErrProbeFailed is returned when the probed boot would have failed on a
// real client; the report printed before it says where.
type ErrProbeFailed struct {
	Cause error
}

func (e *ErrProbeFailed) Error() string { return "bootstrap probe: " + e.Cause.Error() }
func (e *ErrProbeFailed) Unwrap() error { return e.Cause }

// ErrResolveDumpFailed is returned when `bootstrap resolve --dump` cannot
// write a resolved config.
type ErrResolveDumpFailed struct {
	Path  string
	Cause error
}

func (e ErrResolveDumpFailed) Error() string {
	return "bootstrap resolve: write " + e.Path + ": " + e.Cause.Error()
}

func (e ErrResolveDumpFailed) Unwrap() error { return e.Cause }
