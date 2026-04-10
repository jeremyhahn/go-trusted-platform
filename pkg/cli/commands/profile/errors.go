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

package profile

import "fmt"

// ErrDaemonConnectionRequired is returned when daemon connection is required
type ErrDaemonConnectionRequired struct{}

func (e ErrDaemonConnectionRequired) Error() string {
	return "daemon connection required"
}

// ErrInvalidID is returned when an invalid profile ID is provided
type ErrInvalidID struct {
	ID string
}

func (e ErrInvalidID) Error() string {
	return fmt.Sprintf("invalid profile ID: %s", e.ID)
}

// ErrProfileNotFound is returned when a profile is not found
type ErrProfileNotFound struct {
	ID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("profile not found: %d", e.ID)
}

// ErrListProfilesFailed is returned when listing profiles fails
type ErrListProfilesFailed struct {
	Reason string
}

func (e ErrListProfilesFailed) Error() string {
	return fmt.Sprintf("failed to list profiles: %s", e.Reason)
}

// ErrGetProfileFailed is returned when getting a profile fails
type ErrGetProfileFailed struct {
	ID     uint64
	Reason string
}

func (e ErrGetProfileFailed) Error() string {
	return fmt.Sprintf("failed to get profile %d: %s", e.ID, e.Reason)
}

// ErrDeleteProfileFailed is returned when deleting a profile fails
type ErrDeleteProfileFailed struct {
	ID     uint64
	Reason string
}

func (e ErrDeleteProfileFailed) Error() string {
	return fmt.Sprintf("failed to delete profile %d: %s", e.ID, e.Reason)
}

// ErrMatchProfileFailed is returned when matching a profile fails
type ErrMatchProfileFailed struct {
	Reason string
}

func (e ErrMatchProfileFailed) Error() string {
	return fmt.Sprintf("failed to match profile: %s", e.Reason)
}

// ErrNoMatchCriteria is returned when no match criteria is provided
type ErrNoMatchCriteria struct{}

func (e ErrNoMatchCriteria) Error() string {
	return "at least one of --mac, --serial, or --model is required"
}

// ErrNoMatchingProfile is returned when no matching profile is found
type ErrNoMatchingProfile struct{}

func (e ErrNoMatchingProfile) Error() string {
	return "no matching profile found"
}
