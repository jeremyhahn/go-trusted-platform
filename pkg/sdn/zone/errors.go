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

package zone

import (
	"fmt"
)

// ErrDuplicateZone is returned when two zone configs share the same name.
type ErrDuplicateZone struct {
	// Name is the duplicated zone name.
	Name Zone
}

// Error implements the error interface.
func (e ErrDuplicateZone) Error() string {
	return fmt.Sprintf("zone: duplicate zone name %q", e.Name)
}

// ErrEmptyZoneName is returned when a zone config carries an empty name.
type ErrEmptyZoneName struct{}

// Error implements the error interface.
func (e ErrEmptyZoneName) Error() string {
	return "zone: zone name must not be empty"
}

// ErrInvalidZoneName is returned when a zone name is not a lowercase
// DNS-label-safe identifier.
type ErrInvalidZoneName struct {
	// Name is the offending zone name.
	Name Zone
}

// Error implements the error interface.
func (e ErrInvalidZoneName) Error() string {
	return fmt.Sprintf("zone: zone name %q is not a lowercase DNS-label-safe identifier", e.Name)
}

// ErrLifecycleRoleCount is returned when the number of zones carrying a
// required lifecycle role is not exactly one.
type ErrLifecycleRoleCount struct {
	// Role is the lifecycle role in question.
	Role LifecycleRole
	// Count is the actual number of zones found with that role.
	Count int
}

// Error implements the error interface.
func (e ErrLifecycleRoleCount) Error() string {
	return fmt.Sprintf("zone: exactly one zone must carry lifecycle role %q, found %d", e.Role, e.Count)
}

// ErrInvalidLifecycleRole is returned when a zone carries an unrecognised
// lifecycle role value.
type ErrInvalidLifecycleRole struct {
	// Zone is the zone whose role is invalid.
	Zone Zone
	// Role is the unrecognised value.
	Role LifecycleRole
}

// Error implements the error interface.
func (e ErrInvalidLifecycleRole) Error() string {
	return fmt.Sprintf("zone: zone %q has unknown lifecycle role %q", e.Zone, e.Role)
}

// ErrUnknownZoneRef is returned when a zone's IsolateFrom or AllowTo entry
// references a zone name that is not declared in the resolved set.
type ErrUnknownZoneRef struct {
	// Source is the zone that contains the reference.
	Source Zone
	// Field is "isolate_from" or "allow_to".
	Field string
	// Target is the undeclared zone name that was referenced.
	Target Zone
}

// Error implements the error interface.
func (e ErrUnknownZoneRef) Error() string {
	return fmt.Sprintf("zone: %q.%s references undeclared zone %q", e.Source, e.Field, e.Target)
}

// ErrOOBWithInternetIngress is returned when a zone is marked both OOB and
// InternetIngress, which is contradictory.
type ErrOOBWithInternetIngress struct {
	// Zone is the offending zone name.
	Zone Zone
}

// Error implements the error interface.
func (e ErrOOBWithInternetIngress) Error() string {
	return fmt.Sprintf("zone: zone %q is marked oob and internet_ingress; these are mutually exclusive", e.Zone)
}

// ErrOmitLifecycleHolder is returned when a user entry omits a built-in zone
// that carries a lifecycle role and no other zone in the resolved set takes
// that role.
type ErrOmitLifecycleHolder struct {
	// Zone is the built-in zone that was omitted.
	Zone Zone
	// Role is the lifecycle role that became uncovered.
	Role LifecycleRole
}

// Error implements the error interface.
func (e ErrOmitLifecycleHolder) Error() string {
	return fmt.Sprintf(
		"zone: omitting built-in zone %q leaves lifecycle role %q without a holder",
		e.Zone, e.Role,
	)
}

// ErrNoZoneForRole is returned by ZoneForRole when no zone in the set carries
// the requested lifecycle role.
type ErrNoZoneForRole struct {
	// Role is the lifecycle role that was not found.
	Role LifecycleRole
}

// Error implements the error interface.
func (e ErrNoZoneForRole) Error() string {
	return fmt.Sprintf("zone: no zone carries lifecycle role %q", e.Role)
}

// isDNSLabelSafe reports whether s is a non-empty lowercase string containing
// only ASCII letters, digits, and hyphens, and not starting or ending with a
// hyphen.  This matches the DNS label constraint described in RFC 1123.
func isDNSLabelSafe(s string) bool {
	if len(s) == 0 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !isDNSLabelChar(r) {
			return false
		}
	}
	return true
}

// isDNSLabelChar reports whether r may appear inside a DNS label: a lowercase
// ASCII letter, a digit, or a hyphen.
func isDNSLabelChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
}

// validLifecycleRoles is the set of recognised LifecycleRole values (excluding
// the empty string, which is always valid).
var validLifecycleRoles = map[LifecycleRole]struct{}{
	LifecycleRoleProvisioning: {},
	LifecycleRoleQuarantine:   {},
}

// requiredLifecycleRoles lists the roles that must each appear exactly once.
var requiredLifecycleRoles = []LifecycleRole{
	LifecycleRoleProvisioning,
	LifecycleRoleQuarantine,
}
