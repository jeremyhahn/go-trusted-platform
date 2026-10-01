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

// ErrOOBAllowTo is returned when the out-of-band zone opens a path to
// another zone: management never reaches a data zone.
type ErrOOBAllowTo struct {
	// Zone is the OOB zone.
	Zone Zone
	// To is the zone it tried to reach.
	To Zone
}

// Error implements the error interface.
func (e ErrOOBAllowTo) Error() string {
	return fmt.Sprintf("zone: out-of-band zone %q cannot allow_to %q: it never reaches another zone", e.Zone, e.To)
}

// ErrOmitRequired is returned when an operator entry omits a built-in zone
// the platform cannot run without (fabric, provisioning, quarantine,
// control-plane).
type ErrOmitRequired struct {
	// Zone is the built-in zone that was omitted.
	Zone Zone
}

// Error implements the error interface.
func (e ErrOmitRequired) Error() string {
	return fmt.Sprintf("zone: built-in zone %q is required and cannot be omitted", e.Zone)
}

// ErrOmitUnknown is returned when an operator entry sets omit on a name that
// is not a built-in zone.
type ErrOmitUnknown struct {
	// Zone is the name the entry tried to omit.
	Zone Zone
}

// Error implements the error interface.
func (e ErrOmitUnknown) Error() string {
	return fmt.Sprintf("zone: omit on %q: only a built-in zone can be omitted", e.Zone)
}

// ErrBuiltinIdentity is returned when an operator entry for a built-in zone
// tries to change its identity: offset, port classes, lifecycle role or OOB.
// Built-in zones have fixed numbering; only their policy can be tuned.
type ErrBuiltinIdentity struct {
	// Zone is the built-in zone.
	Zone Zone
	// Field is the identity field the entry tried to change.
	Field string
}

// Error implements the error interface.
func (e ErrBuiltinIdentity) Error() string {
	return fmt.Sprintf("zone: built-in zone %q cannot change %s; only its policy can be tuned", e.Zone, e.Field)
}

// ErrReservedZoneName is returned for a zone named after an overlay kind
// (platform, tenant, public) or the retired "trusted" zone. Overlays are
// never zones.
type ErrReservedZoneName struct {
	// Name is the reserved name.
	Name Zone
}

// Error implements the error interface.
func (e ErrReservedZoneName) Error() string {
	return fmt.Sprintf("zone: %q is reserved and cannot name a zone (overlays are not zones)", e.Name)
}

// ErrDuplicateOffset is returned when two zones take the same offset.
type ErrDuplicateOffset struct {
	// Offset is the shared offset.
	Offset Offset
	// Zones are the two zones that claim it.
	Zones [2]Zone
}

// Error implements the error interface.
func (e ErrDuplicateOffset) Error() string {
	return fmt.Sprintf("zone: zones %q and %q both take offset %02d", e.Zones[0], e.Zones[1], e.Offset)
}

// ErrOwnerZoneOffset is returned when an owner-defined zone's offset is
// outside 9–99.
type ErrOwnerZoneOffset struct {
	// Zone is the owner-defined zone.
	Zone Zone
	// Offset is the offending offset.
	Offset Offset
}

// Error implements the error interface.
func (e ErrOwnerZoneOffset) Error() string {
	return fmt.Sprintf("zone: owner-defined zone %q must take an offset in %02d-%02d, got %02d",
		e.Zone, MinOwnerOffset, MaxOffset, e.Offset)
}

// ErrOwnerZonePortClass is returned when an owner-defined zone joins no port
// class, or a class other than gateway and hypervisor.
type ErrOwnerZonePortClass struct {
	// Zone is the owner-defined zone.
	Zone Zone
	// Class is the offending class; empty when the zone joins none.
	Class PortClass
}

// Error implements the error interface.
func (e ErrOwnerZonePortClass) Error() string {
	if e.Class == "" {
		return fmt.Sprintf("zone: owner-defined zone %q must join the gateway or hypervisor port class", e.Zone)
	}
	return fmt.Sprintf("zone: owner-defined zone %q cannot join port class %q (gateway or hypervisor only)", e.Zone, e.Class)
}

// ErrOwnerZoneField is returned when an owner-defined zone sets a field that
// only a built-in zone may carry (lifecycle_role, oob).
type ErrOwnerZoneField struct {
	// Zone is the owner-defined zone.
	Zone Zone
	// Field is the built-in-only field.
	Field string
}

// Error implements the error interface.
func (e ErrOwnerZoneField) Error() string {
	return fmt.Sprintf("zone: owner-defined zone %q cannot set %s", e.Zone, e.Field)
}

// ErrPrivilegedAccessRequired is returned when a zone's allow_to opens a
// path into control-plane or management beyond the reference defaults
// without a complete privileged_access override (reason and approved_by).
type ErrPrivilegedAccessRequired struct {
	// Zone is the source zone.
	Zone Zone
	// To is the privileged destination.
	To Zone
}

// Error implements the error interface.
func (e ErrPrivilegedAccessRequired) Error() string {
	return fmt.Sprintf("zone: %q allow_to %q needs a privileged_access override with reason and approved_by", e.Zone, e.To)
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
