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

// Validate checks a resolved zone set (the output of Resolve):
//
//   - names are non-empty, DNS-label safe, unique and not reserved;
//   - built-in zones keep their offsets; owner-defined zones take a unique
//     offset in 9–99, join at least one of the gateway and hypervisor port
//     classes, and carry neither a lifecycle role nor OOB;
//   - exactly one zone carries each required lifecycle role;
//   - OOB and InternetIngress are mutually exclusive, and an OOB zone opens
//     no path to another zone;
//   - IsolateFrom and AllowTo reference declared zones;
//   - every AllowTo path into control-plane or management that the reference
//     defaults do not open carries a complete PrivilegedAccess override.
func Validate(zones []ZoneConfig) error {
	declared := make(map[Zone]struct{}, len(zones))
	offsets := make(map[Offset]Zone, len(zones))
	for _, z := range zones {
		if err := validateIdentity(z); err != nil {
			return err
		}
		if _, dup := declared[z.Name]; dup {
			return ErrDuplicateZone{Name: z.Name}
		}
		declared[z.Name] = struct{}{}
		if other, dup := offsets[z.Offset]; dup {
			return ErrDuplicateOffset{Offset: z.Offset, Zones: [2]Zone{other, z.Name}}
		}
		offsets[z.Offset] = z.Name
	}

	roleCounts := make(map[LifecycleRole]int, len(validLifecycleRoles))
	for _, z := range zones {
		if z.LifecycleRole == "" {
			continue
		}
		if _, ok := validLifecycleRoles[z.LifecycleRole]; !ok {
			return ErrInvalidLifecycleRole{Zone: z.Name, Role: z.LifecycleRole}
		}
		roleCounts[z.LifecycleRole]++
	}
	for _, role := range requiredLifecycleRoles {
		if roleCounts[role] != 1 {
			return ErrLifecycleRoleCount{Role: role, Count: roleCounts[role]}
		}
	}

	for _, z := range zones {
		if z.OOB && z.InternetIngress {
			return ErrOOBWithInternetIngress{Zone: z.Name}
		}
		if z.OOB {
			for _, path := range z.AllowTo {
				if path.Zone != z.Name {
					return ErrOOBAllowTo{Zone: z.Name, To: path.Zone}
				}
			}
		}
		for _, ref := range z.IsolateFrom {
			if _, ok := declared[ref]; !ok {
				return ErrUnknownZoneRef{Source: z.Name, Field: "isolate_from", Target: ref}
			}
		}
		for _, path := range z.AllowTo {
			if _, ok := declared[path.Zone]; !ok {
				return ErrUnknownZoneRef{Source: z.Name, Field: "allow_to", Target: path.Zone}
			}
		}
		if err := validatePrivilegedAccess(z); err != nil {
			return err
		}
	}

	return nil
}

// validateIdentity checks a zone's name, offset, port classes, lifecycle
// role and OOB flag against whether it is built in or owner-defined.
func validateIdentity(z ZoneConfig) error {
	if z.Name == "" {
		return ErrEmptyZoneName{}
	}
	if !isDNSLabelSafe(string(z.Name)) {
		return ErrInvalidZoneName{Name: z.Name}
	}
	if _, reserved := reservedNames[z.Name]; reserved {
		return ErrReservedZoneName{Name: z.Name}
	}

	if b, ok := Builtin(z.Name); ok {
		if z.Offset != b.Offset {
			return ErrBuiltinIdentity{Zone: z.Name, Field: "offset"}
		}
		if !samePortClasses(z.PortClasses, b.PortClasses) {
			return ErrBuiltinIdentity{Zone: z.Name, Field: "port_classes"}
		}
		if z.LifecycleRole != b.LifecycleRole {
			return ErrBuiltinIdentity{Zone: z.Name, Field: "lifecycle_role"}
		}
		if z.OOB != b.OOB {
			return ErrBuiltinIdentity{Zone: z.Name, Field: "oob"}
		}
		return nil
	}

	if z.Offset < MinOwnerOffset || z.Offset > MaxOffset {
		return ErrOwnerZoneOffset{Zone: z.Name, Offset: z.Offset}
	}
	if len(z.PortClasses) == 0 {
		return ErrOwnerZonePortClass{Zone: z.Name}
	}
	for _, c := range z.PortClasses {
		if _, ok := ownerPortClasses[c]; !ok {
			return ErrOwnerZonePortClass{Zone: z.Name, Class: c}
		}
	}
	if z.LifecycleRole != "" {
		return ErrOwnerZoneField{Zone: z.Name, Field: "lifecycle_role"}
	}
	if z.OOB {
		return ErrOwnerZoneField{Zone: z.Name, Field: "oob"}
	}
	return nil
}

// validatePrivilegedAccess requires a complete PrivilegedAccess override on
// a zone whose AllowTo opens a privileged path.
func validatePrivilegedAccess(z ZoneConfig) error {
	paths := privilegedPaths(z)
	if len(paths) == 0 {
		return nil
	}
	pa := z.PrivilegedAccess
	if pa == nil || pa.Reason == "" || pa.ApprovedBy == "" {
		return ErrPrivilegedAccessRequired{Zone: z.Name, To: paths[0].Zone}
	}
	return nil
}

// PrivilegedPaths returns every AllowTo path in zones that goes into
// control-plane or management beyond the reference defaults, with the
// override that permits it. It is meant for a validated set; callers log
// each entry as an audit event when the zone set is loaded.
func PrivilegedPaths(zones []ZoneConfig) []PrivilegedPath {
	var out []PrivilegedPath
	for _, z := range zones {
		if z.PrivilegedAccess == nil {
			continue
		}
		for _, p := range privilegedPaths(z) {
			svc := make([]string, len(p.Services))
			copy(svc, p.Services)
			out = append(out, PrivilegedPath{
				From:     z.Name,
				To:       p.Zone,
				Services: svc,
				Access:   *z.PrivilegedAccess,
			})
		}
	}
	return out
}

// privilegedPaths returns the AllowTo paths of z into a privileged zone that
// z's built-in defaults do not already open.
func privilegedPaths(z ZoneConfig) []ZonePath {
	var defaults []ZonePath
	if b, ok := Builtin(z.Name); ok {
		defaults = b.AllowTo
	}
	var out []ZonePath
	for _, p := range z.AllowTo {
		if _, privileged := privilegedZones[p.Zone]; !privileged {
			continue
		}
		if p.Zone == z.Name {
			// Traffic inside a zone never crosses into it.
			continue
		}
		if coveredBy(p, defaults) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// coveredBy reports whether path p opens nothing that one of the default
// paths does not already open: the same destination, and services that are
// a subset of the default's (an empty list means all services).
func coveredBy(p ZonePath, defaults []ZonePath) bool {
	for _, d := range defaults {
		if d.Zone != p.Zone {
			continue
		}
		if len(d.Services) == 0 {
			return true
		}
		if len(p.Services) == 0 {
			return false
		}
		allowed := make(map[string]struct{}, len(d.Services))
		for _, s := range d.Services {
			allowed[s] = struct{}{}
		}
		subset := true
		for _, s := range p.Services {
			if _, ok := allowed[s]; !ok {
				subset = false
				break
			}
		}
		if subset {
			return true
		}
	}
	return false
}
