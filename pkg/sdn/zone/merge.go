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

import "sort"

// Resolve merges operator zone entries onto the built-in zones and returns
// the resolved set: the built-ins in offset order, then the owner-defined
// zones in offset order.
//
// An operator entry whose name matches a built-in tunes that built-in's
// policy: InternetIngress, IsolateFrom, AllowTo, Services, Isolate and
// PrivilegedAccess replace the built-in's values. The built-in's identity —
// offset, port classes, OOB and lifecycle role — is kept; an entry may
// repeat it but never change it (ErrBuiltinIdentity). An entry with Omit set
// drops an optional built-in (ErrOmitRequired for the ones the platform
// needs). Every other entry is an owner-defined zone and is appended as
// written; Validate checks its offset and port classes.
func Resolve(user []ZoneConfig) ([]ZoneConfig, error) {
	userByName := make(map[Zone]ZoneConfig, len(user))
	for _, u := range user {
		if _, dup := userByName[u.Name]; dup {
			return nil, ErrDuplicateZone{Name: u.Name}
		}
		userByName[u.Name] = u
	}

	out := make([]ZoneConfig, 0, len(builtins)+len(user))
	for _, b := range builtins {
		u, tuned := userByName[b.Name]
		if !tuned {
			out = append(out, copyZoneConfig(b))
			continue
		}
		if u.Omit {
			if _, required := requiredBuiltins[b.Name]; required {
				return nil, ErrOmitRequired{Zone: b.Name}
			}
			continue
		}
		merged, err := tuneBuiltin(b, u)
		if err != nil {
			return nil, err
		}
		out = append(out, merged)
	}

	owner := make([]ZoneConfig, 0, len(user))
	for _, u := range user {
		if IsBuiltin(u.Name) {
			continue
		}
		if u.Omit {
			return nil, ErrOmitUnknown{Zone: u.Name}
		}
		owner = append(owner, copyZoneConfig(u))
	}
	sort.SliceStable(owner, func(i, j int) bool { return owner[i].Offset < owner[j].Offset })

	return append(out, owner...), nil
}

// tuneBuiltin applies the policy fields of the operator entry u to the
// built-in b, refusing any change to b's identity.
func tuneBuiltin(b, u ZoneConfig) (ZoneConfig, error) {
	if u.Offset != 0 && u.Offset != b.Offset {
		return ZoneConfig{}, ErrBuiltinIdentity{Zone: b.Name, Field: "offset"}
	}
	if u.PortClasses != nil && !samePortClasses(u.PortClasses, b.PortClasses) {
		return ZoneConfig{}, ErrBuiltinIdentity{Zone: b.Name, Field: "port_classes"}
	}
	if u.LifecycleRole != "" && u.LifecycleRole != b.LifecycleRole {
		return ZoneConfig{}, ErrBuiltinIdentity{Zone: b.Name, Field: "lifecycle_role"}
	}
	if u.OOB != b.OOB && u.OOB {
		return ZoneConfig{}, ErrBuiltinIdentity{Zone: b.Name, Field: "oob"}
	}

	merged := copyZoneConfig(b)
	tuned := copyZoneConfig(u)
	merged.InternetIngress = tuned.InternetIngress
	merged.IsolateFrom = tuned.IsolateFrom
	merged.AllowTo = tuned.AllowTo
	merged.Services = tuned.Services
	merged.Isolate = tuned.Isolate
	merged.PrivilegedAccess = tuned.PrivilegedAccess
	return merged, nil
}

// samePortClasses reports whether a and b hold the same classes in any
// order.
func samePortClasses(a, b []PortClass) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[PortClass]int, len(a))
	for _, c := range a {
		set[c]++
	}
	for _, c := range b {
		set[c]--
	}
	for _, n := range set {
		if n != 0 {
			return false
		}
	}
	return true
}
