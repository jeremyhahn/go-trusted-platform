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

// Resolve merges user-supplied zone configs with the built-in defaults and
// returns the resolved set.  Merge semantics:
//
//   - A user entry whose name matches a built-in fully overrides that built-in.
//   - A user entry with Omit=true and a matching built-in name drops the
//     built-in from the resolved set.  Omitting a built-in that carries a
//     lifecycle role is only valid when another zone in the user set already
//     takes that role; otherwise Resolve returns ErrOmitLifecycleHolder.
//   - Built-ins not matched by any user entry are included unchanged.
//   - User entries with names that do not match any built-in are appended as
//     new zones.
//
// Resolve does not run full validation; call Validate on the result for that.
func Resolve(user []ZoneConfig) ([]ZoneConfig, error) {
	// Index user entries by name for O(1) lookup.
	userByName := make(map[Zone]ZoneConfig, len(user))
	for _, u := range user {
		userByName[u.Name] = u
	}

	// Build index of built-in lifecycle roles so we can check omit safety.
	builtinRole := make(map[Zone]LifecycleRole, len(builtins))
	for _, b := range builtins {
		if b.LifecycleRole != "" {
			builtinRole[b.Name] = b.LifecycleRole
		}
	}

	// Collect user-declared lifecycle roles (for omit-safety check).
	userRoles := make(map[LifecycleRole]struct{})
	for _, u := range user {
		if !u.Omit && u.LifecycleRole != "" {
			userRoles[u.LifecycleRole] = struct{}{}
		}
	}

	// Build a set of built-in names for quick lookup.
	builtinNames := make(map[Zone]struct{}, len(builtins))
	for _, b := range builtins {
		builtinNames[b.Name] = struct{}{}
	}

	// Walk built-ins; apply overrides, omissions, and retain unchanged ones.
	out := make([]ZoneConfig, 0, len(builtins)+len(user))
	for _, b := range builtins {
		u, overridden := userByName[b.Name]
		if !overridden {
			// No user entry for this built-in; keep it as-is.
			out = append(out, copyZoneConfig(b))
			continue
		}
		if u.Omit {
			// User wants to drop this built-in.  Validate that its lifecycle
			// role (if any) is covered by another user zone.
			if role, hasRole := builtinRole[b.Name]; hasRole {
				if _, covered := userRoles[role]; !covered {
					return nil, ErrOmitLifecycleHolder{Zone: b.Name, Role: role}
				}
			}
			// Omit: do not add to output.
			continue
		}
		// Full override: use the user's declaration.
		out = append(out, copyZoneConfig(u))
	}

	// Append user-added zones (names that are not built-ins).
	for _, u := range user {
		if _, isBuiltin := builtinNames[u.Name]; isBuiltin {
			// Already handled above.
			continue
		}
		if u.Omit {
			// Omit on a non-built-in is a no-op; skip.
			continue
		}
		out = append(out, copyZoneConfig(u))
	}

	return out, nil
}
