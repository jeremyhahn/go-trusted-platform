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

// Validate checks a resolved zone set for internal consistency.  The checks
// performed are:
//
//   - No duplicate zone names.
//   - Every name is a non-empty, lowercase DNS-label-safe string.
//   - Every LifecycleRole value is either empty or one of the recognised
//     constants.
//   - Exactly one zone carries LifecycleRoleProvisioning and exactly one
//     carries LifecycleRoleQuarantine.
//   - Every Zone name referenced in IsolateFrom or AllowTo exists in the
//     resolved set.
//   - OOB zones do not also have InternetIngress.
//
// Validate returns the first error encountered.  It does not accumulate a
// list of errors; callers that want all errors should call it iteratively
// after fixing each defect.
func Validate(zones []ZoneConfig) error {
	// Build name index while checking for duplicates and name validity.
	declared := make(map[Zone]struct{}, len(zones))
	for _, z := range zones {
		if z.Name == "" {
			return ErrEmptyZoneName{}
		}
		if !isDNSLabelSafe(string(z.Name)) {
			return ErrInvalidZoneName{Name: z.Name}
		}
		if _, dup := declared[z.Name]; dup {
			return ErrDuplicateZone{Name: z.Name}
		}
		declared[z.Name] = struct{}{}
	}

	// Validate lifecycle roles and count required ones.
	roleCounts := make(map[LifecycleRole]int, len(validLifecycleRoles))
	for _, z := range zones {
		r := z.LifecycleRole
		if r == "" {
			continue
		}
		if _, ok := validLifecycleRoles[r]; !ok {
			return ErrInvalidLifecycleRole{Zone: z.Name, Role: r}
		}
		roleCounts[r]++
	}
	for _, role := range requiredLifecycleRoles {
		if roleCounts[role] != 1 {
			return ErrLifecycleRoleCount{Role: role, Count: roleCounts[role]}
		}
	}

	// Validate cross-references and OOB invariants.
	for _, z := range zones {
		if z.OOB && z.InternetIngress {
			return ErrOOBWithInternetIngress{Zone: z.Name}
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
	}

	return nil
}
