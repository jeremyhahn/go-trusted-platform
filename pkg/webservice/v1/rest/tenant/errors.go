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

package tenant

// ErrAuthorizationRequired is returned when NewTenantRouter is called without
// a guard it needs. Every route under /{id} takes its target tenant from the
// URL, so publishing this surface without the guards would let any caller
// holding the "admin" role act on any tenant by changing a path segment
// (#234). Failing construction is the only safe response: the caller then
// leaves the routes unregistered.
type ErrAuthorizationRequired struct {
	Guard string
}

// Error implements the error interface.
func (e ErrAuthorizationRequired) Error() string {
	return "tenant router: missing authorization guard: " + e.Guard
}
