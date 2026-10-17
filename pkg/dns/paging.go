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

package dns

// Paging of the zone and record lists. Every transport pages through these
// rules so a page means the same thing on each (docs/dns/api.md).
const (
	// DefaultPageLimit is the page size when a caller sends none, or one
	// below 1.
	DefaultPageLimit = 50

	// MaxPageLimit caps the page size a caller may ask for.
	MaxPageLimit = 1000
)

// Page is the window one list request covers over a list of items.
type Page struct {
	// Limit and Offset are the page size and position the request
	// resolves to, after clamping.
	Limit  int
	Offset int

	// Start and End bound the page within the list: items[Start:End].
	Start int
	End   int
}

// NewPage resolves a requested limit and offset over a list of n items. A
// limit below 1 is DefaultPageLimit, one above MaxPageLimit is MaxPageLimit,
// and an offset below 0 is 0. When paged is false the caller asked for no
// page, so the window is the whole list while Limit and Offset still report
// what the request resolved to (the defaults when it sent neither), as the
// REST list routes always have.
func NewPage(n, limit, offset int, paged bool) Page {
	if limit < 1 {
		limit = DefaultPageLimit
	}
	limit = min(limit, MaxPageLimit)
	offset = max(offset, 0)

	page := Page{Limit: limit, Offset: offset, Start: 0, End: n}
	if paged {
		page.Start = min(offset, n)
		page.End = min(page.Start+limit, n)
	}
	return page
}
