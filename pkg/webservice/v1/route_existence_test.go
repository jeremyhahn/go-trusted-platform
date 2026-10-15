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

package v1

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// routeGoldenPath holds every "METHOD /template" the built table exposes.
const routeGoldenPath = "testdata/routes.golden"

// minimumRoutes is a vacuity floor, not the assertion.
//
// The assertion is the golden comparison below. This exists so that a renamed
// fixture, a moved package or a router that fails to build cannot turn this
// test into a pass over an empty set -- the failure mode that made every
// OTHER route-table test in this package unable to notice a deleted router
// (#348). A guard that cannot fail is worse than no guard, because it reads
// as coverage.
const minimumRoutes = 300

// TestRegisterRoutes_EveryRouteStillExists asserts route EXISTENCE.
//
// Every other route-table test in this package asserts a property OF EACH
// ROUTE THAT HAPPENS TO BE THERE -- that it denies without a credential, that
// it carries an exemption justification, that a client claim resolves. All of
// them iterate the built table, so deleting a live router makes every one of
// them iterate a smaller set and pass. This is the test that notices.
//
// It compares the built table against a checked-in list rather than counting,
// because a count hides a swap: twelve routes added under one prefix and
// twelve removed under another nets to zero.
//
// WHEN THIS FAILS the diff on testdata/routes.golden is the review artifact,
// and it is designed to be read rather than approved:
//
//   - every line is one "METHOD /template" -- semantic, not serialized state;
//   - the list is sorted, so a change is a minimal +/- rather than a reflow;
//   - an ADDED line is a new route, and the reviewer's question is whether it
//     is authorized (TestRegisterRoutes_EveryRouteDeniesWithoutCredential
//     answers that independently);
//   - a REMOVED line is a route the platform no longer serves, and that is a
//     claim about the product, not about the test. It needs a sentence in the
//     PR saying who called it and why they no longer do.
//
// Regenerate deliberately, by hand or by pasting the reported lines. There is
// intentionally no -update flag: the cost of editing this file is the point,
// and a flag turns a decision into a keystroke.
func TestRegisterRoutes_EveryRouteStillExists(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := testutil.WalkRoutes(t, router)

	require.GreaterOrEqualf(t, len(built), minimumRoutes,
		"the route walk enumerated only %d routes, below the %d vacuity floor. "+
			"The fixture almost certainly failed to build the table -- fix that rather "+
			"than lowering the floor, or this test passes over an empty set",
		len(built), minimumRoutes)

	data, err := os.ReadFile(routeGoldenPath)
	require.NoError(t, err, "missing %s -- it is the assertion, not a cache", routeGoldenPath)

	golden := make([]string, 0, len(built))
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			golden = append(golden, line)
		}
	}
	sort.Strings(golden)

	added, removed := diffRouteSets(golden, built)

	if len(removed) > 0 {
		t.Errorf("%d route(s) the platform used to serve are GONE from the built table.\n"+
			"This is the deletion every other route test in this package cannot see.\n"+
			"If it is intended, remove these lines from %s and say in the PR who called "+
			"them and why they no longer do:\n  %s",
			len(removed), routeGoldenPath, strings.Join(removed, "\n  "))
	}
	if len(added) > 0 {
		t.Errorf("%d new route(s) are not recorded in %s.\n"+
			"Add these lines, and check each is gated -- a new route is unauthenticated "+
			"until something says otherwise:\n  %s",
			len(added), routeGoldenPath, strings.Join(added, "\n  "))
	}
}

// diffRouteSets returns the routes present only in built (added) and only in
// golden (removed).
func diffRouteSets(golden, built []string) (added, removed []string) {
	inGolden := make(map[string]bool, len(golden))
	for _, r := range golden {
		inGolden[r] = true
	}
	inBuilt := make(map[string]bool, len(built))
	for _, r := range built {
		inBuilt[r] = true
	}

	for _, r := range built {
		if !inGolden[r] {
			added = append(added, r)
		}
	}
	for _, r := range golden {
		if !inBuilt[r] {
			removed = append(removed, r)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
