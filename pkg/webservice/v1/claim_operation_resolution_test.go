package v1

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// A claim that RESOLVES is not a claim that resolves CORRECTLY.
//
// TestSDKRouteClaims_ResolveAgainstBuiltRoutes asserts every claim reaches some
// server route, which is necessary and not sufficient: a claim whose path has a
// literal segment where the server serves a {placeholder} still matches, and the
// server then answers about a different resource. RemoveGroupMember landing on
// DeleteGroup with id="members" is the shape -- the client deletes the group.
//
// #321 recorded that as "returned the wrong resource rather than an error",
// which is why RouteClaim's own doc says consumers must match by ROUTING a
// concrete path rather than comparing strings. This asserts the second half:
// the route it routes TO is the one it claims.

// claimsResolvingToASiblingRoute are claims that today match a route other than
// the one they name. Each is a real defect and each has an owner; the map exists
// so the assertion can land green and catch the NEXT one, rather than reddening
// main behind work that is already tracked.
//
// It is a ratchet: TestSDKRouteClaims_SiblingExemptionsAreStillReal fails when
// an entry stops resolving to a sibling, so a fix forces its entry out and the
// list can only shrink.
var claimsResolvingToASiblingRoute = map[string]string{
	// Empty: every claim resolves to its own route. A new entry needs the issue that tracks it.
}

// TestSDKRouteClaims_ResolveToTheirOwnOperation is the fourth ratchet (#415).
func TestSDKRouteClaims_ResolveToTheirOwnOperation(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := testutil.WalkRoutes(t, router)

	claims := sdkrest.RouteClaims()
	require.GreaterOrEqualf(t, len(claims), 280,
		"only %d SDK route claims enumerated, below the 280 floor -- the client route "+
			"tables failed to populate and this test would pass over an empty set", len(claims))

	sort.Slice(claims, func(i, j int) bool { return claims[i].GRPCMethod < claims[j].GRPCMethod })

	var swallowed []string
	resolved := 0

	for _, c := range claims {
		if _, ok := testutil.DaemonOnlyPrefixOf(c.Path); ok {
			continue
		}
		// A claim that resolves nowhere is ResolveAgainstBuiltRoutes' finding.
		// Reporting it here too would make one defect fail two tests.
		if _, ok := unroutedClaims[c.GRPCMethod]; ok {
			continue
		}

		route, ok := testutil.MatchClaim(router, c.Method, c.Path, built)
		if !ok {
			continue
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			continue
		}
		resolved++

		if testutil.NormalisePlaceholders(template) == testutil.NormalisePlaceholders(c.Path) {
			continue
		}
		if _, known := claimsResolvingToASiblingRoute[c.GRPCMethod]; known {
			continue
		}
		swallowed = append(swallowed, c.GRPCMethod+"\n      claims:  "+c.Method+" "+c.Path+
			"\n      matched: "+c.Method+" "+template)
	}

	require.GreaterOrEqualf(t, resolved, 100,
		"only %d of %d claims resolved to a server route; the fixture almost certainly "+
			"failed to build the router, and this walk would have nothing to walk",
		resolved, len(claims))

	if len(swallowed) > 0 {
		sort.Strings(swallowed)
		t.Errorf("%d SDK route claim(s) resolve to a route they do not name:\n\n    %s\n\n"+
			"Each compiles, sends, and is answered by a DIFFERENT operation than the caller "+
			"asked for -- the wrong resource rather than an error (#321). Either register the "+
			"route the claim names, repoint the claim at the route that exists, or record it "+
			"in claimsResolvingToASiblingRoute with the issue that tracks it -- never silently.",
			len(swallowed), strings.Join(swallowed, "\n\n    "))
	}
}

// TestSDKRouteClaims_SiblingExemptionsAreStillReal keeps the list above a
// ratchet: an entry whose claim now lands on its own route, or which is no
// longer a claim at all, must be deleted rather than left as cover.
func TestSDKRouteClaims_SiblingExemptionsAreStillReal(t *testing.T) {
	if len(claimsResolvingToASiblingRoute) == 0 {
		return
	}
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := testutil.WalkRoutes(t, router)

	live := map[string]sdkrest.RouteClaim{}
	for _, c := range sdkrest.RouteClaims() {
		live[c.GRPCMethod] = c
	}

	var stale []string
	for method := range claimsResolvingToASiblingRoute {
		c, ok := live[method]
		if !ok {
			stale = append(stale, method+" (no longer a claim at all)")
			continue
		}
		route, ok := testutil.MatchClaim(router, c.Method, c.Path, built)
		if !ok {
			stale = append(stale, method+" (now resolves to no route -- that is unroutedClaims' finding)")
			continue
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			continue
		}
		if testutil.NormalisePlaceholders(template) == testutil.NormalisePlaceholders(c.Path) {
			stale = append(stale, method+" (now lands on its own route)")
		}
	}

	sort.Strings(stale)
	require.Emptyf(t, stale,
		"%d entr(ies) in claimsResolvingToASiblingRoute no longer describe a swallow:\n  %s\n\n"+
			"Delete them. This list is a ratchet over the tracked defects; it may shrink, never "+
			"grow silently.", len(stale), strings.Join(stale, "\n  "))
}

// TestUnroutedClaims_EveryEntryIsStillAClaim is the mirror of the check inside
// TestSDKRouteClaims_ResolveAgainstBuiltRoutes, which iterates CLAIMS and so
// can only see an entry whose claim still exists. When a claim is deleted its
// exemption is stranded: it exempts something that cannot be asked for, in a
// list whose purpose is recording what still needs fixing.
//
// #441 stranded nineteen at once by deleting route-map entries naming gRPC
// methods that exist on no generated client, and nothing failed. This iterates
// the LIST instead.
func TestUnroutedClaims_EveryEntryIsStillAClaim(t *testing.T) {
	live := map[string]bool{}
	for _, c := range sdkrest.RouteClaims() {
		live[c.GRPCMethod] = true
	}
	require.GreaterOrEqualf(t, len(live), 280,
		"only %d claims enumerated, below the 280 floor -- every entry would read as "+
			"stranded and this test would report a false wall of defects", len(live))

	var stranded []string
	for method := range unroutedClaims {
		if !live[method] {
			stranded = append(stranded, method)
		}
	}
	sort.Strings(stranded)

	require.Emptyf(t, stranded,
		"%d unroutedClaims entr(ies) name a method that is no longer a claim:\n  %s\n\n"+
			"Each exempts a call no client can make. Delete them -- an exemption list that "+
			"only grows stops recording what is owed and starts hiding it.",
		len(stranded), strings.Join(stranded, "\n  "))
}
