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

package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readClusterDoc reads docs/cluster/<name> and returns its text with every
// run of whitespace folded to one space, so a phrase that wraps across lines
// still matches.
func readClusterDoc(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("../../../docs/cluster/" + name)
	require.NoError(t, err, "read docs/cluster/%s", name)
	return strings.Join(strings.Fields(string(body)), " ")
}

// Since #2140 serve and every embedded host set the cluster servicer through
// appbackends.WireSDKBackends, and the embedded registry serves the cluster
// service. The cluster feature docs are the requirements contract, so they
// must not still say nothing calls SetClusterService.
func TestClusterDocs_NoStaleUnwiredClaims(t *testing.T) {
	stale := []struct {
		doc    string
		phrase string
	}{
		{"api.md", "nothing calls it in production"},
		{"api.md", "field exists, never populated"},
		{"api.md", "No servicer set (production today)"},
		{"api.md", "Today every cluster REST call returns 503"},
		{"api.md", "which the daemon never populates"},
		{"api.md", "and **not** " + "`Cluster`"},
		{"engineering.md", "**Nothing calls it**"},
		{"user.md", "is not usable yet"},
		{"user.md", "Every cluster REST route returns **503**"},
		{"user.md", "No coordinator is wired into the daemon"},
		{"api.md", "`Join` and `Leave` still answer"},
		{"api.md", "`Join` and `Leave` return 503"},
		{"api.md", "`Join` and `Leave` answer `Unavailable`"},
		{"architecture.md", "Leave still answer Unavailable"},
		{"architecture.md", "Join and Leave answer Unavailable"},
		{"engineering.md", "Join and Leave answer Unavailable until #336 lands"},
		{"cli.md", "no cluster servicer is wired into the daemon"},
		{"user.md", "Join and Leave answer **`Unavailable`**"},
		{"user.md", "and Leave answer Unavailable until #336 lands"},
		{"user.md", "Changing membership through the platform is not wired yet"},
	}
	docs := map[string]string{}
	for _, s := range stale {
		body, ok := docs[s.doc]
		if !ok {
			body = readClusterDoc(t, s.doc)
			docs[s.doc] = body
		}
		assert.NotContains(t, body, s.phrase,
			"docs/cluster/%s still makes the stale claim %q", s.doc, s.phrase)
	}
}

// The docs name the production wiring: WireSDKBackends sets the servicer, and
// the embedded registry's Cluster field carries the daemon's cluster service.
func TestClusterDocs_NameTheProductionWiring(t *testing.T) {
	for _, doc := range []string{"api.md", "user.md", "engineering.md"} {
		assert.Contains(t, readClusterDoc(t, doc), "WireSDKBackends",
			"docs/cluster/%s does not name WireSDKBackends", doc)
	}
	assert.Contains(t, readClusterDoc(t, "api.md"), "registry.Cluster",
		"docs/cluster/api.md does not name registry.Cluster")
}

// TestClusterDocs_LeaveAnswersUnavailable pins that the API and user docs say Leave answers Unavailable.
func TestClusterDocs_LeaveAnswersUnavailable(t *testing.T) {
	for _, doc := range []string{"api.md", "user.md"} {
		assert.Contains(t, readClusterDoc(t, doc), "Leave answers `Unavailable`",
			"docs/cluster/%s does not say Leave answers Unavailable", doc)
	}
}
