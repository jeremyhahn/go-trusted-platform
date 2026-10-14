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
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pluralDevicePrefix   = "/api/v1/devices"
	singularDevicePrefix = "/api/v1/device"
)

// seederPluralRoutes are the bootstrap seeder's routes
// (pkg/webservice/v1/rest/device). They are the only plural routes allowed to
// share a path with a singular one. The seeder alone owns them (#123/#124):
// its `{role, template}` body is a different contract from the CRUD create,
// and pkg/bootstrap/seeder.go calls them by these names. The exemption is
// keyed by method AND path, so a new CRUD alias on one of these paths, such
// as GET /devices/templates, is still reported. The seeder's GET
// /devices/config, which the templates' config-server-url names, is not in
// this table: only the provisioning surface mounts it (#177).
var seederPluralRoutes = map[string]bool{
	"POST /api/v1/devices/templates":                            true,
	"POST /api/v1/devices/templates/{id:[0-9]+}/create-profile": true,
}

// deviceRouteSuffix splits a "METHOD /path" route into the path below the
// device prefixes, reporting whether the path is plural, singular, or neither.
func deviceRouteSuffix(route string) (suffix string, plural, singular bool) {
	_, path, found := strings.Cut(route, " ")
	if !found {
		return "", false, false
	}
	if rest, ok := strings.CutPrefix(path, pluralDevicePrefix); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		return rest, true, false
	}
	if rest, ok := strings.CutPrefix(path, singularDevicePrefix); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
		return rest, false, true
	}
	return "", false, false
}

// dualNamedDeviceRoutes returns, sorted, every path below the device prefixes
// that is registered under BOTH `/devices` and `/device`, whatever the
// methods. Seeder routes do not count on the plural side.
func dualNamedDeviceRoutes(routes []string) []string {
	pluralSuffixes := map[string]bool{}
	singularSuffixes := map[string]bool{}
	for _, route := range routes {
		suffix, plural, singular := deviceRouteSuffix(route)
		switch {
		case plural && !seederPluralRoutes[route]:
			pluralSuffixes[suffix] = true
		case singular:
			singularSuffixes[suffix] = true
		}
	}

	dual := []string{}
	for suffix := range pluralSuffixes {
		if singularSuffixes[suffix] {
			dual = append(dual, suffix)
		}
	}
	sort.Strings(dual)
	return dual
}

// TestDeviceRoutesHaveOneName pins the #266 ruling on the router platformd
// actually builds: device records live under `/devices`, profiles and
// templates under `/device`, and no path answers under both. The removed
// plural aliases were partial: they covered list and `{id}`, but not
// count, match, serial, mac, find-config or assign. That left clients
// guessing which name worked for which operation.
func TestDeviceRoutesHaveOneName(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	built := walkRoutes(t, router)

	// Vacuity guard: the device surface must have been wired at all, or
	// an empty intersection proves nothing.
	var plural, singular int
	for _, route := range built {
		_, isPlural, isSingular := deviceRouteSuffix(route)
		if isPlural {
			plural++
		}
		if isSingular {
			singular++
		}
	}
	require.Positive(t, plural, "no /devices routes were built")
	require.Positive(t, singular, "no /device routes were built")

	assert.Empty(t, dualNamedDeviceRoutes(built),
		"these paths are served under both /api/v1/devices and /api/v1/device; "+
			"#266 gives each device resource exactly one name (docs/device/api.md §3.1)")

	// The exemption cannot go stale: each seeder route must still be
	// registered, or the entry is excusing nothing.
	registered := map[string]bool{}
	for _, route := range built {
		registered[route] = true
	}
	for route := range seederPluralRoutes {
		assert.True(t, registered[route], "seeder exemption %q matches no registered route", route)
	}
}

// TestDualNamedDeviceRoutes_ReportsAnAlias runs the detector over a router
// carrying the dual registration #266 removed, walked the same way as the
// real one, and requires it to be reported.
func TestDualNamedDeviceRoutes_ReportsAnAlias(t *testing.T) {
	ok := func(http.ResponseWriter, *http.Request) {}
	fixture := mux.NewRouter()
	fixture.HandleFunc("/api/v1/device/profiles", ok).Methods(http.MethodGet)
	fixture.HandleFunc("/api/v1/devices/profiles", ok).Methods(http.MethodPost)
	fixture.HandleFunc("/api/v1/device/templates", ok).Methods(http.MethodGet)
	// A CRUD alias on a seeder path is still an alias.
	fixture.HandleFunc("/api/v1/devices/templates", ok).Methods(http.MethodGet)
	fixture.HandleFunc("/api/v1/devices/{id:[0-9]+}", ok).Methods(http.MethodGet)

	assert.Equal(t, []string{"/profiles", "/templates"}, dualNamedDeviceRoutes(walkRoutes(t, fixture)))
}

// TestDualNamedDeviceRoutes_AllowsTheSplitAndTheSeeder is the control: records
// under one prefix, profiles under the other, and the seeder's own routes
// beside the singular CRUD ones.
func TestDualNamedDeviceRoutes_AllowsTheSplitAndTheSeeder(t *testing.T) {
	routes := []string{
		"GET /api/v1/devices",
		"GET /api/v1/devices/{id:[0-9]+}",
		"GET /api/v1/device/profiles",
		"POST /api/v1/device/templates",
		"POST /api/v1/devices/templates",
		"POST /api/v1/device/templates/{id:[0-9]+}/create-profile",
		"POST /api/v1/devices/templates/{id:[0-9]+}/create-profile",
		// Neither prefix: a longer word and an unrelated tree.
		"GET /api/v1/devicesx/profiles",
		"GET /api/v1/provisioning/sessions",
		"malformed",
	}

	assert.Empty(t, dualNamedDeviceRoutes(routes))
}

func TestDeviceRouteSuffix(t *testing.T) {
	tests := []struct {
		route    string
		suffix   string
		plural   bool
		singular bool
	}{
		{"GET /api/v1/devices", "", true, false},
		{"GET /api/v1/devices/count", "/count", true, false},
		{"GET /api/v1/device/profiles", "/profiles", false, true},
		{"GET /api/v1/device", "", false, true},
		{"GET /api/v1/devicesx", "", false, false},
		{"GET /api/v1/deviceprofiles", "", false, false},
		{"GET /api/v1/tenants", "", false, false},
		{"no-space", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.route, func(t *testing.T) {
			suffix, plural, singular := deviceRouteSuffix(tt.route)
			assert.Equal(t, tt.suffix, suffix)
			assert.Equal(t, tt.plural, plural)
			assert.Equal(t, tt.singular, singular)
		})
	}
}
