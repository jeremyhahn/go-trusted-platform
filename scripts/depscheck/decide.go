package main

import (
	"slices"
	"strings"
)

// forkLatest stands in for the latest version of a replace onto a different
// module path, which no version comparison can judge.
const forkLatest = "n/a (replaced by a different module)"

// finding is the verdict on one dependency.
type finding struct {
	Dep    dependency
	Latest string
	Behind bool
	// Unused is set for a replace that applies to no module in the build list.
	Unused bool
	// Lookup is set when the latest version could not be looked up.
	Lookup *LookupError
}

// assess judges one dependency against its `go list` entry. listed is false
// when the listing has no entry for the module at all.
//
// The latest version is, for a first-party module (path under firstParty),
// the highest published tag including -alpha prereleases, the version
// `make deps-latest` moves to (dependency-resolution.md §3). For a
// third-party require it is the go command's own Update answer, which
// prefers releases and skips retractions. A replace has no Update of its
// own, so for it the latest is the highest release in Versions.
func assess(dep dependency, mod listedModule, listed bool, firstParty string) finding {
	f := finding{Dep: dep}
	switch {
	case !listed:
		f.Lookup = &LookupError{Module: dep.Module, Reason: "go list returned no entry for it"}
		return f
	case mod.Error != nil:
		f.Lookup = &LookupError{Module: dep.Module, Reason: mod.Error.Err}
		return f
	case mod.Version == "" && dep.Kind == kindReplace:
		f.Unused = true
		return f
	case mod.Version == "":
		f.Lookup = &LookupError{Module: dep.Module, Reason: "not a known dependency"}
		return f
	case dep.Path != dep.Module:
		// A fork: holding it is always a decision that needs its reason.
		f.Latest, f.Behind = forkLatest, true
		return f
	}
	f.Latest = latestVersion(dep, mod, strings.HasPrefix(dep.Path, firstParty))
	f.Behind = isBehind(dep.Version, f.Latest, mod.Versions)
	return f
}

func latestVersion(dep dependency, mod listedModule, firstParty bool) string {
	if dep.Kind == kindRequire && !firstParty {
		if mod.Update != nil {
			return mod.Update.Version
		}
		return dep.Version
	}
	candidates := mod.Versions
	if !firstParty {
		if releases := releasesOnly(mod.Versions); len(releases) > 0 {
			candidates = releases
		}
	}
	if len(candidates) > 0 {
		return candidates[len(candidates)-1]
	}
	if mod.Update != nil {
		return mod.Update.Version
	}
	return dep.Version
}

// isBehind compares positions in the go command's semantic-version ordering
// of the published versions. A current version that is not a published tag
// (a pseudo-version) is behind any tag the latest names; a latest that is
// not in the list came from Update, which the go command reports only when
// it is newer.
func isBehind(current, latest string, versions []string) bool {
	if latest == current {
		return false
	}
	at := slices.Index(versions, latest)
	if at < 0 {
		return true
	}
	return slices.Index(versions, current) < at
}

func releasesOnly(versions []string) []string {
	var releases []string
	for _, v := range versions {
		if !isPrerelease(v) {
			releases = append(releases, v)
		}
	}
	return releases
}

// isPrerelease reports a semantic-version prerelease, including a
// pseudo-version: a "-" before any "+build" suffix, since the
// vMAJOR.MINOR.PATCH core never contains one.
func isPrerelease(version string) bool {
	core, _, _ := strings.Cut(version, "+")
	return strings.Contains(core, "-")
}
