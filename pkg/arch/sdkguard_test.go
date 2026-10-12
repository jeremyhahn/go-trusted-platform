// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// sdkguard_test.go — SDK-module data-plane guard.
//
// The sdk/go module links platform packages through its replace of the main
// module (sdk/go/transport/mcp -> pkg/api/mcp -> ... -> pkg/sdn). It must
// not reach the overlay IPsec and BGP data plane: those packages link
// govici, nftables and GoBGP, which the SDK module neither needs nor lists
// in its go.sum. The overlay.ipsec section the SDN configuration carries
// lives in pkg/sdn/ipsec/config for exactly this reason.
//
// The guard reuses the gateway guard's go/parser walk (production files,
// platform-internal edges) from every package under sdk/go.
package arch_test

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sdkRoot is the module-relative directory of the sdk/go module.
const sdkRoot = "sdk/go"

// sdkForbiddenPackages are the data-plane packages the SDK module must not
// link, each with the third-party stack it would drag in.
var sdkForbiddenPackages = map[string]string{
	"pkg/sdn/ipsec": "govici, nftables, netlink",
	"pkg/sdn/bgp":   "GoBGP",
}

// sdkPackages lists the module-relative packages under sdk/go: every
// directory holding a production .go file.
func sdkPackages(t *testing.T, root string) []string {
	t.Helper()

	seen := make(map[string]struct{})
	walkErr := filepath.WalkDir(filepath.Join(root, sdkRoot), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		seen[filepath.ToSlash(rel)] = struct{}{}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk %s: %v", sdkRoot, walkErr)
	}
	pkgs := make([]string, 0, len(seen))
	for pkg := range seen {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)
	return pkgs
}

// importClosure walks platform-internal imports from starts and returns
// every reached package mapped to the package that first imported it (""
// for a start).
func importClosure(t *testing.T, root string, starts []string) map[string]string {
	t.Helper()

	parent := make(map[string]string, len(starts))
	queue := make([]string, 0, len(starts))
	for _, start := range starts {
		parent[start] = ""
		queue = append(queue, start)
	}
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		for _, imp := range packageImports(t, root, pkg) {
			if _, visited := parent[imp]; visited {
				continue
			}
			parent[imp] = pkg
			queue = append(queue, imp)
		}
	}
	return parent
}

// forbiddenReached reports each forbidden package in closure with the
// import chain that reached it.
func forbiddenReached(closure map[string]string) []string {
	var reached []string
	for pkg, stack := range sdkForbiddenPackages {
		if _, ok := closure[pkg]; ok {
			reached = append(reached, pkg+" ("+stack+") via "+importChain(closure, pkg))
		}
	}
	sort.Strings(reached)
	return reached
}

func TestSDKModule_DoesNotReachIPsecDataPlane(t *testing.T) {
	root := moduleRoot(t)

	starts := sdkPackages(t, root)
	if len(starts) == 0 {
		t.Fatalf("no packages found under %s", sdkRoot)
	}
	for _, v := range forbiddenReached(importClosure(t, root, starts)) {
		t.Errorf("sdk/go links a data-plane package: %s", v)
	}
}

// TestSDKModule_GuardDetectsDataPlane proves the walk is not vacuous: the
// daemon API, which runs IPsec, does reach the data plane through it.
func TestSDKModule_GuardDetectsDataPlane(t *testing.T) {
	root := moduleRoot(t)

	reached := forbiddenReached(importClosure(t, root, []string{"pkg/api/daemon"}))
	if len(reached) != len(sdkForbiddenPackages) {
		t.Fatalf("pkg/api/daemon reached %v, want every package in %v", reached, sdkForbiddenPackages)
	}
}
