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

// gatewayguard_test.go — gatewayd assembly-boundary guard.
//
// gatewayd (cmd/gatewayd → pkg/sdn/gateway/commands) is a lean edge daemon:
// control-plane interactions with platformd go through sdk/go exclusively,
// and its in-process data plane is pkg/proxy plus the pkg/sdn service
// stack. It must never link the platformd composition root (pkg/app), the
// daemon API surface (pkg/api/...), the web service tree, or any other
// platformd-side package.
//
// Like layerguard, the guard walks imports with go/parser (imports only, no
// package builds), but transitively: starting at pkg/sdn/gateway/commands
// it follows every platform-internal import edge (production files only)
// and fails with the offending package plus the import chain that reached
// it when the closure escapes the allowlist below.
package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// modulePrefix is the platform module path prefix shared by the main module
// and the sdk/go module.
const modulePrefix = "github.com/jeremyhahn/go-trusted-platform/"

// gatewayRoot is the module-relative package the guard starts from.
const gatewayRoot = "pkg/sdn/gateway/commands"

// gatewayAllowedPrefixes is the allowlist of module-relative package path
// prefixes the gatewayd assembly may reach transitively. Every entry is
// either a direct assembly need or a documented transitive carry; the guard
// reports the full import chain, so tightening an entry immediately shows
// which edge to cut.
var gatewayAllowedPrefixes = []string{
	// The gatewayd assembly itself and the SDN service stack (gateway,
	// proxysvc, firewall/NAT, zone, ovs, bgp, ipam, vxlan, p2p, ...).
	"pkg/sdn",

	// The in-process L7 data plane. A forwarder cannot forward through an
	// RPC client; pkg/proxy is the sanctioned in-process exception (see
	// cmd/gatewayd/CLAUDE.md).
	"pkg/proxy",

	// Trusted-computing collaborators of the proxy auth chain.
	"pkg/trust",
	"pkg/auth",

	// The OPA policy engine backing the proxy auth chain's per-route
	// PolicyEvaluator (proxysvc.OPAEvaluator). Pure-Go embedded OPA with
	// its go:embed policy bundle — no daemon, storage, or webservice
	// dependencies.
	"pkg/policy",

	// Cross-cutting utility packages.
	"pkg/logging",
	"pkg/common",
	"pkg/config",
	"pkg/util",
	"pkg/serializer",

	// The platform SDK — the ONLY control-plane path to platformd.
	"sdk/go",

	// Shared internal serializer/crypto adapters (carried by pkg/serializer
	// and the sdk transports).
	"internal/adapters",
	"internal/xkms",

	// Carried by pkg/sdn/policy (zone policy engine): the device store
	// entities/DAO surface and its datastore layer. Leaf carries, NOT
	// license to import the web service tree: the broad pkg/webservice,
	// pkg/api, and pkg/app prefixes remain forbidden.
	"pkg/device/dao",
	"pkg/device/entities",
	"pkg/store/datastore",

	// Carried by pkg/sdn/gateway/modes (PXE gateway mode).
	"pkg/ipxe",
	"pkg/testenv",
	// Carried by pkg/ipxe: the Raspberry Pi bootloader's netboot protocol
	// (recognising a Pi's DHCP request, its option 43). Pure protocol —
	// dhcpv4, tftp, logging; the TFTP tree staging, which needs the image
	// tooling, is pkg/diskimage/netboot and stays forbidden.
	"pkg/rpinetboot",

	// Carried by pkg/sdn/gateway/services/vpn (#584): the caller-admission
	// policy, the verdict type and the host-attestation manifest are leaf
	// packages of pkg/attestation with no reach into pkg/api or pkg/app.
	// The attestation SERVICE (pkg/attestation/service, which drags the
	// daemon in) stays forbidden: the VPN service takes a Verifier
	// interface the daemon fills.
	"pkg/attestation/calleradmission",
	"pkg/attestation/verdict",
	"pkg/attestation/manifest",
}

// gatewayForbiddenExamples are packages that must never enter the gatewayd
// closure; they exercise the allowlist matcher against the exact drift this
// guard exists to prevent.
var gatewayForbiddenExamples = []string{
	"pkg/app",
	"pkg/api/daemon",
	"pkg/api/grpc",
	"pkg/api/rest",
	"pkg/api/quic",
	"pkg/api/mcp",
	"pkg/webservice",
	"pkg/webservice/v1",
	"pkg/webservice/v1/webauthn",
	"pkg/cli",
	"pkg/daemon",
	"pkg/bootstrap",
	"pkg/bmc",
	"pkg/compute",
	"pkg/iso",
	"pkg/installer",
	"pkg/initrd",
	// The attestation service and reporting trees reach the daemon; only the
	// three leaf packages above are allowed (#584).
	"pkg/attestation/service",
	"pkg/attestation/reporting",
	"pkg/attestation",
}

// gatewayAllowed reports whether a module-relative package path matches the
// allowlist. Matching is by path-segment prefix so "pkg/sdn" allows
// "pkg/sdn/zone" but never "pkg/sdnx".
func gatewayAllowed(pkg string) bool {
	for _, prefix := range gatewayAllowedPrefixes {
		if pkg == prefix || strings.HasPrefix(pkg, prefix+"/") {
			return true
		}
	}
	return false
}

// packageDir maps a module-relative package path to its directory under the
// repository root. The sdk/go module lives in-repo, so the mapping is the
// identity for both modules.
func packageDir(root, pkg string) string {
	return filepath.Join(root, filepath.FromSlash(pkg))
}

// packageImports parses every production (non-test) .go file in the package
// directory and returns the platform-internal imports as module-relative
// package paths.
func packageImports(t *testing.T, root, pkg string) []string {
	t.Helper()

	dir := packageDir(root, pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package %s: %v", pkg, err)
	}
	fset := token.NewFileSet()
	seen := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("parse %s/%s: %v", pkg, name, err)
			continue
		}
		for _, spec := range file.Imports {
			value, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				continue
			}
			if !strings.HasPrefix(value, modulePrefix) {
				continue
			}
			seen[strings.TrimPrefix(value, modulePrefix)] = struct{}{}
		}
	}
	imports := make([]string, 0, len(seen))
	for imp := range seen {
		imports = append(imports, imp)
	}
	sort.Strings(imports)
	return imports
}

// TestGatewayBoundary_TransitiveClosureWithinAllowlist walks the transitive
// platform-internal import closure of pkg/sdn/gateway/commands and fails
// with the import chain for every package outside the allowlist.
func TestGatewayBoundary_TransitiveClosureWithinAllowlist(t *testing.T) {
	root := moduleRoot(t)

	// BFS with parent tracking for import-chain diagnostics.
	parent := map[string]string{gatewayRoot: ""}
	queue := []string{gatewayRoot}
	var violations []string

	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]

		if !gatewayAllowed(pkg) && pkg != gatewayRoot {
			violations = append(violations, pkg+" (via "+importChain(parent, pkg)+")")
			// Do not descend into forbidden packages; one report per edge
			// keeps the failure actionable.
			continue
		}
		for _, imp := range packageImports(t, root, pkg) {
			if _, visited := parent[imp]; visited {
				continue
			}
			parent[imp] = pkg
			queue = append(queue, imp)
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("gatewayd closure escaped the allowlist (%d violation(s)):", len(violations))
		for _, v := range violations {
			t.Errorf("  %s", v)
		}
	}
}

// importChain renders the BFS path from the gateway root to pkg.
func importChain(parent map[string]string, pkg string) string {
	var chain []string
	for p := pkg; p != ""; p = parent[p] {
		chain = append(chain, p)
	}
	// Reverse into root-first order.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return strings.Join(chain, " -> ")
}

// TestGatewayBoundary_ForbiddenExamplesRejected proves the matcher rejects
// the platformd-side packages this guard exists to keep out, so an
// allowlist regression cannot silently open them up.
func TestGatewayBoundary_ForbiddenExamplesRejected(t *testing.T) {
	for _, pkg := range gatewayForbiddenExamples {
		if gatewayAllowed(pkg) {
			t.Errorf("forbidden package %q is matched by the allowlist", pkg)
		}
	}
}

// TestGatewayBoundary_AllowlistIsWellFormed guards the guard: prefixes must
// be clean module-relative paths and must not shadow each other with
// non-segment matches.
func TestGatewayBoundary_AllowlistIsWellFormed(t *testing.T) {
	seen := make(map[string]bool, len(gatewayAllowedPrefixes))
	for _, prefix := range gatewayAllowedPrefixes {
		if prefix == "" || strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
			t.Errorf("malformed allowlist prefix %q", prefix)
		}
		if seen[prefix] {
			t.Errorf("duplicate allowlist prefix %q", prefix)
		}
		seen[prefix] = true
	}
	// Segment matching: pkg/sdn must not admit pkg/sdnx.
	if gatewayAllowed("pkg/sdnx") {
		t.Error("prefix matching is not segment-aware: pkg/sdnx admitted")
	}
	if !gatewayAllowed("pkg/sdn/zone") {
		t.Error("prefix matching broken: pkg/sdn/zone rejected")
	}
}
