package arch

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every veth a test creates has one tx and one rx queue on both ends (#1178).
// The kernel default is one queue per possible CPU, and each queue raises its
// own uevents on add and remove: on ci-node-1 (80 cores, 112 queues) that was
// about 450 uevents per pair, and test churn drove the host to load 660 in a
// udev storm. pkg/testenv's NewVeth (netlink) and VethArgs / VethNetnsArgs
// (ip(8)) pin the counts; this guard fails on any test-path veth creation
// that bypasses them.
//
// Test paths are every _test.go file, every Go file under test/ and
// pkg/testenv/, and every shell script under test/, scripts/ and build/.
// Product code is out of scope: it creates no veths today, and a workload
// veth may want more than one queue. Three shapes are a veth creation:
//
//   - a netlink Veth literal that sets PeerName (netlink documents PeerName
//     as create-only), or a netlink.NewVeth call;
//   - an ip(8) argument list holding "type", "veth" (call arguments or a
//     []string literal);
//   - a string literal or shell line holding "type veth".
//
// The ip(8) and string forms pass when they set numtxqueues 1 and
// numrxqueues 1 for both ends; the netlink forms always go through NewVeth.

const netlinkImport = "github.com/vishvananda/netlink"

// vethGuardExempt holds the helper that builds the pinned arguments
// dynamically and this guard, whose fixtures are deliberate violations.
var vethGuardExempt = map[string]bool{
	"pkg/testenv/veth.go":        true,
	"pkg/arch/vethguard_test.go": true,
}

var (
	typeVethRe    = regexp.MustCompile(`\btype\s+veth\b`)
	numTxQueue1Re = regexp.MustCompile(`\bnumtxqueues\s+1\b`)
	numRxQueue1Re = regexp.MustCompile(`\bnumrxqueues\s+1\b`)
)

// UnpinnedVethError reports a test-path veth creation that does not give both
// ends a single tx and rx queue.
type UnpinnedVethError struct {
	// File is the repository-relative path.
	File string

	// Line is the 1-based line of the creation.
	Line int

	// What names the shape that was found.
	What string
}

func (e *UnpinnedVethError) Error() string {
	return fmt.Sprintf("%s:%d: %s: create test veths through pkg/testenv NewVeth, VethArgs or "+
		"VethNetnsArgs, or give both ends numtxqueues 1 numrxqueues 1; a veth with the default "+
		"per-CPU queue count floods udev with uevents (#1178)", e.File, e.Line, e.What)
}

// isVethTestPath reports whether rel, a slash-separated repository path, is
// a file whose veths the guard checks.
func isVethTestPath(rel string) bool {
	if vethGuardExempt[rel] {
		return false
	}
	switch {
	case strings.HasSuffix(rel, ".go"):
		return strings.HasSuffix(rel, "_test.go") ||
			strings.HasPrefix(rel, "test/") ||
			strings.HasPrefix(rel, "pkg/testenv/")
	case strings.HasSuffix(rel, ".sh"):
		return strings.HasPrefix(rel, "test/") ||
			strings.HasPrefix(rel, "scripts/") ||
			strings.HasPrefix(rel, "build/")
	}
	return false
}

// pinsBothEnds reports whether text sets one tx and one rx queue twice: once
// for the local end and once for the peer.
func pinsBothEnds(text string) bool {
	return len(numTxQueue1Re.FindAllString(text, -1)) >= 2 &&
		len(numRxQueue1Re.FindAllString(text, -1)) >= 2
}

// shellVethViolations returns every line of a shell script that creates a
// veth without pinning both ends' queues. Comment lines are prose.
func shellVethViolations(rel, script string) []*UnpinnedVethError {
	var findings []*UnpinnedVethError
	for i, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if typeVethRe.MatchString(line) && !pinsBothEnds(line) {
			findings = append(findings, &UnpinnedVethError{File: rel, Line: i + 1, What: "ip link add ... type veth"})
		}
	}
	return findings
}

// goVethViolations returns every unpinned veth creation in a Go source file.
func goVethViolations(rel string, src []byte) ([]*UnpinnedVethError, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return nil, err
	}

	netlinkName := ""
	for _, spec := range file.Imports {
		path, unquoteErr := strconv.Unquote(spec.Path.Value)
		if unquoteErr != nil || path != netlinkImport {
			continue
		}
		netlinkName = "netlink"
		if spec.Name != nil {
			netlinkName = spec.Name.Name
		}
	}

	var findings []*UnpinnedVethError
	report := func(pos token.Pos, what string) {
		findings = append(findings, &UnpinnedVethError{File: rel, Line: fset.Position(pos).Line, What: what})
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			if isNetlinkSelector(node.Type, netlinkName, "Veth") && setsField(node, "PeerName") {
				report(node.Pos(), "netlink.Veth literal")
			}
			if unpinnedVethArgs(node.Elts) {
				report(node.Pos(), `[]string{..., "type", "veth", ...}`)
			}
		case *ast.CallExpr:
			if isNetlinkSelector(node.Fun, netlinkName, "NewVeth") {
				report(node.Pos(), "netlink.NewVeth call")
			}
			if unpinnedVethArgs(node.Args) {
				report(node.Pos(), `ip(8) arguments "type", "veth"`)
			}
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			text, unquoteErr := strconv.Unquote(node.Value)
			if unquoteErr == nil && typeVethRe.MatchString(text) && !pinsBothEnds(text) {
				report(node.Pos(), `string "... type veth ..."`)
			}
		}
		return true
	})
	return findings, nil
}

// isNetlinkSelector reports whether expr is pkg.name for the netlink import.
func isNetlinkSelector(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || pkg == "" || sel.Sel.Name != name {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == pkg
}

// setsField reports whether a keyed composite literal sets field.
func setsField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); ok && key.Name == field {
			return true
		}
	}
	return false
}

// unpinnedVethArgs reports whether exprs hold the separate string literals
// "type", "veth" in a row (a single "... type veth ..." literal is the
// BasicLit case) without numtxqueues 1 and numrxqueues 1 for both ends.
func unpinnedVethArgs(exprs []ast.Expr) bool {
	words := make([]string, len(exprs))
	for i, expr := range exprs {
		if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if text, err := strconv.Unquote(lit.Value); err == nil {
				words[i] = text
			}
		}
	}
	for i := 0; i+1 < len(words); i++ {
		if words[i] == "type" && words[i+1] == "veth" {
			return !pinsBothEnds(strings.Join(words, " "))
		}
	}
	return false
}

func TestTestVethsHaveOneQueuePerEnd(t *testing.T) {
	root := repoRoot(t)
	scanned := 0

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A root-owned directory a devcontainer suite left behind holds
			// nothing the guard checks (see layerguard_test.go).
			if d != nil && d.IsDir() && errors.Is(err, fs.ErrPermission) {
				return filepath.SkipDir
			}
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if !isVethTestPath(rel) {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++

		var findings []*UnpinnedVethError
		if strings.HasSuffix(rel, ".sh") {
			findings = shellVethViolations(rel, string(src))
		} else {
			var parseErr error
			findings, parseErr = goVethViolations(rel, src)
			if parseErr != nil {
				t.Errorf("parse %s: %v", rel, parseErr)
			}
		}
		for _, finding := range findings {
			t.Error(finding)
		}
		return nil
	})
	require.NoError(t, walkErr)
	require.NotZero(t, scanned, "the guard scanned no test files")
}

func TestIsVethTestPath(t *testing.T) {
	for rel, want := range map[string]bool{
		"pkg/sdn/netlink/link_test.go":           true,
		"test/integration/sdn/netns_helpers.go":  true,
		"pkg/testenv/network_linux.go":           true,
		"build/docker/devcontainer/run.sh":       true,
		"scripts/ci/net.sh":                      true,
		"test/e2e/setup.sh":                      true,
		"pkg/sdn/netlink/link.go":                false,
		"docs/test/integration.md":               false,
		"pkg/testenv/veth.go":                    false,
		"pkg/arch/vethguard_test.go":             false,
		"configs/platform/templates/x/script.sh": false,
	} {
		require.Equal(t, want, isVethTestPath(rel), rel)
	}
}

const fixtureVethGo = `package fixture

import (
	"os/exec"

	vnl "github.com/vishvananda/netlink"
)

func create() {
	_ = vnl.LinkAdd(&vnl.Veth{LinkAttrs: vnl.LinkAttrs{Name: "a"}, PeerName: "b"})
	_ = vnl.NewVeth(vnl.LinkAttrs{Name: "c"})
	_ = exec.Command("ip", "link", "add", "d", "type", "veth", "peer", "name", "e")
	_ = []string{"link", "add", "f", "type", "veth", "peer", "name", "g"}
	_ = exec.Command("sh", "-c", "ip link add h type veth peer name i")
}
`

func TestGoVethViolationsFindsEachShape(t *testing.T) {
	findings, err := goVethViolations("test/x_test.go", []byte(fixtureVethGo))
	require.NoError(t, err)

	var got []string
	for _, f := range findings {
		got = append(got, fmt.Sprintf("%d %s", f.Line, f.What))
	}
	require.Equal(t, []string{
		"10 netlink.Veth literal",
		"11 netlink.NewVeth call",
		`12 ip(8) arguments "type", "veth"`,
		`13 []string{..., "type", "veth", ...}`,
		`14 string "... type veth ..."`,
	}, got)
	require.Contains(t, findings[0].Error(), "test/x_test.go:10:")
	require.Contains(t, findings[0].Error(), "#1178")
}

const fixtureVethGoPinned = `package fixture

import (
	"os/exec"

	"github.com/vishvananda/netlink"
)

func inspect() {
	// A Veth without PeerName describes an existing link, not a creation.
	_ = &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: 3, Name: "veth0"}}
	_ = exec.Command("ip", "link", "add", "name", "a", "numtxqueues", "1", "numrxqueues", "1",
		"type", "veth", "peer", "name", "b", "numtxqueues", "1", "numrxqueues", "1")
	_ = "ip link add a numtxqueues 1 numrxqueues 1 type veth peer name b numtxqueues 1 numrxqueues 1"
	_ = exec.Command("ip", "link", "add", "br0", "type", "bridge")
}
`

func TestGoVethViolationsAcceptsPinnedAndNonCreations(t *testing.T) {
	findings, err := goVethViolations("test/x_test.go", []byte(fixtureVethGoPinned))
	require.NoError(t, err)
	require.Empty(t, findings)
}

func TestGoVethViolationsPinningOneEndIsNotEnough(t *testing.T) {
	src := "package f\nvar s = \"ip link add a numtxqueues 1 numrxqueues 1 type veth peer name b\"\n"
	findings, err := goVethViolations("test/f.go", []byte(src))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Equal(t, 2, findings[0].Line)
}

func TestGoVethViolationsRejectsUnparsableSource(t *testing.T) {
	_, err := goVethViolations("test/broken.go", []byte("package f\nfunc {"))
	require.Error(t, err)
}

func TestShellVethViolations(t *testing.T) {
	script := strings.Join([]string{
		"#!/bin/sh",
		"# ip link add a type veth peer name b  (prose)",
		"ip link add a type veth peer name b",
		"ip link add c numtxqueues 1 numrxqueues 1 type veth peer name d numtxqueues 1 numrxqueues 1",
		"ip link add e numtxqueues 1 numrxqueues 1 type veth peer name f",
		"ip link add br0 type bridge",
	}, "\n")

	findings := shellVethViolations("test/net.sh", script)
	require.Len(t, findings, 2)
	require.Equal(t, 3, findings[0].Line)
	require.Equal(t, 5, findings[1].Line, "pinning only the local end leaves the peer at the default")
	require.Empty(t, shellVethViolations("test/empty.sh", ""))
}
