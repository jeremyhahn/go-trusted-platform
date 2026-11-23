package arch

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// documentationRanges are the IPv4 ranges an example address may come from:
// the RFC 5737 documentation blocks and the RFC 2544 benchmark range. The
// repository is public, and an address from a real plan is an internal value
// (public hygiene, "Internal values are configuration inputs").
var documentationRanges = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// reservedSpecials are special-purpose addresses an example may name
// without revealing a plan: unspecified, loopback, link-local and broadcast.
var reservedSpecials = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

// ipv4Literal matches a dotted-quad candidate; netip.ParseAddr decides
// whether it is an address.
var ipv4Literal = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)

// addressPlanFiles are the stand-alone IPAM pool examples: the IPAM docs, the
// ipam CLI help and the IPAM window tests (#2350 row 2).
var addressPlanFiles = []string{
	"docs/sdn/ipam/api-reference.md",
	"docs/sdn/ipam/api-reference-rest.md",
	"docs/sdn/ipam/api-reference-grpc.md",
	"pkg/cli/commands/sdn/ipam.go",
	"pkg/api/mcp/gateway_ipam_window_test.go",
	"pkg/api/quic/gateway_ipam_window_test.go",
	"pkg/api/daemon/ipam_window_transport_test.go",
	"pkg/sdn/ipam/window_test.go",
	"pkg/sdn/ipam/backends/window_test.go",
	"pkg/sdn/ipam/backends/update_regression_test.go",
}

// addressPlanFindings returns one "name:line: <addr> is outside the
// documentation ranges" finding per IPv4 literal in data that no
// documentation range or reserved special contains.
func addressPlanFindings(name, data string) []string {
	var findings []string
	for i, line := range strings.Split(data, "\n") {
		for _, literal := range ipv4Literal.FindAllString(line, -1) {
			addr, err := netip.ParseAddr(literal)
			if err != nil || !addr.Is4() || allowedExampleAddress(addr) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s:%d: %s is outside the documentation ranges", name, i+1, addr))
		}
	}
	return findings
}

func allowedExampleAddress(addr netip.Addr) bool {
	for _, lists := range [][]netip.Prefix{documentationRanges, reservedSpecials} {
		for _, prefix := range lists {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

// TestExampleAddressesUseDocumentationRanges requires every IPv4 literal in
// the IPAM docs, the ipam CLI help and the IPAM window tests to sit in a
// documentation range.
func TestExampleAddressesUseDocumentationRanges(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range addressPlanFiles {
		data, err := os.ReadFile(filepath.Join(root, rel))
		require.NoError(t, err)
		for _, finding := range addressPlanFindings(rel, string(data)) {
			t.Error(finding)
		}
	}
}

// TestAddressPlanFindingsFlagPrivateAddresses pins the guard itself: a
// private address is a finding, documentation addresses are not.
func TestAddressPlanFindingsFlagPrivateAddresses(t *testing.T) {
	private := netip.AddrFrom4([4]byte{172, 16, 4, 20})
	findings := addressPlanFindings("example.md", "gateway "+private.String())
	require.Equal(t, []string{"example.md:1: " + private.String() + " is outside the documentation ranges"}, findings)

	require.Empty(t, addressPlanFindings("example.md", "range 198.18.9.50 via 192.0.2.1"))
}
