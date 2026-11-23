package arch

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// privateRanges are the RFC 1918 blocks. They are built from bytes so that no
// private dotted quad is typed in Go source.
var privateRanges = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{172, 16, 0, 0}), 12),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 16),
}

// docsAddressFiles are the docs whose example addresses must come from the
// documentation ranges (RFC 5737 or 198.18/15), never from RFC 1918 (#2350
// row 2). Docs quote public addresses and OIDs, so this guard flags only the
// private blocks; the strict addressPlanFiles guard covers the IPAM docs.
//
// Left off, because they state a value the Go code ships as its default:
//   - docs/architecture/reference-network.md, docs/architecture/deployment-reference.md
//     and docs/bootstrap/user.md derive the reference plan from
//     netplan.DefaultBase (pkg/sdn/netplan/number.go), an IPv4 /8 that no
//     documentation range can hold;
//   - docs/dns/configuration.md quotes the default forwarders of
//     pkg/dns/config.go.
var docsAddressFiles = []string{
	"docs/bootstrap/cli.md",
	"docs/bootstrap/dane-bootstrap-flow.mmd",
	"docs/bootstrap/engineering.md",
	"docs/device-templates.md",
	"docs/device/api-reference-rest.md",
	"docs/dht/02-network-architecture.md",
	"docs/dht/18-platformd-p2p.md",
	"docs/dht/api-reference-unix.md",
	"docs/dns/api.md",
	"docs/factory-image/user.md",
	"docs/gateway/api.md",
	"docs/gateway/cli.md",
	"docs/gateway/engineering.md",
	"docs/gateway/user.md",
	"docs/iam/configuration.md",
	"docs/installer/user.md",
	"docs/ipxe/cli.md",
	"docs/ipxe/engineering.md",
	"docs/ipxe/user.md",
	"docs/ntp/architecture.md",
	"docs/ntp/engineering.md",
	"docs/ntp/user.md",
	"docs/operations/gateway-bringup.md",
	"docs/plans/1994.md",
	"docs/provisioning/README.md",
	"docs/provisioning/client.md",
	"docs/sdn/INDEX.md",
	"docs/sdn/api-reference-rest.md",
	"docs/sdn/cli-usage.md",
	"docs/sdn/configuration.md",
	"docs/sdn/dhcp/architecture.md",
	"docs/sdn/dhcp/cli-usage.md",
	"docs/sdn/dhcp/configuration.md",
	"docs/sdn/firewall/README.md",
	"docs/sdn/firewall/configuration.md",
	"docs/sdn/ipam/README.md",
	"docs/sdn/ipam/api-reference-unix.md",
	"docs/sdn/ipam/architecture.md",
	"docs/sdn/ipam/configuration.md",
	"docs/sdn/overlay/README.md",
	"docs/sdn/overlay/configuration.md",
	"docs/sdn/overlay/operations.md",
	"docs/sdn/provisioning.md",
	"docs/sdn/tunnel/README.md",
	"docs/sdn/tunnel/configuration.md",
	"docs/sdn/user.md",
	"docs/trust/engineering.md",
	"docs/trust/user.md",
	"docs/vpn/api.md",
}

// privateAddressFindings returns one "name:line: addr" finding per IPv4
// literal in data inside an RFC 1918 block. A block's own network address
// followed by its own prefix length names the block as a concept and is not
// a finding.
func privateAddressFindings(name, data string) []string {
	var findings []string
	for i, line := range strings.Split(data, "\n") {
		for _, loc := range ipv4Literal.FindAllStringIndex(line, -1) {
			addr, err := netip.ParseAddr(line[loc[0]:loc[1]])
			if err != nil || !addr.Is4() {
				continue
			}
			for _, block := range privateRanges {
				if !block.Contains(addr) {
					continue
				}
				if addr == block.Addr() && namesBlock(line[loc[1]:], block.Bits()) {
					break
				}
				findings = append(findings, fmt.Sprintf("%s:%d: %s", name, i+1, addr))
				break
			}
		}
	}
	return findings
}

// namesBlock reports whether rest starts with "/bits" and no further digit.
func namesBlock(rest string, bits int) bool {
	suffix := "/" + strconv.Itoa(bits)
	if !strings.HasPrefix(rest, suffix) {
		return false
	}
	rest = rest[len(suffix):]
	return rest == "" || rest[0] < '0' || rest[0] > '9'
}

// TestDocsCarryNoPrivateAddresses requires the listed docs to carry no RFC
// 1918 address: the repository is public, and examples use RFC 5737 or
// 198.18/15.
func TestDocsCarryNoPrivateAddresses(t *testing.T) {
	root := repoRoot(t)
	var findings []string
	for _, name := range docsAddressFiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		findings = append(findings, privateAddressFindings(name, string(data))...)
	}
	require.Empty(t, findings, "docs examples must use RFC 5737 or 198.18/15 addresses, not RFC 1918")
}

// TestPrivateAddressFindingsFlagEachBlock pins the docs guard itself.
func TestPrivateAddressFindingsFlagEachBlock(t *testing.T) {
	for _, addr := range []netip.Addr{
		netip.AddrFrom4([4]byte{10, 1, 2, 3}),
		netip.AddrFrom4([4]byte{172, 20, 1, 1}),
		netip.AddrFrom4([4]byte{192, 168, 7, 9}),
	} {
		require.Len(t, privateAddressFindings("x.md", "a "+addr.String()+" b"), 1, addr.String())
	}
	block := netip.AddrFrom4([4]byte{192, 168, 0, 0})
	require.Empty(t, privateAddressFindings("x.md", "a "+block.String()+"/16 b"))
	require.Len(t, privateAddressFindings("x.md", "a "+block.String()+"/24 b"), 1)
	require.Empty(t, privateAddressFindings("x.md", "a 192.0.2.10 b"))
	require.Empty(t, privateAddressFindings("x.md", "a 198.19.4.1 b"))
}
