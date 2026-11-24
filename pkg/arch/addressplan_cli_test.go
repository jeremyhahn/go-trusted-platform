package arch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// cliAddressFiles are the platformctl command files whose help text,
// examples and test fixtures must use documentation-range addresses.
//
// Left off, because a literal in them must equal a value shipped by Go
// code outside pkg/cli/commands:
//   - pkg/cli/commands/iso/test_pxe.go and test_client_server.go describe
//     the PXE test network of pkg/ipxe/testenv.go.
var cliAddressFiles = []string{
	// help and Example text
	"pkg/cli/commands/bmc/cert.go",
	"pkg/cli/commands/bmc/user.go",
	"pkg/cli/commands/bootstrap/probe_http.go",
	"pkg/cli/commands/ca/issue.go",
	"pkg/cli/commands/cluster/bootstrap.go",
	"pkg/cli/commands/cluster/cluster.go",
	"pkg/cli/commands/cluster/join.go",
	"pkg/cli/commands/proxy/pool.go",
	"pkg/cli/commands/proxy/proxy.go",
	"pkg/cli/commands/sdn/flow.go",
	"pkg/cli/commands/sdn/gateway.go",
	"pkg/cli/commands/sdn/gateway_lb.go",
	"pkg/cli/commands/tpm/enroll.go",
	// tests
	"pkg/cli/commands/acme/acme_test.go",
	"pkg/cli/commands/admin/claim_test.go",
	"pkg/cli/commands/bmc/cert_restore_test.go",
	"pkg/cli/commands/bmc/cert_test.go",
	"pkg/cli/commands/bmc/enroll_test.go",
	"pkg/cli/commands/bootstrap/probe_http_test.go",
	"pkg/cli/commands/bootstrap/probe_test.go",
	"pkg/cli/commands/bootstrap/pxe_test.go",
	"pkg/cli/commands/bootstrap/run_output_test.go",
	"pkg/cli/commands/ca/ca_test.go",
	"pkg/cli/commands/ca/run_test.go",
	"pkg/cli/commands/canonical_init_run_test.go",
	"pkg/cli/commands/cluster/cluster_test.go",
	"pkg/cli/commands/cluster/helpers_test.go",
	"pkg/cli/commands/container/additional_coverage_test.go",
	"pkg/cli/commands/diskimage/flat_dhcp_test.go",
	"pkg/cli/commands/iam/coverage_964_test.go",
	"pkg/cli/commands/iso/coverage_964_test.go",
	"pkg/cli/commands/iso/host_seams_cs_test.go",
	"pkg/cli/commands/iso/network_config_test.go",
	"pkg/cli/commands/iso/platform_config_dns_test.go",
	"pkg/cli/commands/iso/test_pxe_arch_test.go",
	"pkg/cli/commands/ntp/ntp_test.go",
	"pkg/cli/commands/proxy/proxy_test.go",
	"pkg/cli/commands/sdn/gateway_lb_test.go",
	"pkg/cli/commands/sdn/gateway_snapshot_test.go",
	"pkg/cli/commands/sdn/run_coverage_test.go",
	"pkg/cli/commands/sdn/run_inproc_gateway_test.go",
	"pkg/cli/commands/sdn/run_inproc_sdn_test.go",
	"pkg/cli/commands/sdn/run_inproc_test.go",
	"pkg/cli/commands/vpn/client_test.go",
}

// TestCLICarriesNoPrivateAddresses keeps RFC 1918 addresses out of the
// platformctl help text and its tests (#2350 row 2): examples and
// fixtures use the RFC 5737 documentation ranges or the RFC 2544
// benchmark range.
func TestCLICarriesNoPrivateAddresses(t *testing.T) {
	root := repoRoot(t)
	var findings []string
	for _, name := range cliAddressFiles {
		data, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err)
		findings = append(findings, privateAddressFindings(name, string(data))...)
	}
	require.Empty(t, findings, "platformctl examples and fixtures must use RFC 5737 or RFC 2544 addresses, not RFC 1918")
}
