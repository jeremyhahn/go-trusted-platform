package arch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// gatewayServicesAddressFiles are the gateway services sources, fixtures
// and goldens (load balancer, firewall, host firewall, NAT64 and perf)
// whose example addresses must come from the documentation ranges. The VPN
// service is not yet covered.
var gatewayServicesAddressFiles = []string{
	"pkg/sdn/gateway/services/loadbalancer/service.go",
	"pkg/sdn/gateway/services/loadbalancer/service_test.go",
	"pkg/sdn/gateway/services/loadbalancer/prober_test.go",
	"pkg/sdn/gateway/services/loadbalancer/types_test.go",
	"pkg/sdn/gateway/services/firewall/nat_test.go",
	"pkg/sdn/gateway/services/firewall/nat_uplinks_test.go",
	"pkg/sdn/gateway/services/firewall/service_test.go",
	"pkg/sdn/gateway/services/firewall/testdata/nat/dual_uplink_snat.golden",
	"pkg/sdn/gateway/services/firewall/testdata/nat/single_uplink.golden",
	"pkg/sdn/gateway/services/firewall/testdata/nat/static_hairpin.golden",
	"pkg/sdn/gateway/services/hostfw/program_test.go",
	"pkg/sdn/gateway/services/hostfw/render_test.go",
	"pkg/sdn/gateway/services/hostfw/testdata/fixture.nft",
	"pkg/sdn/gateway/services/nat64/config.go",
	"pkg/sdn/gateway/services/nat64/config_test.go",
	"pkg/sdn/gateway/services/nat64/driver_test.go",
	"pkg/sdn/gateway/services/perf/service_test.go",
}

func TestGatewayServicesCarryNoPrivateAddresses(t *testing.T) {
	root := repoRoot(t)
	var findings []string
	for _, name := range gatewayServicesAddressFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		require.NoError(t, err)
		findings = append(findings, privateAddressFindings(name, string(data))...)
	}
	require.Empty(t, findings, "gateway services fixtures, goldens and comments must use RFC 5737 or RFC 2544 addresses, not RFC 1918")
}
