package arch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// gatewayModesAddressFiles are the gateway overlay mode tests whose underlay
// VTEPs, overlay subnet and prefix routes must come from the documentation
// ranges.
var gatewayModesAddressFiles = []string{
	"pkg/sdn/gateway/modes/errors_test.go",
	"pkg/sdn/gateway/modes/overlay_evpn_test.go",
	"pkg/sdn/gateway/modes/overlay_flood_peers_test.go",
	"pkg/sdn/gateway/modes/overlay_flows_test.go",
	"pkg/sdn/gateway/modes/overlay_generation_test.go",
	"pkg/sdn/gateway/modes/overlay_helpers_test.go",
	"pkg/sdn/gateway/modes/overlay_nd_test.go",
	"pkg/sdn/gateway/modes/overlay_test.go",
}

func TestGatewayModesCarryNoPrivateAddresses(t *testing.T) {
	root := repoRoot(t)
	var findings []string
	for _, name := range gatewayModesAddressFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		require.NoError(t, err)
		findings = append(findings, privateAddressFindings(name, string(data))...)
	}
	require.Empty(t, findings, "gateway overlay mode tests must use RFC 5737 addresses, not RFC 1918")
}
