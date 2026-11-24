package arch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// webAddressFiles are the web console and JS SDK sources whose example
// addresses (doc comments, placeholders, unit fixtures and mocked
// Playwright specs) must come from the documentation ranges. The
// real-server integration specs under test/integration/web are not yet
// covered.
var webAddressFiles = []string{
	"sdk/javascript/src/services/dns-service.ts",
	"sdk/javascript/src/services/gateway-service.ts",
	"sdk/javascript/src/services/quicbaas/cluster-service.ts",
	"sdk/javascript/src/services/quicbaas/object-transfer-service.ts",
	"sdk/javascript/src/services/__tests__/gateway-service.test.ts",
	"sdk/javascript/src/services/__tests__/wire-enum-round-trip.test.ts",
	"sdk/javascript/src/types/__tests__/device-profile-networks.test.ts",
	"web/src/app/(dashboard)/networking/ipam/page.tsx",
	"web/src/app/(dashboard)/devices/templates/[id]/create-profile/create-profile-client.tsx",
	"web/src/components/features/networking/dns-record-form.tsx",
	"web/src/app/(dashboard)/networking/ipam/page.test.tsx",
	"web/src/app/(dashboard)/networking/gateway/page.test.tsx",
	"web/src/app/(dashboard)/networking/flows/page.test.tsx",
	"web/src/app/(dashboard)/networking/vpn/page.test.tsx",
	"web/src/components/features/networking/gateway-snapshot-detail.test.tsx",
	"web/e2e/fixtures/device-api-mock.ts",
	"web/e2e/networking.spec.ts",
	"web/e2e/overlay.spec.ts",
	"web/e2e/attestation-reports.spec.ts",
}

func TestWebCarriesNoPrivateAddresses(t *testing.T) {
	root := repoRoot(t)
	var findings []string
	for _, name := range webAddressFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		require.NoError(t, err)
		findings = append(findings, privateAddressFindings(name, string(data))...)
	}
	require.Empty(t, findings, "web and SDK examples and fixtures must use RFC 5737 or RFC 2544 addresses, not RFC 1918")
}
