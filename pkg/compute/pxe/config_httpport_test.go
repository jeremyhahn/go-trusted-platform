package pxe

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestDaemonConfigHTTPPort pins the pxe section's http-port: the pxe
// integration leg runs its iPXE HTTP server on its own port, apart from the
// ipxe suite's 8080 on the shared host network (#1896).
func TestDaemonConfigHTTPPort(t *testing.T) {
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)

	t.Run("unset keeps the ipxe default 8080", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe"}).ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, ipxe.DefaultHTTPPort, cfg.IPXEConfig.HTTPPort)
	})

	t.Run("a set http-port reaches IPXEConfig.HTTPPort", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe", HTTPPort: 18089}).ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Equal(t, 18089, cfg.IPXEConfig.HTTPPort)
	})

	t.Run("an out-of-range port is refused by the service config validation", func(t *testing.T) {
		for _, port := range []int{-1, 65536} {
			cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe", HTTPPort: port}).ToServiceConfig(plan)
			require.Error(t, err, "port %d", port)
			assert.Nil(t, cfg)
			assert.True(t, errors.Is(err, ErrInvalidConfig), "port %d: %v", port, err)
		}
	})
}
