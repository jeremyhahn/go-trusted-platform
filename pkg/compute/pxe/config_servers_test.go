package pxe

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestDaemonConfigProvisioningServers covers the pxe: section's
// acme-servers and dns-servers keys: they reach ServiceConfig as parsed
// addresses in order, stay empty when unset, and an unparsable entry is
// refused naming its key.
func TestDaemonConfigProvisioningServers(t *testing.T) {
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	require.NoError(t, err)

	t.Run("unset leaves both lists empty", func(t *testing.T) {
		cfg, err := (&DaemonConfig{Enabled: true, BridgeName: "br-pxe"}).ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		assert.Nil(t, cfg.ACMEServerIPs)
		assert.Nil(t, cfg.DNSServerIPs)
	})

	t.Run("set lists reach ServiceConfig", func(t *testing.T) {
		cfg, err := (&DaemonConfig{
			Enabled:     true,
			BridgeName:  "br-pxe",
			ACMEServers: []string{"192.0.2.10"},
			DNSServers:  []string{"192.0.2.53", "2001:db8::53"},
		}).ToServiceConfig(plan)
		require.NoError(t, err)
		require.NotNil(t, cfg)
		require.Len(t, cfg.ACMEServerIPs, 1)
		assert.True(t, cfg.ACMEServerIPs[0].Equal(net.ParseIP("192.0.2.10")))
		require.Len(t, cfg.DNSServerIPs, 2)
		assert.True(t, cfg.DNSServerIPs[0].Equal(net.ParseIP("192.0.2.53")))
		assert.True(t, cfg.DNSServerIPs[1].Equal(net.ParseIP("2001:db8::53")))
	})

	t.Run("an unparsable address is refused", func(t *testing.T) {
		for field, d := range map[string]*DaemonConfig{
			"pxe.dns-servers":  {Enabled: true, BridgeName: "br-pxe", DNSServers: []string{"not-an-ip"}},
			"pxe.acme-servers": {Enabled: true, BridgeName: "br-pxe", ACMEServers: []string{"not-an-ip"}},
		} {
			cfg, err := d.ToServiceConfig(plan)
			require.Error(t, err, field)
			assert.Nil(t, cfg, field)
			var cfgErr ErrInvalidConfiguration
			require.True(t, errors.As(err, &cfgErr), "%s: %v", field, err)
			assert.Equal(t, field, cfgErr.Field)
			assert.Contains(t, cfgErr.Reason, "not-an-ip")
		}
	})
}
